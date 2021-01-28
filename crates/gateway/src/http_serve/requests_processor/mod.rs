use crate::cache::{Cache, HandlerChecksum};
use crate::clients::traffic_counter::{RecordedTrafficStatistics, TrafficCounters};
use crate::clients::ClientTunnels;
use crate::http_serve::auth::JwtEcdsa;
use crate::mime_helpers::{is_mime_match, ordered_by_quality};
use crate::public_hyper_client::MeteredHttpsConnector;
use crate::rules_counter::AccountCounters;
use crate::webapp::{ConfigData, ConfigsResponse};
use byte_unit::Byte;
use chrono::{DateTime, Utc};
use core::mem;
use exogress_common::config_core::{
    self, is_profile_active, Action, CatchAction, CatchMatcher, ClientHandlerVariant, Exception,
    MatchedResponseModification, MatchingPath, MethodMatcher, ModifyHeaders, RequestModifications,
    RescueItem, ResponseBody, Rule, StaticResponse, StatusCodeRange, TemplateEngine,
    TrailingSlashFilterRule, UrlPathSegmentOrQueryPart,
};
use exogress_common::entities::{
    AccountUniqueId, ConfigId, ConfigName, HandlerName, InstanceId, MountPointName, ProjectName,
    StaticResponseName,
};
use exogress_server_common::logging::{
    ExceptionProcessingStep, LogMessage, ProcessingStep, StaticResponseProcessingStep,
};
use exogress_server_common::presence;
use futures::channel::{mpsc, oneshot};
use futures::{SinkExt, StreamExt};
use handlebars::Handlebars;
use hashbrown::HashMap;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use hyper::Body;
use itertools::Itertools;
use parking_lot::Mutex;
use serde_json::json;
use smol_str::SmolStr;
use sodiumoxide::crypto::secretstream::xchacha20poly1305;
use std::collections::BTreeMap;
use std::convert::{TryFrom, TryInto};
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Instant;
use tokio::io::AsyncWriteExt;
use trust_dns_resolver::TokioAsyncResolver;
use typed_headers::{Accept, ContentType, HeaderMapExt};
use url::Url;
use weighted_rs::{SmoothWeight, Weight};

#[macro_use]
mod macros;

mod application_firewall;
mod auth;
mod gcs_bucket;
mod helpers;
mod pass_through;
mod post_processing;
mod proxy;
mod s3_bucket;
mod static_dir;

use crate::dbip::LocationAndIsp;
use crate::http_serve::requests_processor::pass_through::ResolvedPassThrough;
use exogress_common::common_utils::uri_ext::UriExt;
use exogress_server_common::url_prefix::MountPointBaseUrl;
use http::header::{HeaderName, CACHE_CONTROL, LOCATION, RANGE, STRICT_TRANSPORT_SECURITY};
use memmap::Mmap;
use std::sync::Arc;

pub struct RequestsProcessor {
    ordered_handlers: Vec<ResolvedHandler>,
    pub generated_at: DateTime<Utc>,
    pub google_oauth2_client: super::auth::google::GoogleOauth2Client,
    pub github_oauth2_client: super::auth::github::GithubOauth2Client,
    pub assistant_base_url: Url,
    pub maybe_identity: Option<Vec<u8>>,
    strict_transport_security: Option<u64>,
    rules_counter: AccountCounters,
    pub account_unique_id: AccountUniqueId,
    _stop_public_counter_tx: oneshot::Sender<()>,
    cache: Cache,
    project_name: ProjectName,
    url_prefix: MountPointBaseUrl,
    mount_point_name: MountPointName,
    xchacha20poly1305_secret_key: xchacha20poly1305::Key,
    max_pop_cache_size_bytes: Byte,
    gw_location: SmolStr,
    log_messages_tx: mpsc::Sender<LogMessage>,
    dbip: Option<Arc<maxminddb::Reader<Mmap>>>,
}

impl RequestsProcessor {
    async fn do_process(
        &self,
        req: &mut Request<Body>,
        res: &mut Response<Body>,
        requested_url: &http::uri::Uri,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        facts: Arc<Mutex<HashMap<SmolStr, SmolStr>>>,
        log_message: &mut LogMessage,
    ) {
        if let Some(db) = self.dbip.as_ref() {
            if let Ok(loc) = db.lookup::<LocationAndIsp>(remote_addr.ip()) {
                let mut locked = facts.lock();
                if let Some(isp) = loc.isp {
                    locked.insert("isp".into(), isp);
                };
                if let Some(organization) = loc.organization {
                    locked.insert("organization".into(), organization);
                };
                if let Some(city) = loc.city.and_then(|c| c.names.and_then(|c| c.en)) {
                    locked.insert("city".into(), city);
                };
                if let Some(country) = loc.country.map(|c| c.iso_code).flatten() {
                    locked.insert("country".into(), country);
                };
            }
        }
        facts
            .lock()
            .insert("mount_point_hostname".into(), self.url_prefix.host().into());

        self.rules_counter.register_request(&self.account_unique_id);

        let mut processed_by = None;
        let original_req_headers = req.headers().clone();
        for handler in &self.ordered_handlers {
            // restore original headers
            *req.headers_mut() = original_req_headers.clone();

            // create new response for each handler, avoid using dirty data from the previous handler
            *res = Response::new(Body::empty());

            if req.method() == &Method::GET || req.method() == &Method::HEAD {
                // eligible for caching
                // lookup for cache response and respond if exists

                let cached_response = self
                    .cache
                    .serve_from_cache(
                        &self.account_unique_id,
                        &self.project_name,
                        &self.mount_point_name,
                        &handler.handler_name,
                        &handler.handler_checksum,
                        req.headers(),
                        req.method(),
                        req.uri().path_and_query().expect("FIXME").as_str(),
                        &self.xchacha20poly1305_secret_key,
                    )
                    .await;

                match cached_response {
                    Ok(Some(resp)) => {
                        info!("found data in cache");
                        if resp.status().is_success() || resp.status() == StatusCode::NOT_MODIFIED {
                            // respond from cache only if success response

                            *res = resp;

                            res.headers_mut()
                                .insert("x-exg-edge-cached", "1".parse().unwrap());

                            if let Ok(Some(len)) =
                                res.headers().typed_get::<typed_headers::ContentLength>()
                            {
                                log_message.content_len = Some(len.0);
                                let byte = Byte::from(len.0);

                                info!(
                                    "serve {} bytes from cache!",
                                    byte.get_appropriate_unit(true)
                                );
                            }

                            log_message.steps.push(ProcessingStep::ServedFromCache);

                            return;
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        crate::statistics::CACHE_ERRORS
                            .with_label_values(&[crate::statistics::CACHE_ACTION_READ])
                            .inc();
                        warn!("Error reading data from cache: {}", e);
                    }
                }
            }

            if let Some(rebased_url) = Rebase::rebase_url(&handler.rebase, &requested_url) {
                let result = handler
                    .handle_request(
                        req,
                        res,
                        requested_url,
                        &rebased_url,
                        local_addr,
                        remote_addr,
                        log_message,
                    )
                    .await;

                match result {
                    ResolvedHandlerProcessingResult::Processed => {
                        info!("handle successfully finished. exit from handlers loop");
                        processed_by = Some(handler);
                        break;
                    }
                    ResolvedHandlerProcessingResult::FiltersNotMatched => {}
                    ResolvedHandlerProcessingResult::NextHandler => {}
                };
            } else {
                continue;
            }
        }

        match processed_by {
            None => {
                *res = Response::new(Body::from("Not found"));
                *res.status_mut() = StatusCode::NOT_FOUND;
            }
            Some(handler) => {
                let optimize_result = self.optimize_image(req, res, log_message).await;
                if let Err(e) = optimize_result {
                    warn!("Skipped image optimization due to the error: {}", e);
                }

                self.compress(req, res, log_message);

                res.headers_mut()
                    .insert("server", HeaderValue::from_static("exogress"));

                self.save_to_cache(req, res, handler);
            }
        }

        if let Ok(Some(len)) = res.headers().typed_get::<typed_headers::ContentLength>() {
            log_message.content_len = Some(len.0);
        }

        if let Some(strict_transport_security) = &self.strict_transport_security {
            res.headers_mut().insert(
                STRICT_TRANSPORT_SECURITY,
                format!("max-age={}", strict_transport_security)
                    .parse()
                    .unwrap(),
            );
        }
    }

    pub async fn process(
        &self,
        req: &mut Request<Body>,
        res: &mut Response<Body>,
        requested_url: &http::uri::Uri,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
    ) {
        let started_at = Instant::now();
        let facts = Arc::new(Mutex::new(HashMap::<SmolStr, SmolStr>::new()));

        let mut log_message = LogMessage {
            gw_location: self.gw_location.clone(),
            time: Utc::now(),
            client_addr: remote_addr.ip(),
            account_unique_id: self.account_unique_id.clone(),
            project: self.project_name.clone(),
            mount_point: self.mount_point_name.clone(),
            url: requested_url.to_string().into(),
            method: req.method().to_string().into(),
            status_code: None,
            time_taken: None,
            content_len: None,
            steps: vec![],
            facts: facts.clone(),
        };

        self.do_process(
            req,
            res,
            requested_url,
            local_addr,
            remote_addr,
            facts,
            &mut log_message,
        )
        .await;

        log_message.time_taken = Some(started_at.elapsed());
        log_message.status_code = Some(res.status().as_u16());

        self.log_messages_tx
            .clone()
            .send(log_message)
            .await
            .unwrap();
    }

    fn save_to_cache(
        &self,
        req: &Request<Body>,
        res: &mut Response<Body>,
        handler: &ResolvedHandler,
    ) {
        if req.method() != &Method::GET && req.method() != &Method::HEAD {
            return;
        };

        if !res.status().is_success() {
            return;
        }

        if req.headers().get(RANGE).is_some() {
            info!("Range header presented. Skip caching.");
            return;
        }

        let cache_entries: Vec<_> = res
            .headers()
            .get_all(CACHE_CONTROL)
            .iter()
            .map(|cache_control_header| {
                let cache_control = cache_control_header.to_str().unwrap();
                cache_control
                    .split(',')
                    .map(|item: &str| item.trim_matches(' '))
            })
            .flatten()
            .collect();

        let caching_allowed = cache_entries.iter().any(|&c| c == "public")
            && !cache_entries
                .iter()
                .any(|&c| c == "no-cache" || c == "private" || c == "no-store");

        let max_age = cache_entries
            .iter()
            .filter_map(|header| header.strip_prefix("max-age="))
            .map(|h| Ok::<_, anyhow::Error>(chrono::Duration::seconds(h.parse()?)))
            .flatten()
            .next();

        info!(
            "cache entries: {:?} {:?}. caching_allowed = {:?}",
            cache_entries, max_age, caching_allowed
        );
        if !caching_allowed || max_age.is_none() {
            return;
        }

        let max_age = max_age.unwrap();

        let path_and_query = req.uri().path_and_query().expect("FIXME").to_string();

        let cache = self.cache.clone();
        let account_unique_id = self.account_unique_id.clone();
        let project_name = self.project_name.clone();
        let mount_point_name = self.mount_point_name.clone();
        let max_pop_cache_size_bytes = self.max_pop_cache_size_bytes;
        let xchacha20poly1305_secret_key = self.xchacha20poly1305_secret_key.clone();

        let method = req.method().clone();
        let req_headers = req.headers().clone();
        let res_headers = res.headers().clone();
        let status = res.status().clone();
        let handler_name = handler.handler_name.clone();
        let handler_checksum = handler.handler_checksum;

        let (mut resp_tx, resp_rx) = mpsc::channel(1);

        let mut original_body_stream = mem::replace(res.body_mut(), Body::empty());

        tokio::spawn(async move {
            let tempdir = tokio::task::spawn_blocking(|| tempfile::tempdir())
                .await
                .expect("FIXME")
                .expect("FIXME");

            let tempfile_path = tempdir.path().to_owned().join("req");
            let mut original_file_size = 0;
            let mut tempfile = tokio::fs::File::create(&tempfile_path)
                .await
                .expect("FIXME");

            let (mut enc_stream, header) =
                sodiumoxide::crypto::secretstream::Stream::init_push(&xchacha20poly1305_secret_key)
                    .map_err(|_| anyhow!("could not init encryption"))?;

            while let Some(item_result) = original_body_stream.next().await {
                let item = item_result?;
                original_file_size += item.len();

                let mut result_vec = enc_stream
                    .push(
                        item.as_ref(),
                        None,
                        sodiumoxide::crypto::secretstream::Tag::Message,
                    )
                    .unwrap();

                let mut v = u32::try_from(result_vec.len())
                    .unwrap()
                    .to_be_bytes()
                    .to_vec();
                v.append(&mut result_vec);
                tempfile.write_all(&v).await.unwrap();

                resp_tx
                    .send(item)
                    .await
                    .map_err(|_e| anyhow!("error sending to client"))?;
            }

            info!("Body successfully sent. Saving temp file to cache storage");

            let cached_response = cache
                .save_content(
                    &account_unique_id,
                    &project_name,
                    &mount_point_name,
                    &handler_name,
                    &handler_checksum,
                    &method,
                    &req_headers,
                    &res_headers,
                    status,
                    path_and_query.as_str(),
                    original_file_size.try_into().unwrap(),
                    header,
                    max_pop_cache_size_bytes,
                    Utc::now() + max_age,
                    &xchacha20poly1305_secret_key,
                    tempfile_path,
                )
                .await;

            info!("cached save result = {:?}", cached_response);
            if let Err(_e) = cached_response {
                crate::statistics::CACHE_ERRORS
                    .with_label_values(&[crate::statistics::CACHE_ACTION_WRITE])
                    .inc();
            }

            Ok::<_, anyhow::Error>(())
        });

        *res.body_mut() = Body::wrap_stream(resp_rx.map(Ok::<_, hyper::Error>));
    }
}

#[derive(Clone, Debug)]
pub struct Rebase {
    base_path: Vec<UrlPathSegmentOrQueryPart>,
    replace_base_path: Vec<UrlPathSegmentOrQueryPart>,
}

impl Rebase {
    /// Return rebased url if matched
    pub fn rebase_url(
        rebase: &Option<Rebase>,
        requested_url: &http::uri::Uri,
    ) -> Option<http::uri::Uri> {
        let mut rebased_url = requested_url.clone();

        if let Some(rebase) = rebase {
            let mut requested_segments = requested_url.path_segments().into_iter();

            let matched_segments_count = rebase
                .base_path
                .iter()
                .zip(&mut requested_segments)
                .take_while(|(a, b)| &a.as_ref() == b)
                .count();

            if matched_segments_count == rebase.base_path.len() {
                rebased_url.clear_segments();

                for segment in &rebase.replace_base_path {
                    rebased_url.push_segment(segment.as_str());
                }

                // add rest part
                for segment in requested_segments {
                    rebased_url.push_segment(segment);
                }
            } else {
                // path don't match the base path. move on to the next handler
                return None;
            }
        }

        return Some(rebased_url);
    }
}

impl From<config_core::Rebase> for Rebase {
    fn from(rebase: config_core::Rebase) -> Self {
        Rebase {
            base_path: rebase.base_path,
            replace_base_path: rebase.replace_base_path,
        }
    }
}

#[derive(Debug)]
enum ResolvedHandlerVariant {
    Proxy(proxy::ResolvedProxy),
    StaticDir(static_dir::ResolvedStaticDir),
    Auth(auth::ResolvedAuth),
    S3Bucket(s3_bucket::ResolvedS3Bucket),
    GcsBucket(gcs_bucket::ResolvedGcsBucket),
    ApplicationFirewall(application_firewall::ResolvedApplicationFirewall),
    PassThrough(pass_through::ResolvedPassThrough),
}

#[derive(Debug)]
pub enum HandlerInvocationResult {
    Responded,
    ToNextHandler,
    Exception {
        name: Exception,
        data: HashMap<SmolStr, SmolStr>,
    },
}

impl ResolvedHandlerVariant {
    async fn invoke(
        &self,
        req: &mut Request<Body>,
        res: &mut Response<Body>,
        requested_url: &http::uri::Uri,
        rebased_url: &http::uri::Uri,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        log_message: &mut LogMessage,
    ) -> HandlerInvocationResult {
        match self {
            ResolvedHandlerVariant::Proxy(proxy) => {
                proxy
                    .invoke(
                        req,
                        res,
                        requested_url,
                        rebased_url,
                        local_addr,
                        remote_addr,
                        log_message,
                    )
                    .await
            }
            ResolvedHandlerVariant::StaticDir(static_dir) => {
                static_dir
                    .invoke(
                        req,
                        res,
                        requested_url,
                        rebased_url,
                        local_addr,
                        remote_addr,
                        log_message,
                    )
                    .await
            }
            ResolvedHandlerVariant::Auth(auth) => {
                auth.invoke(req, res, requested_url, log_message).await
            }
            ResolvedHandlerVariant::S3Bucket(s3_bucket) => {
                s3_bucket
                    .invoke(req, res, requested_url, rebased_url, log_message)
                    .await
            }
            ResolvedHandlerVariant::GcsBucket(gcs_bucket) => {
                gcs_bucket
                    .invoke(req, res, requested_url, rebased_url, log_message)
                    .await
            }
            ResolvedHandlerVariant::ApplicationFirewall(application_firewall) => {
                application_firewall
                    .invoke(req, res, requested_url, rebased_url, log_message)
                    .await
            }
            ResolvedHandlerVariant::PassThrough(pass_through) => {
                pass_through
                    .invoke(req, res, requested_url, rebased_url, log_message)
                    .await
            }
        }
    }
}

#[derive(Debug)]
enum ResolvedFinalizingRuleAction {
    Invoke {
        rescue: Vec<ResolvedRescueItem>,
    },
    NextHandler,
    Throw {
        exception: Exception,
        data: HashMap<SmolStr, SmolStr>,
    },
    Respond {
        static_response_name: StaticResponseName,
        static_response: Option<ResolvedStaticResponse>,
        data: HashMap<SmolStr, SmolStr>,
        rescue: Vec<ResolvedRescueItem>,
    },
}

#[derive(Debug)]
enum ResolvedRuleAction {
    Finalizing(ResolvedFinalizingRuleAction),
    None,
}

impl ResolvedRuleAction {
    fn is_finalizing(&self) -> bool {
        match self {
            ResolvedRuleAction::None => false,
            ResolvedRuleAction::Finalizing(_) => true,
        }
    }
}

#[derive(Debug, Clone)]
enum ResolvedCatchAction {
    StaticResponse {
        static_response_name: StaticResponseName,
        static_response: Option<ResolvedStaticResponse>,
        data: HashMap<SmolStr, SmolStr>,
    },
    Throw {
        exception: Exception,
        data: HashMap<SmolStr, SmolStr>,
    },
    NextHandler,
}

#[derive(Debug)]
pub struct ResolvedFilter {
    pub path: MatchingPath,
    pub method: MethodMatcher,
    pub trailing_slash: TrailingSlashFilterRule,
    pub base_path: Vec<UrlPathSegmentOrQueryPart>,
}

impl ResolvedFilter {
    fn is_matches(&self, url: &http::uri::Uri, method: &http::Method) -> bool {
        let is_trailing_slash = url.path().ends_with("/");

        if !self.method.is_match(method) {
            return false;
        }

        let mut segments = vec![];
        {
            let mut path_segments = url.path_segments().into_iter();
            let mut base_segments = self.base_path.iter();

            while let Some(expected_base_segment) = base_segments.next() {
                if let Some(segment) = path_segments.next() {
                    if segment != expected_base_segment.as_str() {
                        return false;
                    }
                } else {
                    return false;
                }
            }

            while let Some(segment) = path_segments.next() {
                if !segment.is_empty() {
                    segments.push(segment.to_string());
                }
            }
        }

        let matcher = || match &self.path {
            MatchingPath::Root
                if segments.len() == 0 || (segments.len() == 1 && segments[0].is_empty()) =>
            {
                return true;
            }
            MatchingPath::Wildcard => {
                return true;
            }
            MatchingPath::Strict(match_segments) => {
                if match_segments.len() != segments.len() {
                    return false;
                }
                for (match_segment, segment) in match_segments.iter().zip(&segments) {
                    if !match_segment.is_match(segment) {
                        return false;
                    }
                }
                return true;
            }
            MatchingPath::LeftWildcardRight(left_match_segments, right_match_segments) => {
                if left_match_segments.len() + right_match_segments.len() > segments.len() {
                    return false;
                }
                for (match_segment, segment) in left_match_segments.iter().zip(&segments) {
                    if !match_segment.is_match(segment) {
                        return false;
                    }
                }
                for (match_segment, segment) in
                    right_match_segments.iter().rev().zip(segments.iter().rev())
                {
                    if !match_segment.is_match(segment) {
                        return false;
                    }
                }
                return true;
            }
            MatchingPath::LeftWildcard(left_match_segments) => {
                if left_match_segments.len() > segments.len() {
                    return false;
                }
                for (match_segment, segment) in left_match_segments.iter().zip(&segments) {
                    if !match_segment.is_match(segment) {
                        return false;
                    }
                }
                return true;
            }
            MatchingPath::WildcardRight(right_match_segments) => {
                if right_match_segments.len() > segments.len() {
                    return false;
                }
                for (match_segment, segment) in
                    right_match_segments.iter().rev().zip(segments.iter().rev())
                {
                    if !match_segment.is_match(segment) {
                        return false;
                    }
                }
                return true;
            }
            _ => return false,
        };

        let is_path_matched = (matcher)();

        let trailing_slash_condition_met = match self.trailing_slash {
            TrailingSlashFilterRule::Require => is_trailing_slash == true,
            TrailingSlashFilterRule::Allow => true,
            TrailingSlashFilterRule::Deny => is_trailing_slash == false,
        };

        is_path_matched && trailing_slash_condition_met
    }
}

#[derive(Debug, Clone)]
struct RuleModifications {
    pub insert_headers: HeaderMap,
    pub append_headers: HeaderMap,
    pub remove_headers: Vec<HeaderName>,
}

#[derive(Debug)]
struct ResolvedRule {
    filter: ResolvedFilter,
    request_modifications: RequestModifications,
    response_modifications: Vec<MatchedResponseModification>,
    action: ResolvedRuleAction,
}

impl ResolvedRule {
    fn get_action(
        &self,
        url: &http::uri::Uri,
        method: &http::Method,
    ) -> Option<(
        &ResolvedRuleAction,
        &RequestModifications,
        &Vec<MatchedResponseModification>,
    )> {
        if !self.filter.is_matches(url, method) {
            return None;
        } else {
            info!("{} matches {:?} action {:?}", url, self.filter, self.action);
        }

        Some((
            &self.action,
            &self.request_modifications,
            &self.response_modifications,
        ))
    }
}

struct ResolvedHandler {
    handler_name: HandlerName,
    handler_checksum: HandlerChecksum,

    config_name: Option<ConfigName>,

    resolved_variant: ResolvedHandlerVariant,

    rebase: Option<Rebase>,

    priority: u16,
    handler_rescue: Vec<ResolvedRescueItem>,

    mount_point_rescue: Vec<ResolvedRescueItem>,
    config_rescue: Vec<ResolvedRescueItem>,
    project_rescue: Vec<ResolvedRescueItem>,

    resolved_rules: Vec<ResolvedRule>,

    account_unique_id: AccountUniqueId,
    rules_counter: AccountCounters,
}

#[derive(Debug)]
enum Rescueable<'a> {
    Exception {
        exception: &'a Exception,
        data: &'a HashMap<SmolStr, SmolStr>,
    },
    StatusCode(StatusCode),
}

impl<'a> Rescueable<'a> {
    fn is_exception(&'a self) -> bool {
        match self {
            Rescueable::Exception { .. } => true,
            Rescueable::StatusCode(_) => false,
        }
    }

    fn data(&'a self) -> Option<&'a HashMap<SmolStr, SmolStr>> {
        match self {
            Rescueable::Exception { data, .. } => Some(data),
            Rescueable::StatusCode(_) => None,
        }
    }
}

#[must_use]
enum ResolvedHandlerProcessingResult {
    Processed,
    FiltersNotMatched,
    NextHandler,
}

impl ResolvedHandler {
    fn is_exception_matches(matcher: &Exception, exception: &Exception) -> bool {
        if matcher.0.len() > exception.0.len() {
            return false;
        }

        let zipped = matcher.0.iter().zip(exception.0.iter());

        for (matcher_segment, exception_segment) in zipped {
            if matcher_segment != exception_segment {
                return false;
            }
        }

        true
    }

    fn is_status_code_matches(matcher: &StatusCodeRange, status_code: &StatusCode) -> bool {
        match matcher {
            StatusCodeRange::Single(single) => single == status_code,
            StatusCodeRange::Range(from, to) => {
                (from.as_u16()..=to.as_u16()).contains(&status_code.as_u16())
            }
            StatusCodeRange::List(codes) => codes
                .iter()
                .find(|code| code.as_u16() == status_code.as_u16())
                .is_some(),
        }
    }

    fn find_exception_handler(
        rescue: &Vec<ResolvedRescueItem>,
        rescueable: &Rescueable<'_>,
    ) -> Option<ResolvedCatchAction> {
        for rescue_item in rescue.iter() {
            match (rescueable, &rescue_item.catch) {
                (
                    Rescueable::Exception { exception, .. },
                    ResolvedCatchMatcher::Exception(exception_matcher),
                ) if Self::is_exception_matches(exception_matcher, exception) => {
                    return Some(rescue_item.handle.clone())
                }
                (
                    Rescueable::StatusCode(status_code),
                    ResolvedCatchMatcher::StatusCode(status_code_rande),
                ) if Self::is_status_code_matches(status_code_rande, status_code) => {
                    return Some(rescue_item.handle.clone())
                }
                _ => {}
            }
        }

        None
    }

    /// Handle exception in the right order
    fn handle_rescueable(
        &self,
        req: &Request<Body>,
        res: &mut Response<Body>,
        rescueable: &Rescueable<'_>,
        is_in_exception: bool,
        maybe_rule_invoke_catch: Option<&Vec<ResolvedRescueItem>>,
        log_message: &mut LogMessage,
    ) -> ResolvedHandlerProcessingResult {
        info!("handle rescueable: {:?}", rescueable);

        if let &Rescueable::Exception { exception, data } = rescueable {
            log_message
                .steps
                .push(ProcessingStep::Exception(ExceptionProcessingStep {
                    exception: exception.clone(),
                    data: data.clone(),
                }));
        }

        let maybe_resolved_exception = maybe_rule_invoke_catch
            .and_then(|r| Self::find_exception_handler(r, &rescueable))
            .or_else(|| Self::find_exception_handler(&self.handler_rescue, &rescueable))
            .or_else(|| Self::find_exception_handler(&self.mount_point_rescue, &rescueable))
            .or_else(|| Self::find_exception_handler(&self.config_rescue, &rescueable))
            .or_else(|| Self::find_exception_handler(&self.project_rescue, &rescueable));

        let result = match maybe_resolved_exception {
            None => match rescueable {
                &Rescueable::Exception { exception, data } => {
                    RescueableHandleResult::UnhandledException {
                        exception_name: exception.clone(),
                        data: data.clone(),
                    }
                }
                Rescueable::StatusCode(_) => RescueableHandleResult::FinishProcessing,
            },
            Some(ResolvedCatchAction::Throw { exception, data }) => match rescueable {
                &Rescueable::Exception { .. } => RescueableHandleResult::UnhandledException {
                    exception_name: exception.clone(),
                    data: data.clone(),
                },
                Rescueable::StatusCode(_) => RescueableHandleResult::FinishProcessing,
            },
            Some(ResolvedCatchAction::StaticResponse {
                static_response_name,
                static_response,
                data,
            }) => RescueableHandleResult::StaticResponse {
                static_response_name: static_response_name.clone(),
                static_response: static_response.clone(),
                data: data.clone(),
            },
            Some(ResolvedCatchAction::NextHandler) => RescueableHandleResult::NextHandler,
        };

        match result {
            RescueableHandleResult::StaticResponse {
                static_response_name,
                static_response,
                mut data,
            } => {
                if let Some(additional_data) = rescueable.data() {
                    data.extend(additional_data.iter().map(|(k, v)| (k.clone(), v.clone())));
                }
                return self.handle_static_response(
                    req,
                    res,
                    &static_response_name,
                    &static_response,
                    data,
                    rescueable.is_exception() || is_in_exception,
                    maybe_rule_invoke_catch,
                    log_message,
                );
            }
            RescueableHandleResult::NextHandler => {
                info!("move on to next handler");
                return ResolvedHandlerProcessingResult::NextHandler;
            }
            RescueableHandleResult::UnhandledException { exception_name, .. } => {
                warn!("unhandled exception: {}", exception_name);
                self.respond_server_error(res);
                return ResolvedHandlerProcessingResult::Processed;
            }
            RescueableHandleResult::FinishProcessing => {
                info!("processing finished");
                return ResolvedHandlerProcessingResult::Processed;
            }
        }
    }

    /// Find appropriate final action, which should be executed
    fn find_action(
        &self,
        url: &http::uri::Uri,
        method: &http::Method,
    ) -> Option<(
        &ResolvedRuleAction,
        Vec<&RequestModifications>,
        &Vec<MatchedResponseModification>,
    )> {
        let mut request_modifications_list = Vec::new();

        let rule_action = self
            .resolved_rules
            .iter()
            .filter_map(|resolved_rule| resolved_rule.get_action(url, method))
            .inspect(|_| {
                self.rules_counter.register_rule(&self.account_unique_id);
            })
            .inspect(|(_, request_modifications, _response_modifications)| {
                request_modifications_list.push(*request_modifications);
                // info!(
                //     "request_modifications = {:?}; response_modifications = {:?}",
                //     request_modifications, response_modifications
                // );
            })
            .filter(|(action, _, _)| action.is_finalizing())
            .map(|(action, _, response_modifications)| (action, response_modifications))
            .next();

        rule_action.map(move |(action, response_modifications)| {
            (action, request_modifications_list, response_modifications)
        })
    }

    fn respond_server_error(&self, res: &mut Response<Body>) {
        *res = Response::new(Body::from("Internal server error"));
        *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    }

    // Handle whole request
    async fn handle_request(
        &self,
        req: &mut Request<Body>,
        res: &mut Response<Body>,
        requested_url: &http::uri::Uri,
        rebased_url: &http::uri::Uri,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        log_message: &mut LogMessage,
    ) -> ResolvedHandlerProcessingResult {
        let (action, request_modifications, response_modification) =
            match self.find_action(rebased_url, req.method()) {
                None => return ResolvedHandlerProcessingResult::FiltersNotMatched,
                Some(action) => action,
            };

        for request_modification in &request_modifications {
            apply_headers(req.headers_mut(), &request_modification.headers);
        }

        info!("Request headers after modification: {:?}", req.headers());

        match action {
            ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::Invoke {
                rescue: catch,
            }) => {
                let invocation_result = self
                    .resolved_variant
                    .invoke(
                        req,
                        res,
                        requested_url,
                        rebased_url,
                        local_addr,
                        remote_addr,
                        log_message,
                    )
                    .await;

                match invocation_result {
                    HandlerInvocationResult::Responded => {
                        for modification in response_modification {
                            if modification.status_code.is_belongs(&res.status()) {
                                apply_headers(
                                    res.headers_mut(),
                                    &modification.modifications.headers,
                                );
                            }
                        }

                        let rescueable = Rescueable::StatusCode(res.status());
                        return self.handle_rescueable(
                            req,
                            res,
                            &rescueable,
                            false,
                            Some(catch),
                            log_message,
                        );
                    }
                    HandlerInvocationResult::ToNextHandler => {
                        return ResolvedHandlerProcessingResult::NextHandler;
                    }
                    HandlerInvocationResult::Exception { name, data } => {
                        let rescueable = Rescueable::Exception {
                            exception: &name,
                            data: &data,
                        };
                        return self.handle_rescueable(
                            req,
                            res,
                            &rescueable,
                            false,
                            Some(catch),
                            log_message,
                        );
                    }
                }
            }
            ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::NextHandler) => {
                return ResolvedHandlerProcessingResult::NextHandler;
            }
            ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::Throw {
                exception,
                data,
            }) => {
                let rescueable = Rescueable::Exception { exception, data };
                return self.handle_rescueable(req, res, &rescueable, false, None, log_message);
            }
            ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::Respond {
                static_response_name,
                static_response,
                data,
                rescue,
            }) => {
                return self.handle_static_response(
                    req,
                    res,
                    static_response_name,
                    static_response,
                    data.clone(),
                    false,
                    Some(rescue),
                    log_message,
                );
            }
            ResolvedRuleAction::None => {
                unreachable!("None action should never be called for execution")
            }
        }
    }

    fn handle_static_response(
        &self,
        req: &Request<Body>,
        res: &mut Response<Body>,
        static_response_name: &StaticResponseName,
        maybe_static_response: &Option<ResolvedStaticResponse>,
        additional_data: HashMap<SmolStr, SmolStr>,
        is_in_exception: bool,
        maybe_rule_invoke_catch: Option<&Vec<ResolvedRescueItem>>,
        log_message: &mut LogMessage,
    ) -> ResolvedHandlerProcessingResult {
        log_message.steps.push(ProcessingStep::StaticResponse(
            StaticResponseProcessingStep {
                static_response: static_response_name.clone(),
                data: additional_data.clone(),
                config_name: self.config_name.clone(),
            },
        ));

        let facts = log_message.facts.clone();

        *res = Response::new(Body::empty());

        match maybe_static_response {
            None => {
                let rescueable = Rescueable::Exception {
                    exception: &"static-response-error:not-defined".parse().unwrap(),
                    data: &additional_data,
                };
                return self.handle_rescueable(
                    req,
                    res,
                    &rescueable,
                    true,
                    maybe_rule_invoke_catch,
                    log_message,
                );
            }
            Some(static_response) => match static_response.invoke(req, res, additional_data, facts)
            {
                Ok(()) => ResolvedHandlerProcessingResult::Processed,
                Err((exception, data)) => {
                    *res = Response::new(Body::empty());
                    if !is_in_exception {
                        let rescueable = Rescueable::Exception {
                            exception: &exception,
                            data: &data,
                        };
                        return self.handle_rescueable(
                            req,
                            res,
                            &rescueable,
                            false,
                            maybe_rule_invoke_catch,
                            log_message,
                        );
                    } else {
                        error!(
                            "error evaluating static response while in exception handling: {:?}. {:?}",
                            exception, data
                        );
                        *res.body_mut() = Body::from("Internal server error");
                        *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;

                        return ResolvedHandlerProcessingResult::Processed;
                    }
                }
            },
        }
    }
}

fn apply_headers(headers: &mut HeaderMap<HeaderValue>, modification: &ModifyHeaders) {
    for (header_name, header_value) in &modification.append.0 {
        headers.append(header_name.clone(), header_value.clone());
    }
    for (header_name, header_value) in &modification.insert.0 {
        headers.insert(header_name.clone(), header_value.clone());
    }
    for header_name in &modification.remove {
        headers.remove(header_name);
    }
}

#[derive(Debug)]
#[must_use]
enum RescueableHandleResult {
    /// Respond with static response
    StaticResponse {
        static_response_name: StaticResponseName,
        static_response: Option<ResolvedStaticResponse>,
        data: HashMap<SmolStr, SmolStr>,
    },
    /// Move on to next handler
    NextHandler,
    /// Exception hasn't been handled by ant of handlers
    UnhandledException {
        exception_name: Exception,
        data: HashMap<SmolStr, SmolStr>,
    },
    /// Finish processing normally, respond with prepared response
    FinishProcessing,
}

fn resolve_static_response(
    static_response_name: &StaticResponseName,
    status_code: &Option<exogress_common::config_core::StatusCode>,
    data: &BTreeMap<SmolStr, SmolStr>,
    static_responses: &HashMap<StaticResponseName, StaticResponse>,
) -> Option<ResolvedStaticResponse> {
    let static_response: StaticResponse = static_responses.get(&static_response_name)?.clone();

    let static_response_status_code = match &static_response {
        StaticResponse::Redirect(redirect) => redirect.redirect_type.status_code(),
        StaticResponse::Raw(raw) => raw.status_code,
    };

    let fallback_to_accept = match &static_response {
        StaticResponse::Redirect(_) => None,
        StaticResponse::Raw(raw) => raw
            .fallback_accept
            .as_ref()
            .and_then(|accept| mime::Mime::from_str(&accept).ok()),
    };

    let resolved = ResolvedStaticResponse {
        status_code: status_code
            .as_ref()
            .map(|s| s.0)
            .unwrap_or(static_response_status_code),
        fallback_to_accept,
        body: match &static_response {
            StaticResponse::Raw(raw) => (&raw.body).clone(),
            StaticResponse::Redirect(_) => {
                vec![]
            }
        },
        headers: match &static_response {
            StaticResponse::Raw(raw) => raw.common.headers.clone(),
            StaticResponse::Redirect(redirect) => {
                let mut headers = redirect.common.headers.clone();
                headers.insert(
                    LOCATION,
                    redirect.destination.to_destiation_string().parse().unwrap(),
                );
                headers
            }
        },
        data: data
            .iter()
            .map(|(k, v)| (k.as_str().into(), v.as_str().into()))
            .collect(),
    };

    Some(resolved)
}

fn resolve_catch_action(
    catch_action: &CatchAction,
    static_responses: &HashMap<StaticResponseName, StaticResponse>,
) -> Option<ResolvedCatchAction> {
    Some(match catch_action {
        CatchAction::StaticResponse {
            name,
            status_code,
            data,
        } => ResolvedCatchAction::StaticResponse {
            static_response_name: name.clone(),
            static_response: resolve_static_response(name, status_code, data, static_responses),
            data: data.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        },
        CatchAction::Throw { exception, data } => ResolvedCatchAction::Throw {
            exception: exception.clone(),
            data: data.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        },
        CatchAction::NextHandler => ResolvedCatchAction::NextHandler,
    })
}

fn resolve_rescue_items(
    rescue: &[RescueItem],
    static_responses: &HashMap<StaticResponseName, StaticResponse>,
) -> Option<Vec<ResolvedRescueItem>> {
    rescue
        .iter()
        .map(|rescue_item| {
            Some(ResolvedRescueItem {
                catch: match &rescue_item.catch {
                    CatchMatcher::StatusCode(status_code) => {
                        ResolvedCatchMatcher::StatusCode(status_code.clone())
                    }
                    CatchMatcher::Exception(exception) => {
                        ResolvedCatchMatcher::Exception(exception.clone())
                    }
                },
                handle: resolve_catch_action(&rescue_item.handle, &static_responses)?,
            })
        })
        .collect::<Option<_>>()
}
impl RequestsProcessor {
    pub fn new(
        resp: ConfigsResponse,
        google_oauth2_client: super::auth::google::GoogleOauth2Client,
        github_oauth2_client: super::auth::github::GithubOauth2Client,
        assistant_base_url: Url,
        client_tunnels: ClientTunnels,
        rules_counter: AccountCounters,
        individual_hostname: SmolStr,
        maybe_identity: Option<Vec<u8>>,
        traffic_counters_tx: mpsc::Sender<RecordedTrafficStatistics>,
        log_messages_tx: mpsc::Sender<LogMessage>,
        gw_location: &str,
        cache: Cache,
        presence_client: presence::Client,
        dbip: Option<Arc<maxminddb::Reader<Mmap>>>,
        resolver: TokioAsyncResolver,
    ) -> anyhow::Result<RequestsProcessor> {
        let xchacha20poly1305_secret_key =
            xchacha20poly1305::Key::from_slice(&hex::decode(&resp.xchacha20poly1305_secret_key)?)
                .ok_or_else(|| anyhow!("could not parse xchacha20poly1305 secret key"))?;

        crate::statistics::ACTIVE_REQUESTS_PROCESSORS.inc();

        let max_pop_cache_size_bytes = resp.max_pop_cache_size_bytes;
        let traffic_counters = TrafficCounters::new(resp.account_unique_id.clone());
        let (stop_public_counter_tx, stop_public_counter_rx) = oneshot::channel();
        tokio::spawn(TrafficCounters::spawn_flusher(
            traffic_counters.clone(),
            traffic_counters_tx,
            stop_public_counter_rx,
        ));

        let grouped = resp.configs.iter().group_by(|item| &item.config_name);

        let project_rescue = resp.project_config.rescue;
        let jwt_ecdsa = JwtEcdsa {
            private_key: resp.jwt_ecdsa.private_key.into(),
            public_key: resp.jwt_ecdsa.public_key.into(),
        };

        let mount_point_base_url = resp.url_prefix;
        let account_unique_id = resp.account_unique_id;
        let account_name = resp.account;
        let project_name = resp.project;
        let params = resp.params.clone();

        let project_mount_points = resp
            .project_config
            .mount_points
            .into_iter()
            .map(|(k, v)| (k, (None, None, None, None, None, None, v.into())));

        let grouped_mount_points = grouped
            .into_iter()
            .map(move |(config_name, configs)| {
                let entry: &ConfigData = &configs
                    .into_iter()
                    .map(|entry| (entry.instance_ids.len(), entry))
                    .sorted_by(|(left, _), (right, _)| left.cmp(&right).reverse())
                    .into_iter()
                    .next() //keep only revision with largest number of instances
                    .unwrap()
                    .1;

                let config = &entry.config;
                let instance_ids = entry.instance_ids.clone();
                let active_profile = entry.active_profile.clone();

                let upstreams = &config.upstreams;

                let client_rescue = config.rescue.clone();
                let client_config_static_responses = config.static_responses.clone();

                config
                    .mount_points
                    .clone()
                    .into_iter()
                    .filter({
                        shadow_clone!(active_profile);

                        move |(_, mp)| is_profile_active(&mp.profiles, &active_profile)
                    })
                    .map(move |(mp_name, mp)| {
                        (
                            mp_name,
                            (
                                Some(config_name.clone()),
                                Some(upstreams.clone()),
                                Some(instance_ids.clone()),
                                Some(client_rescue.clone()),
                                Some(client_config_static_responses.clone()),
                                Some(active_profile.clone()),
                                mp,
                            ),
                        )
                    })
            })
            .flatten()
            .chain(project_mount_points)
            .group_by(|a| a.0.clone())
            .into_iter()
            .map(|a| a.1)
            .flatten()
            .collect::<Vec<_>>();

        if grouped_mount_points.is_empty() {
            return Err(anyhow!("no mount points returned"));
        }

        let mount_point_name = grouped_mount_points.iter().next().expect("FIXME").0.clone();

        let project_static_responses = resp.project_config.static_responses.clone();

        let mut merged_resolved_handlers = vec![];

        for (
            _mp_name,
            (
                config_name,
                upstreams,
                instance_ids,
                client_config_rescue,
                client_config_static_responses,
                active_profile,
                mp,
            ),
        ) in grouped_mount_points.into_iter()
        {
            let mp_rescue = mp.rescue.clone();

            shadow_clone!(instance_ids);
            shadow_clone!(project_rescue);
            shadow_clone!(jwt_ecdsa);
            shadow_clone!(mount_point_base_url);
            shadow_clone!(google_oauth2_client);
            shadow_clone!(github_oauth2_client);
            shadow_clone!(assistant_base_url);
            shadow_clone!(maybe_identity);
            shadow_clone!(client_tunnels);
            shadow_clone!(individual_hostname);
            shadow_clone!(account_name);
            shadow_clone!(account_unique_id);
            shadow_clone!(project_name);
            shadow_clone!(rules_counter);
            shadow_clone!(resolver);
            shadow_clone!(traffic_counters);
            shadow_clone!(presence_client);
            shadow_clone!(params);
            shadow_clone!(project_static_responses);
            shadow_clone!(active_profile);

            let public_client = hyper::Client::builder().build::<_, Body>(MeteredHttpsConnector {
                resolver: resolver.clone(),
                counters: traffic_counters.clone(),
                sent_counter: crate::statistics::PUBLIC_ENDPOINT_BYTES_SENT.clone(),
                recv_counter: crate::statistics::PUBLIC_ENDPOINT_BYTES_RECV.clone(),
            });

            let mp_static_responses = mp.static_responses;

            let mut r = mp.handlers
                .into_iter()
                .filter(|(_, handler)| {
                    if let Some(active_profile) = &active_profile {
                        is_profile_active(&handler.profiles, active_profile)
                    } else {
                        true
                    }
                })
                .map({
                    shadow_clone!(project_static_responses);
                    shadow_clone!(active_profile);

                    move |(handler_name, handler)| {
                        let replace_base_path = handler
                            .variant
                            .rebase()
                            .map(|r| r.replace_base_path.clone())
                            .unwrap_or_default();

                        let mut available_static_responses = HashMap::new();

                        // Add all project level static-response to mount-point accessible
                        for (k, v) in &project_static_responses {
                            available_static_responses.insert(k.clone(), v.clone());
                        }

                        // Add all config level static-response to mount-point accessible
                        if let Some(resps) = &client_config_static_responses {
                            for (k, v) in resps {
                                available_static_responses.insert(k.clone(), v.clone());
                            }
                        }

                        // Add all mount-point static-responses
                        for (k, v) in &mp_static_responses {
                            available_static_responses.insert(k.clone(), v.clone());
                        }

                        Some(ResolvedHandler {
                            handler_name: handler_name.clone(),
                            handler_checksum: {
                                use std::hash::{Hash, Hasher};

                                // FIXME
                                let mut s = seahash::SeaHasher::new();
                                handler.hash(&mut s);
                                handler_name.hash(&mut s);
                                let checksum = s.finish();

                                checksum.into()
                            },
                            config_name: config_name.clone(),
                            rebase: handler.variant.rebase().map(|r| r.clone().into()),
                            resolved_variant: match handler.variant {
                                ClientHandlerVariant::Auth(auth) => {
                                    ResolvedHandlerVariant::Auth(auth::ResolvedAuth {
                                        providers: auth
                                            .providers
                                            .into_iter()
                                            .map(|auth_def| {
                                                (
                                                    auth_def.name,
                                                    auth_def.acl.resolve(&params)
                                                )
                                            })
                                            .collect(),
                                        handler_name: handler_name.clone(),
                                        mount_point_base_url: mount_point_base_url.clone(),
                                        jwt_ecdsa: jwt_ecdsa.clone(),
                                        google_oauth2_client: google_oauth2_client.clone(),
                                        github_oauth2_client: github_oauth2_client.clone(),
                                        assistant_base_url: assistant_base_url.clone(),
                                        maybe_identity: maybe_identity.clone(),
                                    })
                                }
                                ClientHandlerVariant::StaticDir(static_dir) => {
                                    ResolvedHandlerVariant::StaticDir(static_dir::ResolvedStaticDir {
                                        config: static_dir,
                                        handler_name: handler_name.clone(),
                                        instance_ids: {
                                            let mut balancer = SmoothWeight::<InstanceId>::new();
                                            let instance_ids = instance_ids
                                                .as_ref()
                                                .expect("[BUG] try to access instance_ids on project-level config")
                                                .keys();
                                            for instance_id in instance_ids {
                                                balancer.add(instance_id.clone(), 1);
                                            }

                                            Mutex::new(balancer)
                                        },
                                        client_tunnels: client_tunnels.clone(),
                                        config_id: ConfigId {
                                            account_name: account_name.clone(),
                                            account_unique_id: account_unique_id.clone(),
                                            project_name: project_name.clone(),
                                            config_name: config_name.as_ref().expect("[BUG] try to access config_name on project-level config").clone(),
                                        },
                                        individual_hostname: individual_hostname.clone(),
                                        public_hostname: mount_point_base_url.host().into(),
                                    })
                                }
                                ClientHandlerVariant::Proxy(proxy) => {
                                    ResolvedHandlerVariant::Proxy(proxy::ResolvedProxy {
                                        name: proxy.upstream.clone(),
                                        upstream: upstreams
                                            .as_ref()
                                            .expect(
                                                "[BUG]: try to access upstream for project-level config",
                                            )
                                            .get(&proxy.upstream)
                                            .cloned()?,
                                        instance_ids: {
                                            let mut balancer = SmoothWeight::<InstanceId>::new();
                                            let instance_ids = instance_ids
                                                .as_ref()
                                                .expect("[BUG] try to access instance_ids on project-level config")
                                                .iter();
                                            for (instance_id, health_status) in instance_ids {
                                                if health_status.get(&proxy.upstream) == Some(&true) {
                                                    balancer.add(instance_id.clone(), 1);
                                                }
                                            }

                                            Mutex::new(balancer)
                                        },
                                        client_tunnels: client_tunnels.clone(),
                                        config_id: ConfigId {
                                            account_name: account_name.clone(),
                                            account_unique_id: account_unique_id.clone(),
                                            project_name: project_name.clone(),
                                            config_name: config_name.as_ref().expect("[BUG] try to access config_name on project-level config").clone(),
                                        },
                                        individual_hostname: individual_hostname.clone(),
                                        public_hostname: mount_point_base_url.host().into(),
                                        presence_client: presence_client.clone(),
                                    })
                                }
                                ClientHandlerVariant::S3Bucket(s3_bucket) => {
                                    ResolvedHandlerVariant::S3Bucket(s3_bucket::ResolvedS3Bucket {
                                        client: public_client.clone(),
                                        credentials:  s3_bucket
                                            .credentials
                                            .map(|container|
                                                container
                                                    .resolve(&params)
                                                    .map(|creds| {
                                                        rusty_s3::Credentials::new(creds.access_key_id.into(), creds.secret_access_key.into())
                                                    })
                                            ),
                                        bucket:
                                        s3_bucket.bucket.resolve(&params)
                                            .map(|s3_bucket_cfg| {
                                                rusty_s3::Bucket::new(
                                                    s3_bucket_cfg.region.endpoint(),
                                                    false,
                                                    s3_bucket_cfg.name.into(),
                                                    s3_bucket_cfg.region.to_string(),
                                                ).expect("FIXME")
                                            }),
                                    })
                                }
                                ClientHandlerVariant::GcsBucket(gcs_bucket) => {
                                    ResolvedHandlerVariant::GcsBucket(gcs_bucket::ResolvedGcsBucket {
                                        client: public_client.clone(),
                                        bucket_name: gcs_bucket.bucket.resolve(&params),
                                        auth: gcs_bucket.credentials.resolve(&params).map(|creds| {
                                            tame_oauth::gcp::ServiceAccountAccess::new(
                                                tame_oauth::gcp::ServiceAccountInfo::deserialize(
                                                    creds.json.as_str()
                                                ).expect("FIXME")
                                            ).expect("FIXME")
                                        }),
                                        token: Default::default(),
                                    })
                                }
                                ClientHandlerVariant::ApplicationFirewall(app_firewall) => {
                                    ResolvedHandlerVariant::ApplicationFirewall(application_firewall::ResolvedApplicationFirewall {
                                        uri_xss: app_firewall.uri_xss,
                                        uri_sqli: app_firewall.uri_sqli,
                                    })
                                }
                                ClientHandlerVariant::PassThrough(_) => {
                                    ResolvedHandlerVariant::PassThrough(ResolvedPassThrough {})
                                }
                            },
                            priority: handler.priority,
                            handler_rescue: resolve_rescue_items(
                                &handler.rescue,
                                &available_static_responses,
                            )?,
                            mount_point_rescue: resolve_rescue_items(
                                &mp_rescue,
                                &available_static_responses,
                            )?,
                            config_rescue: if let Some(client_rescue) = &client_config_rescue {
                                resolve_rescue_items(
                                    client_rescue,
                                    &available_static_responses,
                                )?
                            } else {
                                Default::default()
                            },
                            project_rescue: resolve_rescue_items(
                                &project_rescue,
                                &available_static_responses,
                            )?,
                            resolved_rules: handler
                                .rules
                                .into_iter()
                                .filter(|rule| {
                                    if let Some(active_profile) = &active_profile {
                                        is_profile_active(&rule.profiles, active_profile)
                                    } else {
                                        true
                                    }
                                })
                                .map(|rule: Rule| {
                                    Some(ResolvedRule {
                                        filter: ResolvedFilter {
                                            path: rule.filter.path,
                                            method: rule.filter.methods,
                                            trailing_slash: rule.filter.trailing_slash,
                                            base_path: replace_base_path.clone(),
                                        },
                                        request_modifications: rule
                                            .action
                                            .modify_request()
                                            .cloned()
                                            .unwrap_or_default(),
                                        response_modifications: rule
                                            .action
                                            .modify_response()
                                            .into_iter()
                                            .cloned()
                                            .collect(),
                                        action: match rule.action {
                                            Action::Invoke { rescue, .. } => ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::Invoke {
                                                rescue: resolve_rescue_items(
                                                    &rescue,
                                                    &available_static_responses,
                                                )?,
                                            }),
                                            Action::NextHandler => ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::NextHandler),
                                            Action::None{ .. } => ResolvedRuleAction::None,
                                            Action::Throw { exception, data } => ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::Throw {
                                                exception,
                                                data: data.iter().map(|(k,v)| (k.as_str().into(), v.as_str().into())).collect(),
                                            }),
                                            Action::Respond {
                                                name: static_response_name, status_code, data, rescue
                                            } => ResolvedRuleAction::Finalizing(ResolvedFinalizingRuleAction::Respond {
                                                static_response_name: static_response_name.clone(),
                                                static_response: resolve_static_response(
                                                    &static_response_name,
                                                    &status_code,
                                                    &data,
                                                    &available_static_responses,

                                                ),
                                                data: Default::default(), // TODO: what data should be here? argh, need integrateion test suite
                                                rescue: resolve_rescue_items(
                                                    &rescue,
                                                    &available_static_responses,
                                                )?,
                                            }),
                                        },
                                    })
                                })
                                .collect::<Option<_>>()?,
                            account_unique_id,
                            rules_counter: rules_counter.clone(),
                        })
                    }
                })
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| anyhow!("failed to build processor"))?;

            merged_resolved_handlers.append(&mut r);
        }

        merged_resolved_handlers.sort_by(|left, right| left.priority.cmp(&right.priority));

        Ok(RequestsProcessor {
            ordered_handlers: merged_resolved_handlers,
            generated_at: resp.generated_at,
            google_oauth2_client,
            github_oauth2_client,
            assistant_base_url,
            maybe_identity,
            strict_transport_security: resp.strict_transport_security,
            rules_counter,
            account_unique_id,
            _stop_public_counter_tx: stop_public_counter_tx,
            cache,
            project_name,
            url_prefix: mount_point_base_url.clone(),
            mount_point_name,
            xchacha20poly1305_secret_key,
            max_pop_cache_size_bytes,
            gw_location: gw_location.into(),
            log_messages_tx,
            dbip,
        })
    }
}

impl Drop for RequestsProcessor {
    fn drop(&mut self) {
        crate::statistics::ACTIVE_REQUESTS_PROCESSORS.dec();
    }
}

#[derive(Clone, Debug)]
struct ResolvedStaticResponse {
    status_code: StatusCode,
    fallback_to_accept: Option<mime::Mime>,
    body: Vec<ResponseBody>,
    headers: HeaderMap,
    data: HashMap<SmolStr, SmolStr>,
}

impl ResolvedStaticResponse {
    fn select_best_response<'a>(
        &self,
        items: impl Iterator<Item = &'a mime::Mime>,
    ) -> Option<(mime::Mime, &ResponseBody)> {
        items
            .filter_map(|mime_pattern| {
                self.body
                    .iter()
                    .filter_map(|resp_candidate| {
                        Some((
                            resp_candidate.content_type.as_str().parse().ok()?,
                            resp_candidate,
                        ))
                    })
                    .find(|(content_type, _resp_candidate)| {
                        is_mime_match(mime_pattern, &content_type)
                    })
            })
            .next()
    }

    fn invoke(
        &self,
        req: &Request<Body>,
        res: &mut Response<Body>,
        additional_data: HashMap<SmolStr, SmolStr>,
        facts: Arc<Mutex<HashMap<SmolStr, SmolStr>>>,
    ) -> Result<(), (Exception, HashMap<SmolStr, SmolStr>)> {
        *res = Response::new(Body::empty());

        let mut merged_data = self.data.clone();
        merged_data.extend(additional_data.into_iter());

        merged_data.insert("time".into(), Utc::now().to_string().into());

        for (k, v) in &self.headers {
            res.headers_mut().append(k, v.clone());
        }

        *res.status_mut() = self.status_code.clone();

        if self.body.is_empty() {
            // no body defined, just respond with the status code
            return Ok(());
        }

        let parsed_accept = req.headers().typed_get::<Accept>();

        let best_content_type = match (parsed_accept, self.fallback_to_accept.as_ref()) {
            (Ok(Some(accept)), _) => self.select_best_response(ordered_by_quality(&accept)),
            (_, Some(fallback)) => self.select_best_response(std::iter::once(fallback)),
            (Err(_), _) => {
                return Err((
                    Exception::from_str("static-response-error:bad-accept-header").unwrap(),
                    merged_data.clone(),
                ));
            }
            (Ok(None), _) => {
                return Err((
                    Exception::from_str("static-response-error:no-accept-header").unwrap(),
                    merged_data.clone(),
                ));
            }
        };

        match best_content_type {
            Some((resp_content_type, resp)) => {
                res.headers_mut()
                    .typed_insert::<ContentType>(&ContentType(resp_content_type.clone()));
                let body = match &resp.engine {
                    None => resp.content.to_string(),

                    Some(TemplateEngine::Handlebars) => {
                        let handlebars = Handlebars::new();

                        let rendering_data = json!({
                            "data": merged_data.clone(),
                            "facts": facts,
                        });

                        handlebars
                            .render_template(&resp.content, &rendering_data)
                            .map_err(|e| {
                                merged_data.insert("error".into(), e.to_string().into());
                                (
                                    Exception::from_str("static-response-error:render-error")
                                        .unwrap(),
                                    merged_data.into_iter().collect(),
                                )
                            })?
                    }
                };
                info!("body = {:?}", body);
                *res.body_mut() = Body::from(body);
            }
            None => {
                *res.status_mut() = StatusCode::NOT_ACCEPTABLE;
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum ResolvedCatchMatcher {
    StatusCode(StatusCodeRange),
    Exception(Exception),
}

#[derive(Debug)]
pub struct ResolvedRescueItem {
    catch: ResolvedCatchMatcher,
    handle: ResolvedCatchAction,
}

#[derive(Debug)]
struct ResolvedStatusCodeRangeHandler {
    status_codes_range: StatusCodeRange,
    catch: ResolvedCatchAction,
}

#[cfg(test)]
mod test {
    use super::*;
    use exogress_common::config_core::MatchPathSegment;

    #[test]
    fn test_matching() {
        let url: http::Uri = "https://a.b.c/".parse().unwrap();
        let url2: http::Uri = "https://a.b.c/a".parse().unwrap();
        let url3: http::Uri = "https://a.b.c/a/b".parse().unwrap();
        let matcher = ResolvedFilter {
            path: MatchingPath::LeftWildcard(vec![MatchPathSegment::Any]),
            method: Default::default(),
            trailing_slash: Default::default(),
            base_path: vec![],
        };

        assert!(!matcher.is_matches(&url, &Method::GET));
        assert!(matcher.is_matches(&url2, &Method::GET));
        assert!(matcher.is_matches(&url3, &Method::GET));
    }

    // #[test]
    // fn test_matching2() {
    //     let rules = vec![
    //         ResolvedFilter {path: MatchingPath::Root,
    //                 trailing_slash: Default::default(),
    //             },
    //             action: Action::Throw {
    //                 exception: "exception".parse().unwrap(),
    //                 data: Default::default(),
    //             },
    //         },
    //         Rule {
    //             filter: Filter {
    //                 path: MatchingPath::LeftWildcard(vec![MatchPathSegment::Exact(
    //                     "a".parse().unwrap(),
    //                 )]),
    //                 trailing_slash: Default::default(),
    //             },
    //             action: Action::Throw {
    //                 exception: "exception2".parse().unwrap(),
    //                 data: Default::default(),
    //             },
    //         },
    //         Rule {
    //             filter: Filter {
    //                 path: MatchingPath::WildcardRight(vec![MatchPathSegment::Exact(
    //                     "z".parse().unwrap(),
    //                 )]),
    //                 trailing_slash: Default::default(),
    //             },
    //             action: Action::Throw {
    //                 exception: "exception3".parse().unwrap(),
    //                 data: Default::default(),
    //             },
    //         },
    //         Rule {
    //             filter: Filter {
    //                 path: MatchingPath::LeftWildcardRight(
    //                     vec![MatchPathSegment::Exact("b".parse().unwrap())],
    //                     vec![MatchPathSegment::Exact("y".parse().unwrap())],
    //                 ),
    //                 trailing_slash: Default::default(),
    //             },
    //             action: Action::Throw {
    //                 exception: "exception4".parse().unwrap(),
    //                 data: Default::default(),
    //             },
    //         },
    //         Rule {
    //             filter: Filter {
    //                 path: MatchingPath::Strict(vec![
    //                     MatchPathSegment::Exact("c".parse().unwrap()),
    //                     MatchPathSegment::Exact("d".parse().unwrap()),
    //                 ]),
    //                 trailing_slash: Default::default(),
    //             },
    //             action: Action::Throw {
    //                 exception: "exception5".parse().unwrap(),
    //                 data: Default::default(),
    //             },
    //         },
    //         Rule {
    //             filter: Filter {
    //                 path: MatchingPath::Strict(vec![
    //                     MatchPathSegment::Any,
    //                     MatchPathSegment::Exact("e".parse().unwrap()),
    //                 ]),
    //                 trailing_slash: Default::default(),
    //             },
    //             action: Action::Throw {
    //                 exception: "exception6".parse().unwrap(),
    //                 data: Default::default(),
    //             },
    //         },
    //         Rule {
    //             filter: Filter {
    //                 path: MatchingPath::Strict(vec![
    //                     MatchPathSegment::Any,
    //                     MatchPathSegment::Regex("[0-9]{1}.{2}a".parse().unwrap()),
    //                 ]),
    //                 trailing_slash: Default::default(),
    //             },
    //             action: Action::Throw {
    //                 exception: "exception7".parse().unwrap(),
    //                 data: Default::default(),
    //             },
    //         },
    //     ];
    //
    //     let found = common_find_filter_rule(&rules, "http://asd/".parse().unwrap()).next();
    //     assert!(
    //         matches!(found, Some(Action::Throw { exception, .. }) if exception.to_string() == "exception")
    //     );
    //
    //     let found = common_find_filter_rule(&rules, "http://asd/a".parse().unwrap()).next();
    //     assert!(
    //         matches!(found, Some(Action::Throw { exception, .. }) if exception.to_string() == "exception2")
    //     );
    //     let found = common_find_filter_rule(&rules, "http://asd/a/b/c".parse().unwrap()).next();
    //     assert!(
    //         matches!(found, Some(Action::Throw { exception, .. }) if exception.to_string() == "exception2")
    //     );
    //     let found = common_find_filter_rule(&rules, "http://asd/1/2/z".parse().unwrap()).next();
    //     assert!(
    //         matches!(found, Some(Action::Throw { exception, .. }) if exception.to_string() == "exception3")
    //     );
    //     let found = common_find_filter_rule(&rules, "http://asd/z".parse().unwrap()).next();
    //     assert!(
    //         matches!(found, Some(Action::Throw { exception, .. }) if exception.to_string() == "exception3")
    //     );
    //     let found = common_find_filter_rule(&rules, "http://asd/b/1/2/3/y".parse().unwrap()).next();
    //     assert!(
    //         matches!(found, Some(Action::Throw { exception, .. }) if exception.to_string() == "exception4")
    //     );
    //     let found = common_find_filter_rule(&rules, "http://asd/b/y".parse().unwrap()).next();
    //     assert!(
    //         matches!(found, Some(Action::Throw { exception, .. }) if exception.to_string() == "exception4")
    //     );
    //     let not_found = common_find_filter_rule(&rules, "http://asd/b".parse().unwrap()).next();
    //     assert!(matches!(not_found, None));
    //
    //     let found = common_find_filter_rule(&rules, "http://asd/c/d".parse().unwrap()).next();
    //     assert!(
    //         matches!(found, Some(Action::Throw { exception, .. }) if exception.to_string() == "exception5")
    //     );
    //     let found = common_find_filter_rule(&rules, "http://asd/aasd/e".parse().unwrap()).next();
    //     assert!(
    //         matches!(found, Some(Action::Throw { exception, .. }) if exception.to_string() == "exception6")
    //     );
    //     let found =
    //         common_find_filter_rule(&rules, "http://asd/asdfsfdg/1hra".parse().unwrap()).next();
    //     assert!(
    //         matches!(found, Some(Action::Throw { exception, .. }) if exception.to_string() == "exception7")
    //     );
    //     let not_found =
    //         common_find_filter_rule(&rules, "http://asd/asdfsfdg/1hsra".parse().unwrap()).next();
    //     assert!(matches!(not_found, None));
    // }
    //
    // #[test]
    // fn test_wildcards() {
    //     let rules = vec![Rule {
    //         filter: Filter {
    //             path: MatchingPath::LeftWildcard(vec![MatchPathSegment::Any]),
    //             trailing_slash: Default::default(),
    //         },
    //         action: Action::Throw {
    //             exception: "exception8".parse().unwrap(),
    //             data: Default::default(),
    //         },
    //     }];
    //
    //     let found = common_find_filter_rule(
    //         &rules,
    //         "http://asd/hfa/asdf/asdf/asd/f/asdf".parse().unwrap(),
    //     )
    //     .next();
    //     assert!(
    //         matches!(found, Some(Action::Throw { exception, .. }) if exception.to_string() == "exception8")
    //     );
    //     let found = common_find_filter_rule(
    //         &rules,
    //         "http://asd/hfa/asdf/asdf/asd/f/asdf".parse().unwrap(),
    //     )
    //     .next();
    //     assert!(
    //         matches!(found, Some(Action::Throw { exception, .. }) if exception.to_string() == "exception8")
    //     );
    //
    //     let found = common_find_filter_rule(&rules, "http://asd/hfa/".parse().unwrap()).next();
    //     assert!(
    //         matches!(found, Some(Action::Throw { exception, .. }) if exception.to_string() == "exception8")
    //     );
    //
    //     let not_found = common_find_filter_rule(&rules, "http://asd/".parse().unwrap()).next();
    //     assert!(matches!(not_found, None));
    // }

    #[test]
    fn test_rebase_empty() {
        let rebase = Rebase {
            base_path: vec![],
            replace_base_path: vec![],
        };

        let url: http::Uri = "https://example.com/a/b".parse().unwrap();
        let rebased = Rebase::rebase_url(&Some(rebase), &url);

        assert_eq!(rebased, Some(url))
    }

    #[test]
    fn test_rebase_matching() {
        let rebase = Rebase {
            base_path: vec!["a".parse().unwrap()],
            replace_base_path: vec![],
        };

        let url: http::Uri = "https://example.com/a/b".parse().unwrap();
        let rebased = Rebase::rebase_url(&Some(rebase), &url);
        let expected: http::Uri = "https://example.com/b".parse().unwrap();

        assert_eq!(rebased, Some(expected))
    }

    #[test]
    fn test_rebase_match_and_replace() {
        let rebase = Rebase {
            base_path: vec!["a".parse().unwrap()],
            replace_base_path: vec!["c".parse().unwrap(), "d".parse().unwrap()],
        };

        let url: http::Uri = "https://example.com/a/b?f=2".parse().unwrap();
        let rebased = Rebase::rebase_url(&Some(rebase.clone()), &url);
        let expected: http::Uri = "https://example.com/c/d/b?f=2".parse().unwrap();

        assert_eq!(rebased, Some(expected));
    }
}
