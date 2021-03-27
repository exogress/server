use crate::{
    cache::{Cache, HandlerChecksum},
    clients::{
        traffic_counter::{RecordedTrafficStatistics, TrafficCounters},
        ClientTunnels,
    },
    http_serve::{
        auth::JwtEcdsa,
        requests_processor::modifications::{Replaced, ResolvedPathSegmentModify},
    },
    mime_helpers::{is_mime_match, ordered_by_quality},
    public_hyper_client::MeteredHttpsConnector,
    rules_counter::AccountCounters,
    webapp::{ConfigData, ConfigsResponse},
};
pub use auth::{ResolvedGithubAuthDefinition, ResolvedGoogleAuthDefinition};
use byte_unit::Byte;
use chrono::{DateTime, Utc};
use core::mem;
use exogress_common::{
    config_core::{
        self, is_profile_active, Action, CatchAction, CatchMatcher, ClientHandlerVariant,
        MatchPathSegment, MatchPathSingleSegment, MatchQuerySingleValue, MatchQueryValue,
        MatchingPath, MethodMatcher, ModifyHeaders, OnResponse, ResponseBody, StaticResponse,
        StatusCodeRange, TemplateEngine, TrailingSlashFilterRule, UrlPathSegment,
    },
    entities::{
        exceptions, exceptions::MODIFICATION_ERROR, AccountUniqueId, ConfigId, ConfigName,
        HandlerName, InstanceId, MountPointName, ProjectName, StaticResponseName,
    },
};
use exogress_server_common::{
    logging::{LogMessage, ProcessingStep, StaticResponseProcessingStep},
    presence,
};
use futures::{channel::mpsc, SinkExt, StreamExt};
use handlebars::Handlebars;
use hashbrown::HashMap;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use hyper::Body;
use itertools::Itertools;
use parking_lot::Mutex;
use serde_json::json;
use smol_str::SmolStr;
use sodiumoxide::crypto::secretstream::xchacha20poly1305;
use std::{
    collections::BTreeMap,
    convert::{TryFrom, TryInto},
    net::SocketAddr,
    time::Instant,
};
use tokio::io::AsyncWriteExt;
use trust_dns_resolver::TokioAsyncResolver;
use typed_headers::{Accept, ContentType, HeaderMapExt};
use url::Url;
use weighted_rs::{SmoothWeight, Weight};

#[macro_use]
mod macros;

// mod application_firewall;
mod auth;
mod gcs_bucket;
mod helpers;
mod modifications;
mod pass_through;
mod post_processing;
mod proxy;
pub mod refinable;
mod s3_bucket;
mod static_dir;

use crate::{
    dbip::LocationAndIsp,
    http_serve::{
        requests_processor::{
            modifications::substitute_str_with_filter_matches,
            pass_through::ResolvedPassThrough,
            post_processing::{ResolvedEncoding, ResolvedImage, ResolvedPostProcessing},
        },
        templates::render_limit_reached,
    },
};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use exogress_common::{
    common_utils::uri_ext::UriExt,
    config_core::{
        referenced,
        referenced::{Container, Parameter},
        refinable::RefinableSet,
        ClientConfigRevision, ModifyQuery, ModifyQueryStrategy, RedirectTo, RequestModifications,
        Scope, TrailingSlashModification,
    },
    entities::{
        serde::Serializer, url_prefix::MountPointBaseUrl, Exception, ParameterName, ProjectUniqueId,
    },
};
use exogress_server_common::logging::ExceptionProcessingStep;
use http::header::{
    HeaderName, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, LOCATION, RANGE,
    STRICT_TRANSPORT_SECURITY, USER_AGENT,
};
use langtag::LanguageTagBuf;
use linked_hash_map::LinkedHashMap;
use memmap::Mmap;
use mime::TEXT_HTML_UTF_8;
use regex::Regex;
use serde::{
    ser::{SerializeMap, SerializeSeq},
    Serialize,
};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;

pub struct RequestsProcessor {
    pub is_active: bool,
    ordered_handlers: Vec<ResolvedHandler>,
    pub generated_at: DateTime<Utc>,
    pub google_oauth2_client: super::auth::google::GoogleOauth2Client,
    pub github_oauth2_client: super::auth::github::GithubOauth2Client,
    pub assistant_base_url: Url,
    pub maybe_identity: Option<Vec<u8>>,
    strict_transport_security: Option<u64>,
    rules_counter: AccountCounters,
    pub account_unique_id: AccountUniqueId,
    pub project_unique_id: ProjectUniqueId,
    cache: Cache,
    pub project_name: ProjectName,
    url_prefix: MountPointBaseUrl,
    pub mount_point_name: MountPointName,
    pub xchacha20poly1305_secret_key: xchacha20poly1305::Key,
    max_pop_cache_size_bytes: Byte,
    gw_location: SmolStr,
    log_messages_tx: mpsc::Sender<LogMessage>,
    dbip: Option<Arc<maxminddb::Reader<Mmap>>>,
    webp_semaphore: Semaphore,
}

impl RequestsProcessor {
    async fn do_process(
        &self,
        req: &mut Request<Body>,
        res: &mut Response<Body>,
        requested_url: &http::uri::Uri,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        facts: Arc<Mutex<serde_json::Value>>,
        log_message: &mut LogMessage,
    ) {
        if let Some(db) = self.dbip.as_ref() {
            if let Ok(loc) = db.lookup::<LocationAndIsp>(remote_addr.ip()) {
                let mut location = json!({});

                if let Some(isp) = loc.isp {
                    location
                        .as_object_mut()
                        .unwrap()
                        .insert("isp".into(), isp.to_string().into());
                };
                if let Some(organization) = loc.organization {
                    location
                        .as_object_mut()
                        .unwrap()
                        .insert("organization".into(), organization.to_string().into());
                };
                if let Some(city) = loc.city.and_then(|c| c.names.and_then(|c| c.en)) {
                    location
                        .as_object_mut()
                        .unwrap()
                        .insert("city".into(), city.to_string().into());
                };
                if let Some(country) = loc.country.map(|c| c.iso_code).flatten() {
                    location
                        .as_object_mut()
                        .unwrap()
                        .insert("country".into(), country.to_string().into());
                };
                if let Some(geoip_location) = loc.location {
                    if let (Some(lat), Some(lon)) =
                        (geoip_location.latitude, geoip_location.longitude)
                    {
                        location
                            .as_object_mut()
                            .unwrap()
                            .insert("lat".into(), lat.into());
                        location
                            .as_object_mut()
                            .unwrap()
                            .insert("lon".into(), lon.into());
                    }
                };

                facts
                    .lock()
                    .as_object_mut()
                    .unwrap()
                    .insert("location".into(), location);
            }
        }
        facts
            .lock()
            .as_object_mut()
            .unwrap()
            .insert("mount_point_hostname".into(), self.url_prefix.host().into());

        self.rules_counter
            .register_request(&self.account_unique_id, &self.project_unique_id);

        let mut processed_by = None;
        let original_req_headers = req.headers().clone();
        for handler in &self.ordered_handlers {
            // restore original headers
            *req.headers_mut() = original_req_headers.clone();

            // create new response for each handler, avoid using dirty data from the previous handler
            *res = Response::new(Body::empty());

            let cached_response = tokio::time::timeout(
                Duration::from_millis(2000000),
                self.cache.serve_from_cache(&self, &handler, &req),
            )
            .await;

            match cached_response {
                Ok(Ok(Some(resp_from_cache))) => {
                    if resp_from_cache.status().is_success()
                        || resp_from_cache.status() == StatusCode::NOT_MODIFIED
                    {
                        // respond from the cache only if success response
                        *res = resp_from_cache;

                        res.headers_mut()
                            .insert("x-exg-edge-cached", "1".parse().unwrap());

                        if let Ok(Some(len)) =
                            res.headers().typed_get::<typed_headers::ContentLength>()
                        {
                            log_message.content_len = Some(len.0);
                        }

                        log_message.steps.push(ProcessingStep::ServedFromCache);

                        return;
                    }
                }
                Ok(Ok(None)) => {}
                Ok(Err(e)) => {
                    crate::statistics::CACHE_ERRORS
                        .with_label_values(&[crate::statistics::CACHE_ACTION_READ])
                        .inc();
                    warn!("Error reading data from cache: {}", e);
                }
                Err(_) => {
                    crate::statistics::CACHE_ERRORS
                        .with_label_values(&[crate::statistics::CACHE_ACTION_READ])
                        .inc();
                    warn!("Timeout trying to read from cache");
                }
            }

            if let Some(rebased_url) = Rebase::rebase_url(&handler.rebase, &requested_url) {
                let best_language = if let (Some(languages), Ok(Some(accept_languages))) = (
                    &handler.languages,
                    req.headers().typed_get::<typed_headers::AcceptLanguage>(),
                ) {
                    ordered_by_quality(&accept_languages)
                        .filter_map(|accepted| {
                            languages.iter().find(|supported_lang| {
                                if let Some(rest) =
                                    supported_lang.as_str().strip_prefix(accepted.as_str())
                                {
                                    if rest.is_empty() || rest.starts_with("-") {
                                        return true;
                                    }
                                }

                                false
                            })
                        })
                        .next()
                        .cloned()
                } else {
                    None
                };

                let result = handler
                    .handle_request(
                        req,
                        res,
                        requested_url,
                        &rebased_url,
                        local_addr,
                        remote_addr,
                        &best_language,
                        log_message,
                    )
                    .await;

                match result {
                    ResolvedHandlerProcessingResult::Processed => {
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
                let optimize_result = self
                    .optimize_image(
                        req,
                        res,
                        handler
                            .resolved_variant
                            .post_processing()
                            .map(|pp| &pp.image),
                        log_message,
                    )
                    .await;
                if let Err(e) = optimize_result {
                    warn!("Skipped image optimization due to the error: {}", e);
                }

                if let Err(e) = self.compress(
                    req,
                    res,
                    handler
                        .resolved_variant
                        .post_processing()
                        .map(|pp| &pp.encoding),
                    log_message,
                ) {
                    warn!("Error compressing: {}", e);
                }

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
        if self.is_active {
            let started_at = Instant::now();
            let facts = Arc::new(Mutex::new(json!({})));

            let mut log_message = LogMessage {
                gw_location: self.gw_location.clone(),
                project_unique_id: self.project_unique_id.clone(),
                date: Utc::now(),
                remote_addr: remote_addr.ip(),
                account_unique_id: self.account_unique_id.clone(),
                project: self.project_name.clone(),
                mount_point: self.mount_point_name.clone(),
                url: requested_url.to_string().into(),
                method: req.method().to_string().into(),
                protocol: format!("{:?}", req.version()).into(),
                user_agent: req
                    .headers()
                    .get(USER_AGENT)
                    .map(|v| v.to_str().unwrap_or_default().into()),
                status_code: None,
                time_taken: None,
                content_len: None,
                steps: vec![],
                facts: facts.clone(),
                str: None,
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

            log_message.set_message_string();

            self.log_messages_tx
                .clone()
                .send(log_message)
                .await
                .unwrap();
        } else {
            let body = render_limit_reached();
            {
                let headers = res.headers_mut();
                headers.insert(CONTENT_TYPE, TEXT_HTML_UTF_8.to_string().parse().unwrap());
                headers.insert(CONTENT_LENGTH, body.len().into());
                headers.insert("server", HeaderValue::from_static("exogress"));
            }
            *res.body_mut() = Body::from(body);
        }
    }

    fn save_to_cache(
        &self,
        req: &Request<Body>,
        res: &mut Response<Body>,
        handler: &ResolvedHandler,
    ) {
        info!("will try to save to cache");
        if handler.resolved_variant.is_cache_enabled() != Some(true) {
            info!("cache is not enabled");
            return;
        }

        if req.method() != &Method::GET && req.method() != &Method::HEAD {
            info!("bad method");
            return;
        };

        if !res.status().is_success() {
            info!("unsuccessful status");
            return;
        }

        if req.headers().get(RANGE).is_some() {
            info!("range set!");
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

        info!("caching_allowed = {:?}", caching_allowed);

        let max_age = cache_entries
            .iter()
            .filter_map(|header| header.strip_prefix("max-age="))
            .map(|h| Ok::<_, anyhow::Error>(chrono::Duration::seconds(h.parse()?)))
            .flatten()
            .next();

        info!("max_age = {:?}", max_age);

        if !caching_allowed || max_age.is_none() {
            info!("exit from cache");
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

            info!("save content to cache!");

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

            if let Err(e) = cached_response {
                crate::statistics::CACHE_ERRORS
                    .with_label_values(&[crate::statistics::CACHE_ACTION_WRITE])
                    .inc();
                error!("error saving to cache: {}", e);
            }

            Ok::<_, anyhow::Error>(())
        });

        *res.body_mut() = Body::wrap_stream(resp_rx.map(Ok::<_, hyper::Error>));
    }
}

#[derive(Clone, Debug)]
pub struct Rebase {
    base_path: Vec<UrlPathSegment>,
    replace_base_path: Vec<UrlPathSegment>,
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
                .take_while(|(a, b)| &AsRef::<str>::as_ref(a) == b)
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
pub enum ResolvedHandlerVariant {
    Proxy(proxy::ResolvedProxy),
    StaticDir(static_dir::ResolvedStaticDir),
    Auth(auth::ResolvedAuth),
    S3Bucket(s3_bucket::ResolvedS3Bucket),
    GcsBucket(gcs_bucket::ResolvedGcsBucket),
    // ApplicationFirewall(application_firewall::ResolvedApplicationFirewall),
    PassThrough(pass_through::ResolvedPassThrough),
}

impl ResolvedHandlerVariant {
    pub fn is_cache_enabled(&self) -> Option<bool> {
        match self {
            ResolvedHandlerVariant::Proxy(proxy) => Some(proxy.is_cache_enabled),
            ResolvedHandlerVariant::StaticDir(static_dir) => Some(static_dir.is_cache_enabled),
            ResolvedHandlerVariant::Auth(_) => None,
            ResolvedHandlerVariant::S3Bucket(s3) => Some(s3.is_cache_enabled),
            ResolvedHandlerVariant::GcsBucket(gcs) => Some(gcs.is_cache_enabled),
            // ResolvedHandlerVariant::ApplicationFirewall(_) => None,
            ResolvedHandlerVariant::PassThrough(_) => None,
        }
    }

    pub fn post_processing(&self) -> Option<&ResolvedPostProcessing> {
        match self {
            ResolvedHandlerVariant::Proxy(proxy) => Some(&proxy.post_processing),
            ResolvedHandlerVariant::StaticDir(static_dir) => Some(&static_dir.post_processing),
            ResolvedHandlerVariant::Auth(_) => None,
            ResolvedHandlerVariant::S3Bucket(s3) => Some(&s3.post_processing),
            ResolvedHandlerVariant::GcsBucket(gcs) => Some(&gcs.post_processing),
            // ResolvedHandlerVariant::ApplicationFirewall(_) => None,
            ResolvedHandlerVariant::PassThrough(_) => None,
        }
    }
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
        modified_url: &http::uri::Uri,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        language: &Option<LanguageTagBuf>,
        log_message: &mut LogMessage,
    ) -> HandlerInvocationResult {
        match self {
            ResolvedHandlerVariant::Proxy(proxy) => {
                proxy
                    .invoke(
                        req,
                        res,
                        requested_url,
                        modified_url,
                        local_addr,
                        remote_addr,
                        language,
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
                        modified_url,
                        local_addr,
                        remote_addr,
                        language,
                        log_message,
                    )
                    .await
            }
            ResolvedHandlerVariant::Auth(auth) => {
                auth.invoke(req, res, requested_url, language, log_message)
                    .await
            }
            ResolvedHandlerVariant::S3Bucket(s3_bucket) => {
                s3_bucket
                    .invoke(req, res, requested_url, modified_url, language, log_message)
                    .await
            }
            ResolvedHandlerVariant::GcsBucket(gcs_bucket) => {
                gcs_bucket
                    .invoke(req, res, requested_url, modified_url, language, log_message)
                    .await
            }
            // ResolvedHandlerVariant::ApplicationFirewall(application_firewall) => {
            //     application_firewall
            //         .invoke(req, res, requested_url, modified_url, language, log_message)
            //         .await
            // }
            ResolvedHandlerVariant::PassThrough(pass_through) => {
                pass_through
                    .invoke(req, res, requested_url, modified_url, log_message)
                    .await
            }
        }
    }
}

#[derive(Debug)]
enum ResolvedRuleAction {
    Invoke {
        rescue: Vec<ResolvedRescueItem>,
    },
    NextHandler,
    Throw {
        exception: Exception,
        data: HashMap<SmolStr, SmolStr>,
    },
    Respond(ResolvedStaticResponseAction),
}

impl ResolvedRuleAction {
    pub fn rescues(&self) -> Vec<ResolvedRescueItem> {
        match self {
            ResolvedRuleAction::Invoke { rescue } => rescue.clone(),
            ResolvedRuleAction::NextHandler => Default::default(),
            ResolvedRuleAction::Throw { .. } => Default::default(),
            ResolvedRuleAction::Respond(ResolvedStaticResponseAction { rescue, .. }) => {
                rescue.clone()
            }
        }
    }
}

#[derive(Debug, Clone)]
struct ResolvedStaticResponseAction {
    // static_response_name: StaticResponseName,
    pub static_response: Result<ResolvedStaticResponse, referenced::Error>,
    pub rescue: Vec<ResolvedRescueItem>,
}

impl ResolvedStaticResponseAction {
    fn handle_static_response(
        &self,
        handler: &ResolvedHandler,
        req: &Request<Body>,
        res: &mut Response<Body>,
        requested_url: &http::uri::Uri,
        additional_data: Option<&HashMap<SmolStr, SmolStr>>,
        matches: Option<&HashMap<SmolStr, Matched>>,
        is_in_exception: bool,
        language: &Option<LanguageTagBuf>,
        log_message: &mut LogMessage,
    ) -> ResolvedHandlerProcessingResult {
        let facts = log_message.facts.clone();

        *res = Response::new(Body::empty());

        match &self.static_response {
            Err(e) => {
                let mut data = additional_data.cloned().unwrap_or_default();

                data.insert(SmolStr::from("error"), SmolStr::from(e.to_string()));

                let rescueable = Rescueable::Exception {
                    exception: &*exceptions::STATIC_RESPONSE_NOT_DEFINED,
                    data: &data,
                };

                return handler.handle_rescueable(
                    req,
                    res,
                    requested_url,
                    &rescueable,
                    true,
                    &self.rescue,
                    &language,
                    log_message,
                );
            }
            Ok(static_response) => {
                let mut data = if let Some(d) = additional_data {
                    d.clone()
                } else {
                    Default::default()
                };
                for (k, v) in &static_response.data {
                    data.insert(k.clone(), v.clone());
                }

                log_message.steps.push(ProcessingStep::StaticResponse(
                    StaticResponseProcessingStep {
                        data: static_response.data.clone(),
                        config_name: handler.config_name.clone(),
                        language: language.clone(),
                    },
                ));

                match static_response.invoke(
                    req,
                    res,
                    requested_url,
                    data,
                    matches,
                    &language,
                    facts,
                ) {
                    Ok(()) => ResolvedHandlerProcessingResult::Processed,
                    Err((exception, data)) => {
                        *res = Response::new(Body::empty());
                        if !is_in_exception {
                            let rescueable = Rescueable::Exception {
                                exception: &exception,
                                data: &data,
                            };
                            error!("could not invoke static resp; call handle_rescueable. rescue handlers: {:?}", self.rescue);
                            handler.handle_rescueable(
                                req,
                                res,
                                requested_url,
                                &rescueable,
                                false,
                                &self.rescue,
                                &language,
                                log_message,
                            )
                        } else {
                            *res.body_mut() = Body::from("Internal server error");
                            *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;

                            ResolvedHandlerProcessingResult::Processed
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
enum ResolvedCatchAction {
    StaticResponse(ResolvedStaticResponseAction),
    Throw {
        exception: Exception,
        data: HashMap<SmolStr, SmolStr>,
        rescues: Vec<ResolvedRescueItem>,
    },
    NextHandler,
}

#[derive(Debug)]
pub struct ResolvedFilter {
    pub path: ResolvedMatchingPath,
    pub query_params: HashMap<SmolStr, Option<ResolvedMatchQueryValue>>,
    pub method: MethodMatcher,
    pub trailing_slash: TrailingSlashFilterRule,
    pub base_path_replacement: Vec<UrlPathSegment>,
}

#[derive(Debug)]
pub enum ResolvedMatchQueryValue {
    AnySingleSegment,
    MayBeAnyMultipleSegments,
    Exact(SmolStr),
    Regex(Box<Regex>),
    Choice(AhoCorasick),
}

impl From<MatchQueryValue> for ResolvedMatchQueryValue {
    fn from(segment: MatchQueryValue) -> Self {
        match segment {
            MatchQueryValue::Single(MatchQuerySingleValue::AnySingleSegment) => {
                ResolvedMatchQueryValue::AnySingleSegment
            }
            MatchQueryValue::Single(MatchQuerySingleValue::MayBeAnyMultipleSegments) => {
                ResolvedMatchQueryValue::MayBeAnyMultipleSegments
            }
            MatchQueryValue::Single(MatchQuerySingleValue::Exact(e)) => {
                ResolvedMatchQueryValue::Exact(e)
            }
            MatchQueryValue::Single(MatchQuerySingleValue::Regex(r)) => {
                ResolvedMatchQueryValue::Regex(r)
            }
            MatchQueryValue::Choice(variants) => {
                let aho_corasick = AhoCorasickBuilder::new()
                    .match_kind(MatchKind::LeftmostLongest)
                    .build(variants.iter().map(|s| s.as_str()));
                ResolvedMatchQueryValue::Choice(aho_corasick)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum ResolvedMatchingPath {
    // /
    Root,
    // *
    Wildcard,
    // A / B / C
    Strict(Vec<ResolvedMatchPathSegment>),
    // Left / * / Right
    LeftWildcardRight(Vec<ResolvedMatchPathSegment>, Vec<ResolvedMatchPathSegment>),
    // Left / *
    LeftWildcard(Vec<ResolvedMatchPathSegment>),
    // * / Right
    WildcardRight(Vec<ResolvedMatchPathSegment>),
}

impl From<MatchingPath> for ResolvedMatchingPath {
    fn from(matching_path: MatchingPath) -> Self {
        match matching_path {
            MatchingPath::Root => ResolvedMatchingPath::Root,
            MatchingPath::Wildcard => ResolvedMatchingPath::Wildcard,
            MatchingPath::Strict(s) => {
                ResolvedMatchingPath::Strict(s.into_iter().map(From::from).collect())
            }
            MatchingPath::LeftWildcardRight(l, r) => ResolvedMatchingPath::LeftWildcardRight(
                l.into_iter().map(From::from).collect(),
                r.into_iter().map(From::from).collect(),
            ),
            MatchingPath::LeftWildcard(l) => {
                ResolvedMatchingPath::LeftWildcard(l.into_iter().map(From::from).collect())
            }
            MatchingPath::WildcardRight(r) => {
                ResolvedMatchingPath::WildcardRight(r.into_iter().map(From::from).collect())
            }
        }
    }
}

impl From<MatchPathSegment> for ResolvedMatchPathSegment {
    fn from(segment: MatchPathSegment) -> Self {
        match segment {
            MatchPathSegment::Single(MatchPathSingleSegment::Any) => ResolvedMatchPathSegment::Any,
            MatchPathSegment::Single(MatchPathSingleSegment::Exact(e)) => {
                ResolvedMatchPathSegment::Exact(e)
            }
            MatchPathSegment::Single(MatchPathSingleSegment::Regex(r)) => {
                ResolvedMatchPathSegment::Regex(r)
            }
            MatchPathSegment::Choice(variants) => {
                let aho_corasick = AhoCorasickBuilder::new()
                    .match_kind(MatchKind::LeftmostLongest)
                    .build(variants);
                ResolvedMatchPathSegment::Choice(aho_corasick)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum ResolvedMatchPathSegment {
    Any,
    Exact(UrlPathSegment),
    Regex(Box<Regex>),
    Choice(AhoCorasick),
}

#[derive(Debug, Clone)]
pub enum Matched {
    Segments(Vec<SmolStr>),
    Multiple(BTreeMap<u8, SmolStr>),
    Single(SmolStr),
    None,
}

impl Serialize for Matched {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        match self {
            Matched::Segments(s) => {
                let mut seq = serializer.serialize_seq(Some(s.len()))?;
                for item in s.iter() {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Matched::Multiple(multiple) => {
                let mut seq = serializer.serialize_map(Some(multiple.len()))?;
                for (idx, item) in multiple.iter() {
                    seq.serialize_entry(idx, item)?;
                }
                seq.end()
            }
            Matched::Single(s) => serializer.serialize_str(s),
            Matched::None => serializer.serialize_none(),
        }
    }
}

impl Matched {
    fn is_empty(&self) -> bool {
        match self {
            Matched::Multiple(m) if m.is_empty() => true,
            Matched::None => true,
            Matched::Segments(s) if s.is_empty() => true,
            _ => false,
        }
    }
}

impl ResolvedMatchPathSegment {
    pub fn matches(&self, s: &str) -> Option<Matched> {
        match self {
            ResolvedMatchPathSegment::Any => Some(Matched::Single(s.into())),
            ResolvedMatchPathSegment::Exact(segment) if s == AsRef::<str>::as_ref(segment) => {
                // no need to return exact segment
                Some(Matched::None)
            }
            ResolvedMatchPathSegment::Regex(re) => {
                let mut h = BTreeMap::new();

                let captures = re.captures(s)?;

                for (idx, maybe_match) in captures.iter().enumerate() {
                    if let Some(m) = maybe_match {
                        h.insert(idx.try_into().unwrap(), m.as_str().into());
                    }
                }

                Some(Matched::Multiple(h))
            }
            ResolvedMatchPathSegment::Choice(aho_corasick) => {
                if let Some(res) = aho_corasick.find(&s) {
                    if (res.end() - res.start()) == s.len() {
                        Some(Matched::Single(s.into()))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

impl ResolvedFilter {
    fn query_match(
        &self,
        query_pairs: LinkedHashMap<SmolStr, SmolStr>,
    ) -> Option<HashMap<SmolStr, Matched>> {
        let mut h = HashMap::new();
        for (expected_key, maybe_expected_val) in &self.query_params {
            match maybe_expected_val {
                Some(expected_val) => match query_pairs.get(expected_key) {
                    Some(provided_val) => match expected_val {
                        ResolvedMatchQueryValue::AnySingleSegment => {
                            if provided_val.is_empty() || provided_val.contains('/') {
                                return None;
                            } else {
                                h.insert(
                                    expected_key.clone(),
                                    Matched::Single(provided_val.clone()),
                                );
                            }
                        }
                        ResolvedMatchQueryValue::MayBeAnyMultipleSegments => {
                            if provided_val.is_empty() {
                                return None;
                            } else {
                                h.insert(
                                    expected_key.clone(),
                                    Matched::Segments(
                                        provided_val
                                            .split('/')
                                            .filter(|s| !s.is_empty())
                                            .map(|s| s.into())
                                            .collect(),
                                    ),
                                );
                            }
                        }
                        ResolvedMatchQueryValue::Exact(exact) => {
                            if exact != provided_val {
                                return None;
                            }
                        }
                        ResolvedMatchQueryValue::Regex(regex) => {
                            let captures = regex.captures(provided_val)?;

                            let mut inner = BTreeMap::new();

                            for (idx, maybe_match) in captures.iter().enumerate() {
                                if let Some(m) = maybe_match {
                                    inner.insert(idx.try_into().unwrap(), m.as_str().into());
                                }
                            }

                            h.insert(expected_key.clone(), Matched::Multiple(inner));
                        }
                        ResolvedMatchQueryValue::Choice(aho_corasick) => {
                            if let Some(res) = aho_corasick.find(provided_val.as_str()) {
                                if (res.end() - res.start()) != provided_val.len() {
                                    return None;
                                } else {
                                    h.insert(
                                        expected_key.clone(),
                                        Matched::Single(provided_val.clone()),
                                    );
                                }
                            } else {
                                return None;
                            }
                        }
                    },
                    None => {
                        return None;
                    }
                },
                None => {}
            }
        }

        Some(h)
    }

    /// Return match map and number of replaced segments (not suitable for modifications)
    fn matches(
        &self,
        url: &http::Uri,
        method: &http::Method,
    ) -> Option<(HashMap<SmolStr, Matched>, usize)> {
        let is_trailing_slash = url.path().ends_with("/");

        if !self.method.is_match(method) {
            return None;
        }

        let req_query_pairs: LinkedHashMap<SmolStr, SmolStr> = url
            .to_url()
            .query_pairs()
            .map(|(k, v)| (SmolStr::from(k), SmolStr::from(v)))
            .collect();

        let query_matches = self.query_match(req_query_pairs)?;

        let mut segments = vec![];
        {
            let mut path_segments = url.path_segments().into_iter();
            let mut base_segments = self.base_path_replacement.iter();

            while let Some(expected_base_segment) = base_segments.next() {
                if let Some(segment) = path_segments.next() {
                    if segment != expected_base_segment.as_str() {
                        return None;
                    }
                } else {
                    return None;
                }
            }

            while let Some(segment) = path_segments.next() {
                if !segment.is_empty() {
                    segments.push(SmolStr::from(segment.to_string()));
                }
            }
        }

        let matcher = || -> Option<HashMap<SmolStr, Matched>> {
            let mut matches = HashMap::new();

            match &self.path {
                ResolvedMatchingPath::Root
                    if segments.len() == 0 || (segments.len() == 1 && segments[0].is_empty()) => {}
                ResolvedMatchingPath::Wildcard => {
                    matches.insert(
                        "0".to_string().into(),
                        Matched::Segments(segments.iter().cloned().collect()),
                    );
                }
                ResolvedMatchingPath::Strict(match_segments) => {
                    if match_segments.len() != segments.len() {
                        return None;
                    }
                    for (idx, (match_segment, segment)) in
                        match_segments.iter().zip(&segments).enumerate()
                    {
                        let inner = match_segment.matches(segment)?;
                        if !inner.is_empty() {
                            matches.insert(idx.to_string().into(), inner);
                        }
                    }
                }
                ResolvedMatchingPath::LeftWildcardRight(
                    left_match_segments,
                    right_match_segments,
                ) => {
                    if left_match_segments.len() + right_match_segments.len() > segments.len() {
                        return None;
                    }
                    let mut num = 0;
                    for (idx, (match_segment, segment)) in
                        left_match_segments.iter().zip(&segments).enumerate()
                    {
                        let inner = match_segment.matches(segment)?;
                        if !inner.is_empty() {
                            matches.insert(idx.to_string().into(), inner);
                        }
                        num += 1;
                    }

                    let left_ends = num;

                    let segments_len = segments.len();
                    let mut num = segments_len;

                    for (match_segment, segment) in
                        right_match_segments.iter().rev().zip(segments.iter().rev())
                    {
                        num -= 1;
                        let inner = match_segment.matches(segment)?;
                        if !inner.is_empty() {
                            matches.insert(num.to_string().into(), inner);
                        }
                    }

                    let wildcard_part = &segments[left_ends..num];

                    if !wildcard_part.is_empty() {
                        matches.insert(
                            left_ends.to_string().into(),
                            Matched::Segments(wildcard_part.iter().cloned().collect()),
                        );
                    }
                }
                ResolvedMatchingPath::LeftWildcard(left_match_segments) => {
                    if left_match_segments.len() > segments.len() {
                        return None;
                    }
                    let mut num = 0;

                    for (idx, (match_segment, segment)) in
                        left_match_segments.iter().zip(&segments).enumerate()
                    {
                        let inner = match_segment.matches(segment)?;
                        if !inner.is_empty() {
                            matches.insert(idx.to_string().into(), inner);
                        }
                        num += 1;
                    }

                    let wildcard_part = &segments[num..];

                    if !wildcard_part.is_empty() {
                        matches.insert(
                            num.to_string().into(),
                            Matched::Segments(wildcard_part.iter().cloned().collect()),
                        );
                    }
                }
                ResolvedMatchingPath::WildcardRight(right_match_segments) => {
                    let segments_len = segments.len();
                    if right_match_segments.len() > segments_len {
                        return None;
                    }

                    let mut num = segments_len;
                    for (match_segment, segment) in
                        right_match_segments.iter().rev().zip(segments.iter().rev())
                    {
                        num -= 1;
                        let inner = match_segment.matches(segment)?;

                        if !inner.is_empty() {
                            matches.insert(num.to_string().into(), inner);
                        }
                    }

                    let wildcard_part = &segments[..num];

                    if !wildcard_part.is_empty() {
                        matches.insert(
                            0.to_string().into(),
                            Matched::Segments(wildcard_part.iter().cloned().collect()),
                        );
                    }
                }
                _ => return None,
            }

            Some(matches)
        };

        let path_match = (matcher)()?;

        match self.trailing_slash {
            TrailingSlashFilterRule::Require if is_trailing_slash == false => {
                return None;
            }
            TrailingSlashFilterRule::Deny if is_trailing_slash == true => {
                return None;
            }
            _ => {}
        };

        let mut matches = path_match;
        matches.extend(query_matches.into_iter());

        Some((matches, self.base_path_replacement.len()))
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
    request_modifications: ResolvedRequestModifications,
    on_response: Vec<OnResponse>,
    action: ResolvedRuleAction,
}

#[derive(Debug, Clone, Default)]
pub struct ResolvedModifyQuery(ModifyQuery);

impl ResolvedModifyQuery {
    pub(crate) fn add_query(
        &self,
        uri: &mut http::Uri,
        initial_query_params: &LinkedHashMap<String, String>,
        filter_matchers: &HashMap<SmolStr, Matched>,
    ) -> anyhow::Result<()> {
        let mut params = match &self.0.strategy {
            ModifyQueryStrategy::Keep { remove } => {
                let mut query_params = initial_query_params.clone();
                for to_remove in remove {
                    query_params.remove(to_remove.as_str());
                }
                query_params
            }
            ModifyQueryStrategy::Remove { keep } => {
                let mut query_params: LinkedHashMap<String, String> = Default::default();
                for to_keep in keep {
                    if let Some(value) = initial_query_params.get(to_keep.as_str()) {
                        query_params.insert(
                            to_keep.to_string(),
                            substitute_str_with_filter_matches(value, filter_matchers)?.to_string(),
                        );
                    }
                }
                query_params
            }
        };

        for (param, value) in self.0.set.iter() {
            params.insert(
                param.to_string(),
                substitute_str_with_filter_matches(value, filter_matchers)?.to_string(),
            );
        }

        uri.set_query(params);

        Ok(())
    }
}

impl From<ModifyQuery> for ResolvedModifyQuery {
    fn from(q: ModifyQuery) -> Self {
        ResolvedModifyQuery(q)
    }
}

#[derive(Debug, Clone, Default)]
pub struct ResolvedRequestModifications {
    headers: ModifyHeaders,
    path: Option<Vec<ResolvedPathSegmentModify>>,
    trailing_slash: TrailingSlashModification,
    modify_query: ResolvedModifyQuery,
}

impl ResolvedRule {
    fn get_action(
        &self,
        rebased_url: &http::uri::Uri,
        method: &http::Method,
    ) -> Option<(
        HashMap<SmolStr, Matched>,
        usize,
        &ResolvedRuleAction,
        &ResolvedRequestModifications,
        &Vec<OnResponse>,
    )> {
        let (matches, replaced_base_path_len) = self.filter.matches(rebased_url, method)?;

        Some((
            matches,
            replaced_base_path_len,
            &self.action,
            &self.request_modifications,
            &self.on_response,
        ))
    }
}

pub struct ResolvedHandler {
    pub(crate) handler_name: HandlerName,
    pub(crate) handler_checksum: HandlerChecksum,

    config_name: Option<ConfigName>,

    pub(crate) resolved_variant: ResolvedHandlerVariant,

    rebase: Option<Rebase>,

    priority: u16,

    catches: Vec<ResolvedRescueItem>,

    resolved_rules: Vec<ResolvedRule>,

    account_unique_id: AccountUniqueId,
    project_unique_id: ProjectUniqueId,
    rules_counter: AccountCounters,

    languages: Option<Vec<langtag::LanguageTagBuf>>,
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
    fn data(&'a self) -> Option<&'a HashMap<SmolStr, SmolStr>> {
        match self {
            Rescueable::Exception { data, .. } => Some(data),
            Rescueable::StatusCode(_) => None,
        }
    }
}

#[must_use]
#[derive(Debug)]
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
        rescues: &Vec<ResolvedRescueItem>,
        rescueable: &Rescueable<'_>,
    ) -> Option<ResolvedCatchAction> {
        for rescue_item in rescues.iter() {
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
        requested_url: &http::uri::Uri,
        rescueable: &Rescueable<'_>,
        is_in_exception: bool,
        rescues: &Vec<ResolvedRescueItem>,
        language: &Option<LanguageTagBuf>,
        log_message: &mut LogMessage,
    ) -> ResolvedHandlerProcessingResult {
        if let &Rescueable::Exception { exception, data } = rescueable {
            log_message
                .steps
                .push(ProcessingStep::Exception(ExceptionProcessingStep {
                    exception: exception.clone(),
                    data: data.clone(),
                }));
        }

        let mut maybe_resolved_exception = Self::find_exception_handler(rescues, &rescueable);
        let mut collected_data: HashMap<SmolStr, SmolStr> = if let Some(d) = rescueable.data() {
            d.clone()
        } else {
            Default::default()
        };

        let result = loop {
            match maybe_resolved_exception {
                None => match rescueable {
                    &Rescueable::Exception { exception, data } => {
                        collected_data.extend(data.iter().map(|(a, b)| (a.clone(), b.clone())));
                        break RescueableHandleResult::UnhandledException {
                            exception_name: exception.clone(),
                            data: collected_data.clone(),
                        };
                    }
                    Rescueable::StatusCode(_) => break RescueableHandleResult::FinishProcessing,
                },
                Some(ResolvedCatchAction::Throw {
                    exception,
                    data: rethrow_data,
                    rescues,
                }) => {
                    collected_data.extend(rethrow_data.iter().map(|(a, b)| (a.clone(), b.clone())));

                    let rethrow = Rescueable::Exception {
                        exception: &exception,
                        data: &collected_data,
                    };
                    maybe_resolved_exception = Self::find_exception_handler(&rescues, &rethrow);

                    match maybe_resolved_exception {
                        Some(_) => {
                            continue;
                        }
                        None => match &rescueable {
                            Rescueable::Exception { .. } => {
                                break RescueableHandleResult::UnhandledException {
                                    exception_name: exception.clone(),
                                    data: collected_data.clone(),
                                };
                            }
                            Rescueable::StatusCode(_) => {
                                break RescueableHandleResult::FinishProcessing
                            }
                        },
                    }
                }
                Some(ResolvedCatchAction::StaticResponse(ResolvedStaticResponseAction {
                    static_response,
                    rescue,
                })) => {
                    if let Ok(resp) = &static_response {
                        collected_data
                            .extend(resp.data.iter().map(|(a, b)| (a.clone(), b.clone())));
                    }

                    // FIXME: this will probably break data merging if static-resp is innvolvedd
                    // FIXME: merged data shouldd be store to the cotaiier, so that onn exception nnew exception queue is processed
                    break RescueableHandleResult::StaticResponse(ResolvedStaticResponseAction {
                        static_response: static_response.clone(),
                        rescue,
                    });
                }
                Some(ResolvedCatchAction::NextHandler) => {
                    break RescueableHandleResult::NextHandler
                }
            }
        };

        match result {
            RescueableHandleResult::StaticResponse(action) => action.handle_static_response(
                self,
                req,
                res,
                requested_url,
                Some(&collected_data),
                None,
                is_in_exception,
                &language,
                log_message,
            ),
            RescueableHandleResult::NextHandler => ResolvedHandlerProcessingResult::NextHandler,
            RescueableHandleResult::UnhandledException { .. } => {
                self.respond_server_error(res);
                ResolvedHandlerProcessingResult::Processed
            }
            RescueableHandleResult::FinishProcessing => ResolvedHandlerProcessingResult::Processed,
        }
    }

    /// Find appropriate final action, which should be executed
    fn find_action(
        &self,
        rebased_url: &http::uri::Uri,
        method: &http::Method,
    ) -> Option<(
        HashMap<SmolStr, Matched>,
        usize,
        &ResolvedRuleAction,
        &ResolvedRequestModifications,
        &Vec<OnResponse>,
    )> {
        self.resolved_rules
            .iter()
            .filter_map(|resolved_rule| resolved_rule.get_action(rebased_url, method))
            .inspect(|_| {
                self.rules_counter
                    .register_rule(&self.account_unique_id, &self.project_unique_id);
            })
            .next()
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
        language: &Option<LanguageTagBuf>,
        log_message: &mut LogMessage,
    ) -> ResolvedHandlerProcessingResult {
        let (filter_matches, skip_segments, action, request_modification, response_modification) =
            match self.find_action(rebased_url, req.method()) {
                None => return ResolvedHandlerProcessingResult::FiltersNotMatched,
                Some(action) => action,
            };

        let query_modifications = rebased_url.query_pairs();
        let mut modified_url = rebased_url.clone();

        modified_url.clear_query();
        if let Some(path_modify) = &request_modification.path {
            modified_url.clear_segments();

            for replaced_segment in rebased_url.path_segments().iter().take(skip_segments) {
                modified_url.push_segment(replaced_segment);
            }

            for segment in path_modify.iter() {
                let replaced = segment.substitute(&filter_matches).expect("FIXME");
                match replaced {
                    Replaced::Multiple(multiple) => {
                        for s in multiple {
                            modified_url.push_segment(&s);
                        }
                    }
                    Replaced::Single(single) => {
                        modified_url.push_segment(&single);
                    }
                }
            }
        }

        match request_modification.trailing_slash {
            TrailingSlashModification::Keep => {
                modified_url.ensure_trailing_slash(requested_url.path().ends_with("/"));
            }
            TrailingSlashModification::Set => modified_url.ensure_trailing_slash(true),
            TrailingSlashModification::Unset => modified_url.ensure_trailing_slash(false),
        }

        match apply_headers(
            req.headers_mut(),
            &request_modification.headers,
            &filter_matches,
        ) {
            Ok(()) => {}
            Err(ex) => {
                let rescueable = Rescueable::Exception {
                    exception: &ex,
                    data: &Default::default(),
                };
                return self.handle_rescueable(
                    req,
                    res,
                    requested_url,
                    &rescueable,
                    false,
                    &action.rescues(),
                    &language,
                    log_message,
                );
            }
        }

        match request_modification.modify_query.add_query(
            &mut modified_url,
            &query_modifications,
            &filter_matches,
        ) {
            Ok(()) => {}
            Err(ex) => {
                let mut data: HashMap<SmolStr, SmolStr> = Default::default();
                data.insert("error".into(), ex.to_string().into());

                let rescueable = Rescueable::Exception {
                    exception: &*MODIFICATION_ERROR,
                    data: &data,
                };
                return self.handle_rescueable(
                    req,
                    res,
                    requested_url,
                    &rescueable,
                    false,
                    &action.rescues(),
                    &language,
                    log_message,
                );
            }
        }

        match action {
            ResolvedRuleAction::Invoke { rescue } => {
                let invocation_result = self
                    .resolved_variant
                    .invoke(
                        req,
                        res,
                        requested_url,
                        &modified_url,
                        local_addr,
                        remote_addr,
                        language,
                        log_message,
                    )
                    .await;

                match invocation_result {
                    HandlerInvocationResult::Responded => {
                        for modification in response_modification {
                            if modification.when.status_code.is_belongs(&res.status()) {
                                match apply_headers(
                                    res.headers_mut(),
                                    &modification.modifications.headers,
                                    &filter_matches,
                                ) {
                                    Ok(_) => {}
                                    Err(ex) => {
                                        let rescueable = Rescueable::Exception {
                                            exception: &ex,
                                            data: &Default::default(),
                                        };

                                        return self.handle_rescueable(
                                            req,
                                            res,
                                            requested_url,
                                            &rescueable,
                                            false,
                                            rescue,
                                            &language,
                                            log_message,
                                        );
                                    }
                                }
                            }
                        }

                        let rescueable = Rescueable::StatusCode(res.status());

                        self.handle_rescueable(
                            req,
                            res,
                            requested_url,
                            &rescueable,
                            false,
                            rescue,
                            &language,
                            log_message,
                        )
                    }
                    HandlerInvocationResult::ToNextHandler => {
                        ResolvedHandlerProcessingResult::NextHandler
                    }
                    HandlerInvocationResult::Exception { name, data } => {
                        let rescueable = Rescueable::Exception {
                            exception: &name,
                            data: &data,
                        };
                        self.handle_rescueable(
                            req,
                            res,
                            requested_url,
                            &rescueable,
                            false,
                            &rescue,
                            &language,
                            log_message,
                        )
                    }
                }
            }
            ResolvedRuleAction::NextHandler => {
                return ResolvedHandlerProcessingResult::NextHandler;
            }
            ResolvedRuleAction::Throw { exception, data } => {
                let rescueable = Rescueable::Exception { exception, data };
                return self.handle_rescueable(
                    req,
                    res,
                    requested_url,
                    &rescueable,
                    false,
                    &self.catches,
                    &language,
                    log_message,
                );
            }
            ResolvedRuleAction::Respond(action) => {
                return action.handle_static_response(
                    self,
                    req,
                    res,
                    requested_url,
                    None,
                    Some(&filter_matches),
                    false,
                    &language,
                    log_message,
                );
            }
        }
    }
}

fn apply_headers(
    headers: &mut HeaderMap<HeaderValue>,
    modification: &ModifyHeaders,
    filter_matches: &HashMap<SmolStr, Matched>,
) -> Result<(), Exception> {
    for (header_name, header_value) in &modification.append.0 {
        let substituted =
            substitute_str_with_filter_matches(header_value.to_str().unwrap(), filter_matches)
                .map_err(|_e| MODIFICATION_ERROR.clone())?;

        headers.append(
            header_name.clone(),
            substituted.to_string().parse().unwrap(),
        );
    }
    for (header_name, header_value) in &modification.insert.0 {
        let substituted =
            substitute_str_with_filter_matches(header_value.to_str().unwrap(), filter_matches)
                .map_err(|_e| MODIFICATION_ERROR.clone())?;

        headers.insert(
            header_name.clone(),
            substituted.to_string().parse().unwrap(),
        );
    }
    for header_name in &modification.remove.0 {
        headers.remove(header_name);
    }

    Ok(())
}

#[derive(Debug)]
#[must_use]
enum RescueableHandleResult {
    /// Respond with static response
    StaticResponse(ResolvedStaticResponseAction),
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
    static_response_container: Container<StaticResponse, StaticResponseName>,
    status_code: &Option<exogress_common::config_core::StatusCode>,
    data: &BTreeMap<SmolStr, SmolStr>,
    params: &HashMap<ParameterName, Parameter>,
    refined: &RefinableSet,
    scope: &Scope,
) -> Result<ResolvedStaticResponse, referenced::Error> {
    let static_response = static_response_container.resolve(params, refined, scope)?;

    let static_response_status_code = match &static_response {
        StaticResponse::Redirect(redirect) => redirect.redirect_type.status_code(),
        StaticResponse::Raw(raw) => raw.status_code,
    };

    let fallback_to_accept = match &static_response {
        StaticResponse::Redirect(_) => None,
        StaticResponse::Raw(raw) => raw.fallback_accept.clone().map(|r| r.0),
    };

    let resolved = ResolvedStaticResponse {
        status_code: status_code
            .as_ref()
            .map(|s| s.0)
            .unwrap_or(static_response_status_code.0),
        fallback_to_accept,
        body: match &static_response {
            StaticResponse::Raw(raw) => (&raw.body).clone(),
            StaticResponse::Redirect(_) => {
                vec![]
            }
        },
        headers: match &static_response {
            StaticResponse::Raw(raw) => raw.headers.0.clone(),
            StaticResponse::Redirect(redirect) => redirect.headers.0.clone(),
        },
        data: data
            .iter()
            .map(|(k, v)| (k.as_str().into(), v.as_str().into()))
            .collect(),

        maybe_redirect: match &static_response {
            StaticResponse::Redirect(redirect) => Some(ResolvedRedirectResponse {
                location: match &redirect.destination {
                    RedirectTo::Root => ResolvedModifieableRedirectTo::Root,
                    RedirectTo::AbsoluteUrl(url) => {
                        ResolvedModifieableRedirectTo::AbsoluteUrl(url.clone())
                    }
                    RedirectTo::WithBaseUrl(base, segments) => {
                        ResolvedModifieableRedirectTo::WithBaseUrl(
                            base.clone(),
                            segments
                                .iter()
                                .map(|s| ResolvedPathSegmentModify(s.0.clone()))
                                .collect(),
                        )
                    }
                    RedirectTo::Segments(segments) => ResolvedModifieableRedirectTo::Segments(
                        segments
                            .iter()
                            .map(|s| ResolvedPathSegmentModify(s.0.clone()))
                            .collect(),
                    ),
                },
                query_modify: redirect.query_params.clone().into(),
            }),
            StaticResponse::Raw(_) => None,
        },
    };

    Ok(resolved)
}

fn resolve_catch_action(
    client_config_info: &Option<(ConfigName, ClientConfigRevision)>,
    params: &HashMap<ParameterName, Parameter>,
    catch_action: &CatchAction,
    refinable_set: &RefinableSet,
    scope: &Scope,
) -> Option<ResolvedCatchAction> {
    Some(match catch_action {
        CatchAction::StaticResponse {
            static_response,
            status_code,
            data,
        } => ResolvedCatchAction::StaticResponse(ResolvedStaticResponseAction {
            static_response: resolve_static_response(
                static_response.clone(),
                status_code,
                data,
                params,
                refinable_set,
                scope,
            ),
            rescue: if let Some(prev_scope) = scope.prev(client_config_info) {
                resolve_rescue_items(client_config_info, &params, &refinable_set, &prev_scope)?
            } else {
                Default::default()
            },
        }),
        CatchAction::Throw { exception, data } => ResolvedCatchAction::Throw {
            exception: exception.clone(),
            data: data.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            rescues: if let Some(prev_scope) = scope.prev(client_config_info) {
                resolve_rescue_items(client_config_info, &params, &refinable_set, &prev_scope)?
            } else {
                Default::default()
            },
        },
        CatchAction::NextHandler => ResolvedCatchAction::NextHandler,
    })
}

fn resolve_rescue_items(
    client_config_info: &Option<(ConfigName, ClientConfigRevision)>,
    params: &HashMap<ParameterName, Parameter>,
    refinable_set: &RefinableSet,
    scope: &Scope,
) -> Option<Vec<ResolvedRescueItem>> {
    let available_exception_handlers = refinable_set.joined_for_scope(scope);

    available_exception_handlers
        .rescue
        .iter()
        .map(|(rescue_item, _)| {
            Some(ResolvedRescueItem {
                catch: match &rescue_item.catch {
                    CatchMatcher::StatusCode(status_code) => {
                        ResolvedCatchMatcher::StatusCode(status_code.clone())
                    }
                    CatchMatcher::Exception(exception) => {
                        ResolvedCatchMatcher::Exception(exception.clone())
                    }
                },
                handle: resolve_catch_action(
                    client_config_info,
                    params,
                    &rescue_item.handle,
                    refinable_set,
                    scope,
                )?,
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
        public_counters_tx: mpsc::Sender<RecordedTrafficStatistics>,
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
        let traffic_counters = TrafficCounters::new(
            resp.account_unique_id.clone(),
            resp.project_unique_id.clone(),
        );

        let refinable = Arc::new(resp.refinable());

        let grouped = resp.configs.iter().group_by(|item| &item.config_name);

        let project_rescue = resp.project_config.refinable.rescue;
        let jwt_ecdsa = JwtEcdsa {
            private_key: resp.jwt_ecdsa.private_key.into(),
            public_key: resp.jwt_ecdsa.public_key.into(),
        };

        let mount_point_base_url = resp.url_prefix;
        let account_unique_id = resp.account_unique_id;
        let project_unique_id = resp.project_unique_id;
        let account_name = resp.account;
        let project_name = resp.project;
        let params = resp.params.clone();

        let project_mount_points = resp
            .project_config
            .mount_points
            .into_iter()
            .map(|(k, v)| (k, (None, None, None, None, None, v.into())));

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
                let config_revision = &entry.revision;
                let instance_ids = entry.instance_ids.clone();
                let active_profile = entry.active_profile.clone();

                let upstreams = &config.upstreams;

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
                                Some(config_revision.clone()),
                                Some(upstreams.clone()),
                                Some(instance_ids.clone()),
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

        let mount_point_name = grouped_mount_points
            .iter()
            .next()
            .ok_or_else(|| anyhow!("no mount points returned"))?
            .0
            .clone();

        // let project_static_responses = resp.project_config.refinable.static_responses.clone();
        //
        let mut merged_resolved_handlers = vec![];

        for (
            _mp_name,
            (config_name, config_revision, upstreams, instance_ids, active_profile, mp),
        ) in grouped_mount_points.into_iter()
        {
            shadow_clone!(
                instance_ids,
                project_rescue,
                jwt_ecdsa,
                mount_point_base_url,
                google_oauth2_client,
                github_oauth2_client,
                assistant_base_url,
                maybe_identity,
                client_tunnels,
                individual_hostname,
                account_name,
                account_unique_id,
                project_unique_id,
                project_name,
                rules_counter,
                resolver,
                traffic_counters,
                presence_client,
                params,
                active_profile
            );

            let public_client = hyper::Client::builder().build::<_, Body>(MeteredHttpsConnector {
                public_counters_tx: public_counters_tx.clone(),
                resolver: resolver.clone(),
                counters: traffic_counters.clone(),
                sent_counter: crate::statistics::PUBLIC_ENDPOINT_BYTES_SENT.clone(),
                recv_counter: crate::statistics::PUBLIC_ENDPOINT_BYTES_RECV.clone(),
            });

            let client_config_info = config_name.clone().zip(config_revision.clone());

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
                    shadow_clone!(active_profile, mount_point_name, refinable);

                    move |(handler_name, handler)| {
                        let replace_base_path = handler
                            .variant
                            .rebase()
                            .map(|r| r.replace_base_path.clone())
                            .unwrap_or_default();

                        let handler_scope = Scope::handler(
                            config_name.clone().zip(config_revision.clone()),
                            &mount_point_name,
                            &handler_name,
                        );

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
                                        github: auth.github.map(|github| ResolvedGithubAuthDefinition {
                                            acl: github.acl.resolve_non_referenced(
                                                &params,
                                            )
                                        }),
                                        google: auth.google.map(|google| ResolvedGoogleAuthDefinition {
                                            acl: google.acl.resolve_non_referenced(
                                                &params,
                                            )
                                        }),
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
                                        is_cache_enabled: static_dir.cache.enabled,
                                        post_processing: ResolvedPostProcessing {
                                            encoding: ResolvedEncoding {
                                                mime_types: static_dir
                                                    .post_processing
                                                    .encoding
                                                    .mime_types
                                                    .clone()
                                                    .resolve_non_referenced(
                                                        &params,
                                                    )
                                                    .map(|m| m.0.iter().map(|mt| mt.0.essence_str().into()).collect()),
                                                brotli: static_dir.post_processing.encoding.brotli,
                                                gzip: static_dir.post_processing.encoding.gzip,
                                                deflate: static_dir.post_processing.encoding.deflate,
                                                min_size: static_dir.post_processing.encoding.min_size,
                                            },
                                            image: ResolvedImage {
                                                is_png: static_dir.post_processing.image.webp.enabled && static_dir.post_processing.image.webp.png,
                                                is_jpeg: static_dir.post_processing.image.webp.enabled && static_dir.post_processing.image.webp.jpeg,
                                            }
                                        },
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
                                        post_processing: ResolvedPostProcessing {
                                            encoding: ResolvedEncoding {
                                                mime_types: proxy
                                                    .post_processing
                                                    .encoding
                                                    .mime_types
                                                    .clone()
                                                    .resolve_non_referenced(
                                                        &params,
                                                    )
                                                    .map(|m| m.0.iter().map(|mt| mt.0.essence_str().into()).collect()),                                                brotli: proxy.post_processing.encoding.brotli,
                                                gzip: proxy.post_processing.encoding.gzip,
                                                deflate: proxy.post_processing.encoding.deflate,
                                                min_size: proxy.post_processing.encoding.min_size,
                                            },
                                            image: ResolvedImage {
                                                is_png: proxy.post_processing.image.webp.enabled && proxy.post_processing.image.webp.png,
                                                is_jpeg: proxy.post_processing.image.webp.enabled && proxy.post_processing.image.webp.jpeg,
                                            }
                                        },
                                        name: proxy.upstream.clone(),
                                        upstream: upstreams
                                            .as_ref()
                                            .expect(
                                                "[BUG]: try to access upstream for project-level config",
                                            )
                                            .get(&proxy.upstream)
                                            .cloned()?,
                                        instance_is: instance_ids.as_ref().map(|ids| ids.keys().cloned().collect()).unwrap_or_default(),
                                        balancer: {
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
                                        is_cache_enabled: proxy.cache.enabled,
                                        is_websockets_enabled: proxy.websockets,
                                    })
                                }
                                ClientHandlerVariant::S3Bucket(s3_bucket) => {
                                    ResolvedHandlerVariant::S3Bucket(s3_bucket::ResolvedS3Bucket {
                                        post_processing: ResolvedPostProcessing {
                                            encoding: ResolvedEncoding {
                                                mime_types: s3_bucket
                                                    .post_processing
                                                    .encoding
                                                    .mime_types
                                                    .clone()
                                                    .resolve_non_referenced(
                                                        &params,
                                                    )
                                                    .map(|m| m.0.iter().map(|mt| mt.0.essence_str().into()).collect()),                                                brotli: s3_bucket.post_processing.encoding.brotli,
                                                gzip: s3_bucket.post_processing.encoding.gzip,
                                                deflate: s3_bucket.post_processing.encoding.deflate,
                                                min_size: s3_bucket.post_processing.encoding.min_size,
                                            },
                                            image: ResolvedImage {
                                                is_png: s3_bucket.post_processing.image.webp.enabled && s3_bucket.post_processing.image.webp.png,
                                                is_jpeg: s3_bucket.post_processing.image.webp.enabled && s3_bucket.post_processing.image.webp.jpeg,
                                            }
                                        },
                                        client: public_client.clone(),
                                        credentials:  s3_bucket
                                            .credentials
                                            .map(|container|
                                                container
                                                    .resolve_non_referenced(
                                                        &params,
                                                    )
                                                    .map(|creds| {
                                                        rusty_s3::Credentials::new(creds.access_key_id.into(), creds.secret_access_key.into())
                                                    })
                                            ),
                                        bucket:
                                        s3_bucket.bucket
                                            .resolve_non_referenced(
                                                &params,
                                            )
                                            .map(|s3_bucket_cfg| {
                                                rusty_s3::Bucket::new(
                                                    s3_bucket_cfg.region.endpoint(),
                                                    false,
                                                    s3_bucket_cfg.name.into(),
                                                    s3_bucket_cfg.region.to_string(),
                                                ).expect("FIXME")
                                            }),
                                        is_cache_enabled: s3_bucket.cache.enabled,
                                    })
                                }
                                ClientHandlerVariant::GcsBucket(gcs_bucket) => {
                                    ResolvedHandlerVariant::GcsBucket(gcs_bucket::ResolvedGcsBucket {
                                        post_processing: ResolvedPostProcessing {
                                            encoding: ResolvedEncoding {
                                                mime_types: gcs_bucket
                                                    .post_processing
                                                    .encoding
                                                    .mime_types
                                                    .clone()
                                                    .resolve_non_referenced(
                                                        &params,
                                                    )
                                                    .map(|m| m.0.iter().map(|mt| mt.0.essence_str().into()).collect()),                                                brotli: gcs_bucket.post_processing.encoding.brotli,
                                                gzip: gcs_bucket.post_processing.encoding.gzip,
                                                deflate: gcs_bucket.post_processing.encoding.deflate,
                                                min_size: gcs_bucket.post_processing.encoding.min_size,
                                            },
                                            image: ResolvedImage {
                                                is_png: gcs_bucket.post_processing.image.webp.enabled && gcs_bucket.post_processing.image.webp.png,
                                                is_jpeg: gcs_bucket.post_processing.image.webp.enabled && gcs_bucket.post_processing.image.webp.jpeg,
                                            }
                                        },
                                        client: public_client.clone(),
                                        bucket_name: gcs_bucket.bucket
                                            .resolve_non_referenced(
                                                &params,
                                            )
                                        ,
                                        auth: gcs_bucket.credentials.resolve_non_referenced(
                                            &params,
                                        ).map(|creds| {
                                            tame_oauth::gcp::ServiceAccountAccess::new(
                                                tame_oauth::gcp::ServiceAccountInfo::deserialize(
                                                    creds.json.as_str()
                                                ).expect("FIXME")
                                            ).expect("FIXME")
                                        }),
                                        token: Default::default(),
                                        is_cache_enabled: gcs_bucket.cache.enabled,
                                    })
                                }
                                // ClientHandlerVariant::ApplicationFirewall(app_firewall) => {
                                //     ResolvedHandlerVariant::ApplicationFirewall(application_firewall::ResolvedApplicationFirewall {
                                //         uri_xss: app_firewall.uri_xss,
                                //         uri_sqli: app_firewall.uri_sqli,
                                //     })
                                // }
                                ClientHandlerVariant::PassThrough(_) => {
                                    ResolvedHandlerVariant::PassThrough(ResolvedPassThrough {})
                                }
                            },
                            priority: handler.priority,
                            catches: resolve_rescue_items(
                                &client_config_info,
                                &params,
                                &refinable,
                                &handler_scope,
                            )?,
                            resolved_rules: handler
                                .rules
                                .into_iter()
                                .enumerate()
                                .filter(|(_, rule)| {
                                    if let Some(active_profile) = &active_profile {
                                        is_profile_active(&rule.profiles, active_profile)
                                    } else {
                                        true
                                    }
                                })
                                .map(|(rule_num, rule)| {
                                    let rule_scope = Scope::rule(
                                        config_name.clone().zip(config_revision.clone()),
                                        &mount_point_name,
                                        &handler_name,
                                        rule_num,
                                    );

                                    Some(ResolvedRule {
                                        filter: ResolvedFilter {
                                            path: rule.filter.path.into(),
                                            query_params: rule.filter.query_params.inner.into_iter().map(|(k, v)| {
                                                (k, v.map(From::from))
                                            }).collect(),
                                            method: rule.filter.methods,
                                            trailing_slash: rule.filter.trailing_slash,
                                            base_path_replacement: replace_base_path.clone(),
                                        },
                                        request_modifications: rule
                                            .action
                                            .modify_request()
                                            .map(|r: &RequestModifications| {
                                                ResolvedRequestModifications {
                                                    headers: r.headers.clone(),
                                                    path: r.path.as_ref().map(|p| p.iter().map(|p| ResolvedPathSegmentModify(p.0.clone())).collect()),
                                                    trailing_slash: r.trailing_slash.clone(),
                                                    modify_query: r.query_params.clone().into(),
                                                }
                                            })
                                            .unwrap_or_default(),
                                        on_response: rule
                                            .action
                                            .on_response()
                                            .into_iter()
                                            .cloned()
                                            .collect(),
                                        action: match rule.action {
                                            Action::Invoke {  .. } => ResolvedRuleAction::Invoke {
                                                rescue: {
                                                    let rescue = resolve_rescue_items(
                                                        &client_config_info,
                                                        &params,
                                                        &refinable,
                                                        &rule_scope,
                                                    )?;

                                                    rescue
                                                },
                                            },
                                            Action::NextHandler => ResolvedRuleAction::NextHandler,
                                            Action::Throw { exception, data } => ResolvedRuleAction::Throw {
                                                exception,
                                                data: data.iter().map(|(k,v)| (k.as_str().into(), v.as_str().into())).collect(),
                                            },
                                            Action::Respond {
                                                static_response, status_code, data, ..
                                            } => ResolvedRuleAction::Respond(ResolvedStaticResponseAction {
                                                static_response: resolve_static_response(
                                                    static_response,
                                                    &status_code,
                                                    &data,
                                                    &params,
                                                    &refinable,
                                                    &handler_scope
                                                ),
                                                rescue: resolve_rescue_items(
                                                    &client_config_info,
                                                    &params,
                                                    &refinable,
                                                    &rule_scope,
                                                )?,
                                            }),
                                        },
                                    })
                                })
                                .collect::<Option<_>>()?,
                            account_unique_id,
                            project_unique_id: project_unique_id.clone(),
                            rules_counter: rules_counter.clone(),
                            languages: None, //handler.languages,
                        })
                    }
                })
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| anyhow!("failed to build processor"))?;

            merged_resolved_handlers.append(&mut r);
        }

        merged_resolved_handlers.sort_by(|left, right| left.priority.cmp(&right.priority));

        Ok(RequestsProcessor {
            is_active: resp.is_active,
            ordered_handlers: if resp.is_active {
                merged_resolved_handlers
            } else {
                vec![]
            },
            project_unique_id: project_unique_id.clone(),
            generated_at: resp.generated_at,
            google_oauth2_client,
            github_oauth2_client,
            assistant_base_url,
            maybe_identity,
            strict_transport_security: resp.strict_transport_security,
            rules_counter,
            account_unique_id,
            cache,
            project_name,
            url_prefix: mount_point_base_url.clone(),
            mount_point_name,
            xchacha20poly1305_secret_key,
            max_pop_cache_size_bytes,
            gw_location: gw_location.into(),
            log_messages_tx,
            dbip,
            webp_semaphore: tokio::sync::Semaphore::new(4),
        })
    }
}

impl Drop for RequestsProcessor {
    fn drop(&mut self) {
        crate::statistics::ACTIVE_REQUESTS_PROCESSORS.dec();
    }
}

#[derive(Debug, Hash, Clone, Eq, PartialEq)]
pub enum ResolvedModifieableRedirectTo {
    AbsoluteUrl(http::Uri),
    WithBaseUrl(http::Uri, Vec<ResolvedPathSegmentModify>),
    Segments(Vec<ResolvedPathSegmentModify>),
    Root,
}

impl ResolvedModifieableRedirectTo {
    fn replace_segment(
        segment: &ResolvedPathSegmentModify,
        matches: Option<&HashMap<SmolStr, Matched>>,
    ) -> anyhow::Result<Replaced> {
        match matches {
            None => Ok(Replaced::Single(segment.0.clone())),
            Some(matches) => Ok(segment.substitute(matches)?),
        }
    }

    pub fn to_destination_string(
        &self,
        query_pairs: &LinkedHashMap<String, String>,
        query_modify: &ResolvedModifyQuery,
        filter_matches: Option<&HashMap<SmolStr, Matched>>,
    ) -> anyhow::Result<String> {
        let (mut url_with_modified_path, should_strip) = match self {
            ResolvedModifieableRedirectTo::AbsoluteUrl(url) => {
                // just `return url.to_string();`?
                (url.clone(), false)
            }
            ResolvedModifieableRedirectTo::Root => (http::Uri::from_static("http://base/"), true),
            ResolvedModifieableRedirectTo::WithBaseUrl(base_url, segments) => {
                let mut url = base_url.clone();
                for segment in segments {
                    let replaced = Self::replace_segment(segment, filter_matches)?;
                    replaced.push_to_url(&mut url);
                }
                (url, false)
            }
            ResolvedModifieableRedirectTo::Segments(segments) => {
                let mut url = http::Uri::from_static("http://base");
                for segment in segments {
                    let replaced = Self::replace_segment(segment, filter_matches)?;
                    replaced.push_to_url(&mut url);
                }
                (url, true)
            }
        };

        match self {
            ResolvedModifieableRedirectTo::AbsoluteUrl(_) => {}
            _ => {
                query_modify.add_query(
                    &mut url_with_modified_path,
                    query_pairs,
                    &filter_matches.cloned().unwrap_or_default(),
                )?;
            }
        }

        if should_strip {
            Ok(url_with_modified_path.path_and_query().unwrap().to_string())
        } else {
            Ok(url_with_modified_path.to_string())
        }
    }
}

#[derive(Clone, Debug)]
struct ResolvedRedirectResponse {
    location: ResolvedModifieableRedirectTo,
    query_modify: ResolvedModifyQuery,
}

#[derive(Clone, Debug)]
struct ResolvedStaticResponse {
    status_code: StatusCode,
    fallback_to_accept: Option<mime::Mime>,
    body: Vec<ResponseBody>,
    headers: HeaderMap,
    data: HashMap<SmolStr, SmolStr>,
    maybe_redirect: Option<ResolvedRedirectResponse>,
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
                            resp_candidate.content_type.0.essence_str().parse().ok()?,
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
        requested_url: &http::uri::Uri,
        additional_data: HashMap<SmolStr, SmolStr>,
        matches: Option<&HashMap<SmolStr, Matched>>,
        _handler_best_language: &Option<LanguageTagBuf>,
        facts: Arc<Mutex<serde_json::Value>>,
    ) -> Result<(), (Exception, HashMap<SmolStr, SmolStr>)> {
        *res = Response::new(Body::empty());

        let query_pairs = requested_url.query_pairs();

        let mut merged_data = self.data.clone();
        merged_data.extend(additional_data.into_iter());

        merged_data.insert("time".into(), Utc::now().to_string().into());

        for (k, v) in &self.headers {
            res.headers_mut().append(k, v.clone());
        }

        if let Some(redirect) = &self.maybe_redirect {
            match redirect.location.to_destination_string(
                &query_pairs,
                &redirect.query_modify,
                matches,
            ) {
                Ok(s) => {
                    res.headers_mut().insert(LOCATION, s.parse().unwrap());
                }
                Err(_e) => {
                    return Err((
                        exceptions::STATIC_RESPONSE_REDIRECT_ERROR.clone(),
                        merged_data.clone(),
                    ));
                }
            }
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
                    exceptions::STATIC_RESPONSE_BAD_ACCEPT_HEADER.clone(),
                    merged_data.clone(),
                ));
            }
            (Ok(None), _) => {
                return Err((
                    exceptions::STATIC_RESPONSE_NO_ACCEPT_HEADER.clone(),
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
                            "url": requested_url.to_string(),
                            "matches": matches,
                        });

                        handlebars
                            .render_template(&resp.content, &rendering_data)
                            .map_err(|e| {
                                merged_data.insert("error".into(), e.to_string().into());
                                (
                                    exceptions::STATIC_RESPONSE_RENDER_ERROR.clone(),
                                    merged_data.into_iter().collect(),
                                )
                            })?
                    }
                };
                *res.body_mut() = Body::from(body);
            }
            None => {
                *res.status_mut() = StatusCode::NOT_ACCEPTABLE;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum ResolvedCatchMatcher {
    StatusCode(StatusCodeRange),
    Exception(Exception),
}

#[derive(Debug, Clone)]
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
    use exogress_common::config_core::MatchPathSingleSegment;

    #[test]
    fn test_matching() {
        let url: http::Uri = "https://a.b.c/".parse().unwrap();
        let url2: http::Uri = "https://a.b.c/a".parse().unwrap();
        let url3: http::Uri = "https://a.b.c/a/b".parse().unwrap();
        let matcher = ResolvedFilter {
            path: MatchingPath::LeftWildcard(vec![MatchPathSegment::Single(
                MatchPathSingleSegment::Any,
            )])
            .into(),
            query_params: Default::default(),
            method: Default::default(),
            trailing_slash: Default::default(),
            base_path_replacement: vec![],
        };

        assert!(!matcher.matches(&url, &Method::GET).is_some());
        assert!(matcher.matches(&url2, &Method::GET).is_some());
        assert!(matcher.matches(&url3, &Method::GET).is_some());
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
