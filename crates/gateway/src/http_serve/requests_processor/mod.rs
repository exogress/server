use crate::{
    clients::{
        traffic_counter::{RecordedTrafficStatistics, TrafficCounters},
        ClientTunnels,
    },
    http_serve::{
        auth::JwtEcdsa,
        cache::{Cache, HandlerChecksum},
        helpers::{clone_response_through_tempfile, ClonedResponse},
        identifier::RequestProcessingIdentifier,
        logging::{save_body_info_to_log_message, LogMessageSendOnDrop},
        requests_processor::{
            modifications::{
                substitute_str_with_filter_matches, Replaced, ResolvedPathSegmentModify,
            },
            pass_through::ResolvedPassThrough,
            post_processing::{ResolvedEncoding, ResolvedImage, ResolvedPostProcessing},
        },
        templates::render_limit_reached,
    },
    mime_helpers::{is_mime_match, ordered_by_quality},
    public_hyper_client::MeteredHttpConnector,
    rules_counter::AccountCounters,
    transformer::TransformerClient,
    webapp::{ConfigData, ConfigsResponse},
};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
pub use auth::{ResolvedGithubAuthDefinition, ResolvedGoogleAuthDefinition};
use byte_unit::Byte;
use chrono::{DateTime, Utc};
use core::mem;
use etag::EntityTag;
use exogress_common::{
    common_utils::uri_ext::UriExt,
    config_core::{
        self, is_profile_active, referenced,
        referenced::{Container, ContainerScope, Parameter},
        refinable::RefinableSet,
        Action, CatchAction, CatchMatcher, ClientConfigRevision, ClientHandlerVariant, Languages,
        MatchPathSegment, MatchPathSingleSegment, MatchQuerySingleValue, MatchQueryValue,
        MatchingPath, MethodMatcher, ModifyHeaders, ModifyQuery, ModifyQueryStrategy, OnResponse,
        RedirectTo, RequestModifications, ResponseBody, RuleCacheMode, Scope, StaticResponse,
        StatusCodeRange, TemplateEngine, TrailingSlashFilterRule, TrailingSlashModification,
        UrlPathSegment,
    },
    entities::{
        exceptions, exceptions::MODIFICATION_ERROR, serde::Serializer, AccountUniqueId, ConfigId,
        ConfigName, Exception, HandlerName, InstanceId, MountPointName, ParameterName, ProjectName,
        ProjectUniqueId, StaticResponseName, Ulid,
    },
};
use exogress_server_common::{
    crypto,
    crypto::decrypt_reader,
    geoip::{model::LocationAndIsp, GeoipReader},
    logging::{
        CacheSavingStatus, CacheableInvocationProcessingStep, CatchProcessingStep,
        CatchProcessingVariantStep, ExceptionProcessingStep, HandlerProcessingStep,
        HandlerProcessingStepVariant, HttpBodyLog, LogMessage, ProcessingStep, RequestMetaInfo,
        ResponseMetaInfo, ScopeLog, StaticResponseProcessingStep, TransformationStatus,
        WellKnownRequestHeaders,
    },
    presence,
    transformer::{ProcessResponse, MAX_SIZE_FOR_TRANSFORMATION},
    ContentHash,
};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt, TryStreamExt,
};
use handlebars::Handlebars;
use hashbrown::HashMap;
use http::{
    header::{
        HeaderName, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, ETAG, LAST_MODIFIED, LOCATION,
        RANGE, SET_COOKIE, STRICT_TRANSPORT_SECURITY,
    },
    HeaderMap, HeaderValue, Method, Request, Response, StatusCode,
};
use hyper::Body;
use itertools::Itertools;
use language_tags::LanguageTag;
use linked_hash_map::LinkedHashMap;
use mime::{IMAGE_JPEG, IMAGE_PNG, TEXT_HTML_UTF_8};
use parking_lot::Mutex;
use pin_utils::pin_mut;
use regex::Regex;
use rw_stream_sink::RwStreamSink;
use serde::{
    ser::{SerializeMap, SerializeSeq},
    Serialize,
};
use serde_json::json;
use sha2::Digest;
use smol_str::SmolStr;
use sodiumoxide::crypto::secretstream::xchacha20poly1305;
use std::{
    collections::BTreeMap,
    convert::{TryFrom, TryInto},
    io,
    net::SocketAddr,
    sync::Arc,
};
use tap::Tap;
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
mod proxy_public;
pub mod refinable;
mod s3_bucket;
mod static_dir;

mod utils;

pub struct RequestsProcessor {
    pub is_active: bool,
    pub is_transformations_limited: bool,
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
    fqdn: String,
    pub mount_point_name: MountPointName,
    pub xchacha20poly1305_secret_key: xchacha20poly1305::Key,
    max_pop_cache_size_bytes: Byte,
    gw_location: SmolStr,
    transformer_client: TransformerClient,
    log_messages_tx: tokio::sync::mpsc::UnboundedSender<LogMessage>,
    dbip: Option<GeoipReader>,
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
        log_message_container: &Arc<parking_lot::Mutex<LogMessageSendOnDrop>>,
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
            .insert("mount_point_hostname".into(), self.fqdn.clone().into());

        self.rules_counter
            .register_request(&self.account_unique_id, &self.project_unique_id);

        let mut processed_by = None;
        let original_req_headers = req.headers().clone();
        for handler in &self.ordered_handlers {
            let invocation_log = Arc::new(parking_lot::Mutex::new(
                CacheableInvocationProcessingStep::Empty {
                    transformation: None,
                },
            ));

            // restore original headers
            *req.headers_mut() = original_req_headers.clone();

            // create new response for each handler, avoid using dirty data from the previous handler
            *res = Response::new(Body::empty());

            let processing_identifier = RequestProcessingIdentifier::new(
                &self.project_name,
                &self.mount_point_name,
                &handler.handler_name,
                &handler.handler_checksum,
                req.method(),
                req.uri().path_and_query().unwrap().as_str(),
            );

            let cached_response = self
                .cache
                .serve_from_cache(&self, &handler, &processing_identifier, &req)
                .await;

            match cached_response {
                Ok(Some(resp_from_cache)) => {
                    let valid_till = resp_from_cache.valid_till;
                    if resp_from_cache.is_full_response_success()
                        || resp_from_cache.has_conditional()
                    {
                        *invocation_log.lock() = CacheableInvocationProcessingStep::Cached {
                            config_name: handler.config_name.clone(),
                            handler_name: handler.handler_name.clone(),
                            transformation: None,
                        };

                        if self.is_transformations_limited {
                            *invocation_log.lock().transformation_mut() =
                                Some(TransformationStatus::Limited);
                            *res = resp_from_cache.into_for_user();
                        } else if is_eligible_for_transformation_not_considering_status_code(
                            resp_from_cache.as_full_resp(),
                            handler.resolved_variant.post_processing(),
                        ) {
                            match resp_from_cache.split_for_user_and_maybe_cloned().await {
                                Ok((for_user, on_response_finished)) => {
                                    *res = for_user;

                                    let transformer_client = self.transformer_client.clone();
                                    let account_secret_key =
                                        self.xchacha20poly1305_secret_key.clone();

                                    let req_uri = req.uri().clone();
                                    let req_method = req.method().clone();
                                    let req_headers = req.headers().clone();

                                    let cache = self.cache.clone();
                                    let account_unique_id = self.account_unique_id;
                                    let project_name = self.project_name.clone();
                                    let project_unique_id = self.project_unique_id;
                                    let mount_point_name = self.mount_point_name.clone();
                                    let max_pop_cache_size_bytes = self.max_pop_cache_size_bytes;
                                    let xchacha20poly1305_secret_key =
                                        self.xchacha20poly1305_secret_key.clone();
                                    let handler_name = handler.handler_name.clone();
                                    let handler_checksum = handler.handler_checksum;
                                    let requested_url = requested_url.clone();
                                    let log_message_container = log_message_container.clone();
                                    let invocation_log = invocation_log.clone();

                                    tokio::spawn(async move {
                                        match on_response_finished.await {
                                            Some(cloned_resp) => {
                                                trigger_transformation_if_required(
                                                    valid_till,
                                                    &req_headers,
                                                    req_method,
                                                    &req_uri,
                                                    cloned_resp,
                                                    account_secret_key,
                                                    transformer_client,
                                                    cache,
                                                    account_unique_id,
                                                    project_name,
                                                    project_unique_id,
                                                    mount_point_name,
                                                    max_pop_cache_size_bytes,
                                                    xchacha20poly1305_secret_key,
                                                    handler_name,
                                                    handler_checksum,
                                                    &requested_url,
                                                    invocation_log.clone(),
                                                    log_message_container.clone(),
                                                )
                                                .await;
                                            }
                                            None => {
                                                error!("on_response_finished returned None!");
                                            }
                                        }
                                    });
                                }
                                Err(e) => {
                                    error!("Failed to clone response through tempfile: {}", e);

                                    *res.body_mut() = Body::from("internal server error");
                                    *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;

                                    return;
                                }
                            }
                        } else {
                            *invocation_log.lock().transformation_mut() =
                                Some(if resp_from_cache.is_transformed() {
                                    TransformationStatus::Transformed
                                } else {
                                    TransformationStatus::NotEligible
                                });

                            *res = resp_from_cache.into_for_user();
                        }

                        res.headers_mut()
                            .insert("x-exg-edge-cached", "1".parse().unwrap());

                        log_message_container
                            .lock()
                            .as_mut()
                            .response
                            .headers
                            .fill_from_headers(res.headers());

                        log_message_container
                            .lock()
                            .as_mut()
                            .steps
                            .push(ProcessingStep::Invoke(invocation_log));

                        return;
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    crate::statistics::EDGE_CACHE_ERRORS
                        .with_label_values(&[crate::statistics::CACHE_ACTION_READ])
                        .inc();
                    warn!("Error reading data from cache: {}", e);
                }
            }

            if let Some(rebased_url) = Rebase::rebase_url(&handler.rebase, &requested_url) {
                let best_language = if let Some(languages) = &handler.languages {
                    if let Ok(Some(accept_languages)) =
                        req.headers().typed_get::<typed_headers::AcceptLanguage>()
                    {
                        ordered_by_quality(&accept_languages)
                            .filter_map(|accepted| {
                                languages
                                    .supported
                                    .iter()
                                    .find(|supported_lang| supported_lang.matches(accepted))
                            })
                            .next()
                            .cloned()
                    } else {
                        None
                    }
                    .or_else(|| languages.default.clone())
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
                        invocation_log.clone(),
                        log_message_container,
                    )
                    .await;

                match result {
                    ResolvedHandlerProcessingResult::Processed { cache_mode } => {
                        processed_by = Some((handler, cache_mode, invocation_log));
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
            Some((handler, cache_mode, invocation_log)) => {
                // Try to trigger transformation if applicable
                if handler.resolved_variant.is_cache_enabled() != Some(true) {
                    // cache is disabled
                    if let CacheableInvocationProcessingStep::Invoked(step) =
                        &mut *invocation_log.lock()
                    {
                        step.save_to_cache = Some(CacheSavingStatus::Disabled);
                    }
                    *invocation_log.lock().transformation_mut() =
                        Some(TransformationStatus::CacheDisabled);
                } else if !self.is_transformations_limited
                    && res.status().is_success()
                    && is_eligible_for_transformation_not_considering_status_code(
                        res,
                        handler.resolved_variant.post_processing(),
                    )
                {
                    // transformation allowed
                    if !self.cache.is_enough_space() {
                        crate::statistics::CACHE_NOT_ENOUGH_SPACE_SAVE_SKIPPED.inc();
                        warn!(
                            "Not triggering transformation, because cache dir reached global limit in size"
                        );
                    } else if let Some(max_age) = cache_max_age_if_eligible(req, res, &cache_mode) {
                        match clone_response_through_tempfile(res).await {
                            Ok(on_response_finished) => {
                                let transformer_client = self.transformer_client.clone();
                                let account_secret_key = self.xchacha20poly1305_secret_key.clone();

                                let req_uri = req.uri().clone();
                                let req_method = req.method().clone();
                                let req_headers = req.headers().clone();

                                let cache = self.cache.clone();
                                let account_unique_id = self.account_unique_id;
                                let project_name = self.project_name.clone();
                                let project_unique_id = self.project_unique_id;
                                let mount_point_name = self.mount_point_name.clone();
                                let max_pop_cache_size_bytes = self.max_pop_cache_size_bytes;
                                let xchacha20poly1305_secret_key =
                                    self.xchacha20poly1305_secret_key.clone();
                                let handler_name = handler.handler_name.clone();
                                let handler_checksum = handler.handler_checksum;
                                let requested_url = requested_url.clone();
                                let log_message_container = log_message_container.clone();
                                let invocation_log = invocation_log.clone();

                                tokio::spawn(async move {
                                    if let Some(cloned_resp) = on_response_finished.await {
                                        trigger_transformation_if_required(
                                            Utc::now() + max_age,
                                            &req_headers,
                                            req_method,
                                            &req_uri,
                                            cloned_resp,
                                            account_secret_key,
                                            transformer_client,
                                            cache,
                                            account_unique_id,
                                            project_name,
                                            project_unique_id,
                                            mount_point_name,
                                            max_pop_cache_size_bytes,
                                            xchacha20poly1305_secret_key,
                                            handler_name,
                                            handler_checksum,
                                            &requested_url,
                                            invocation_log,
                                            log_message_container.clone(),
                                        )
                                        .await;
                                    }
                                });
                            }
                            Err(e) => {
                                error!("Failed to clone response through tempfile: {}", e);
                            }
                        }
                    }
                } else {
                    // transformation is limited. ignore
                    *invocation_log.lock().transformation_mut() =
                        Some(if self.is_transformations_limited {
                            TransformationStatus::Limited
                        } else {
                            TransformationStatus::NotEligible
                        });
                };

                if let Err(e) = self.compress_if_applicable(
                    req,
                    res,
                    handler
                        .resolved_variant
                        .post_processing()
                        .map(|pp| &pp.encoding),
                    log_message_container,
                ) {
                    warn!("Error compressing: {}", e);
                };

                res.headers_mut()
                    .insert("server", HeaderValue::from_static("exogress"));
                res.headers_mut()
                    .insert("x-exg-location", self.gw_location.parse().unwrap());

                if handler.resolved_variant.is_cache_enabled() == Some(true) {
                    if !self.cache.is_enough_space() {
                        crate::statistics::CACHE_NOT_ENOUGH_SPACE_SAVE_SKIPPED.inc();
                        warn!(
                            "Not saving content to cache, because cache reached the limit in size"
                        );
                        if let CacheableInvocationProcessingStep::Invoked(step) =
                            &mut *invocation_log.lock()
                        {
                            step.save_to_cache = Some(CacheSavingStatus::SaveError);
                        }
                    } else if let Some(max_age) = cache_max_age_if_eligible(req, res, &cache_mode) {
                        let cache = self.cache.clone();
                        let account_unique_id = self.account_unique_id;
                        let project_name = self.project_name.clone();
                        let mount_point_name = self.mount_point_name.clone();
                        let max_pop_cache_size_bytes = self.max_pop_cache_size_bytes;
                        let xchacha20poly1305_secret_key =
                            self.xchacha20poly1305_secret_key.clone();
                        let handler_name = handler.handler_name.clone();
                        let handler_checksum = handler.handler_checksum;

                        let req_headers = req.headers();
                        let req_method = req.method().clone();
                        let req_uri = req.uri();

                        save_to_cache(
                            Utc::now() + max_age,
                            req_headers,
                            req_method,
                            req_uri,
                            res,
                            cache,
                            account_unique_id,
                            project_name,
                            mount_point_name,
                            max_pop_cache_size_bytes,
                            xchacha20poly1305_secret_key,
                            handler_name,
                            handler_checksum,
                            Some(invocation_log.clone()),
                            &log_message_container,
                        );
                    } else if let CacheableInvocationProcessingStep::Invoked(step) =
                        &mut *invocation_log.lock()
                    {
                        step.save_to_cache = Some(CacheSavingStatus::NotEligible);
                    }
                }
            }
        }

        log_message_container
            .lock()
            .as_mut()
            .response
            .headers
            .fill_from_headers(res.headers());

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
            let facts = Arc::new(Mutex::new(json!({})));

            let request_id = Ulid::new();

            let response_body_log = HttpBodyLog::default();
            let request_body_log = HttpBodyLog::default();
            let started_at = Utc::now();

            let log_message = LogMessage {
                request_id,
                gw_location: self.gw_location.clone(),
                project_unique_id: self.project_unique_id,
                remote_addr: remote_addr.ip(),
                account_unique_id: self.account_unique_id,
                project: self.project_name.clone(),
                mount_point: self.mount_point_name.clone(),
                request: RequestMetaInfo {
                    headers: WellKnownRequestHeaders::default().tap_mut(|well_known_headers| {
                        well_known_headers.fill_from_headers(&req.headers())
                    }),
                    body: request_body_log.clone(),
                    url: requested_url.to_string().into(),
                    method: req.method().to_string().into(),
                },
                response: ResponseMetaInfo {
                    headers: Default::default(),
                    body: response_body_log.clone(),
                    compression: None,
                    status_code: None,
                },
                protocol: format!("{:?}", req.version()).into(),
                steps: vec![],
                facts: facts.clone(),
                str: None,
                timestamp: started_at,
                started_at,
                ended_at: None,
                time_taken_ms: None,
            };

            let log_message_container = Arc::new(parking_lot::Mutex::new(
                LogMessageSendOnDrop::new(log_message, self.log_messages_tx.clone()),
            ));

            let original_request_body = mem::replace(req.body_mut(), Body::empty());
            *req.body_mut() = save_body_info_to_log_message(
                original_request_body,
                log_message_container.clone(),
                request_body_log,
            );

            self.do_process(
                req,
                res,
                requested_url,
                local_addr,
                remote_addr,
                facts,
                &log_message_container,
            )
            .await;

            {
                let mut log_message = log_message_container.lock();

                log_message.as_mut().response.status_code = Some(res.status().as_u16());
            };

            let original_response_body = mem::replace(res.body_mut(), Body::empty());
            *res.body_mut() = save_body_info_to_log_message(
                original_response_body,
                log_message_container.clone(),
                response_body_log.clone(),
            );

            res.headers_mut().insert(
                "x-exg-request-id",
                HeaderValue::try_from(request_id.to_string()).unwrap(),
            );
        } else {
            let body = render_limit_reached();
            {
                let headers = res.headers_mut();
                headers.insert(CONTENT_TYPE, TEXT_HTML_UTF_8.to_string().parse().unwrap());
                headers.insert(CONTENT_LENGTH, body.len().into());
                headers.insert("server", HeaderValue::from_static("exogress"));
                res.headers_mut()
                    .insert("x-exg-location", self.gw_location.parse().unwrap());
            }
            *res.body_mut() = Body::from(body);
        }
    }
}

fn save_to_cache(
    valid_till: chrono::DateTime<Utc>,
    req_headers: &HeaderMap,
    req_method: Method,
    req_uri: &http::Uri,
    res: &mut Response<Body>,
    cache: Cache,
    account_unique_id: AccountUniqueId,
    project_name: ProjectName,
    mount_point_name: MountPointName,
    max_pop_cache_size_bytes: Byte,
    xchacha20poly1305_secret_key: xchacha20poly1305::Key,
    handler_name: HandlerName,
    handler_checksum: HandlerChecksum,
    invocation_log: Option<Arc<parking_lot::Mutex<CacheableInvocationProcessingStep>>>,
    log_message_container: &Arc<parking_lot::Mutex<LogMessageSendOnDrop>>,
) {
    if !cache.is_enough_space() {
        crate::statistics::CACHE_NOT_ENOUGH_SPACE_SAVE_SKIPPED.inc();
        warn!("Not saving content to cache, because cache reached the limit in size");
        if let Some(invocation_log) = &invocation_log {
            if let CacheableInvocationProcessingStep::Invoked(step) = &mut *invocation_log.lock() {
                step.save_to_cache = Some(CacheSavingStatus::SaveError);
            }
        }
    }

    shadow_clone!(log_message_container);

    let path_and_query = req_uri.path_and_query().unwrap().to_string();

    let method = req_method;
    let req_headers = req_headers.clone();
    let mut res_headers = res.headers().clone();
    let status = res.status();

    let (mut resp_tx, resp_rx) = mpsc::channel(1);

    let mut original_body_stream = mem::replace(res.body_mut(), Body::empty());

    let mut content_hash = ContentHash::default();

    tokio::spawn(async move {
        let r = async move {
            let tempdir = tokio::task::spawn_blocking(tempfile::tempdir).await??;

            let tempfile_path = tempdir.path().to_owned().join("req");
            let mut original_file_size = 0;
            let mut tempfile = tokio::fs::File::create(&tempfile_path).await?;

            let (content_hash_finished_tx, content_hash_finished_rx) = oneshot::channel();

            let hash_calculating_stream = async_stream::stream! {
                while let Some(chunk) = original_body_stream.next().await {
                    let c = chunk?;
                    content_hash.update(&c);
                    let _ = resp_tx
                        .send(c.clone())
                        .await;

                    yield(Ok::<_, hyper::Error>(c))
                };

                let _ = content_hash_finished_tx.send(content_hash);
            };

            pin_mut!(hash_calculating_stream);

            let (encrypted, header) =
                crypto::encrypt_stream(hash_calculating_stream, &xchacha20poly1305_secret_key)?;

            pin_mut!(encrypted);

            while let Some(item_result) = encrypted.next().await {
                let (item, original_chunk_size) = item_result?;
                original_file_size += original_chunk_size;

                tempfile.write_all(&item).await.unwrap();
            }

            let processing_identifier = RequestProcessingIdentifier::new(
                &project_name,
                &mount_point_name,
                &handler_name,
                &handler_checksum,
                &method,
                &path_and_query,
            );

            if let Ok(content_hash) = content_hash_finished_rx.await {
                let cached_response = cache
                    .save_content_from_temp_file(
                        processing_identifier,
                        &account_unique_id,
                        &req_headers,
                        &mut res_headers,
                        status,
                        original_file_size.try_into().unwrap(),
                        header,
                        bs58::encode(content_hash.finalize()).into_string(),
                        max_pop_cache_size_bytes,
                        valid_till,
                        &xchacha20poly1305_secret_key,
                        tempfile_path,
                    )
                    .await;

                match cached_response {
                    Err(e) => {
                        crate::statistics::EDGE_CACHE_ERRORS
                            .with_label_values(&[crate::statistics::CACHE_ACTION_WRITE])
                            .inc();
                        error!("error saving to cache: {}", e);
                        if let Some(invocation_log) = invocation_log {
                            if let CacheableInvocationProcessingStep::Invoked(step) =
                                &mut *invocation_log.lock()
                            {
                                step.save_to_cache = Some(CacheSavingStatus::SaveError);
                            }
                        }
                    }
                    Ok(true) => {
                        if let Some(invocation_log) = invocation_log {
                            if let CacheableInvocationProcessingStep::Invoked(step) =
                                &mut *invocation_log.lock()
                            {
                                step.save_to_cache = Some(CacheSavingStatus::Saved { valid_till });
                            }
                        }
                    }
                    Ok(false) => {
                        if let Some(invocation_log) = invocation_log {
                            if let CacheableInvocationProcessingStep::Invoked(step) =
                                &mut *invocation_log.lock()
                            {
                                step.save_to_cache = Some(CacheSavingStatus::Skipped);
                            }
                        }
                    }
                }
            }

            mem::drop(log_message_container);

            Ok::<_, anyhow::Error>(())
        }
        .await;

        if let Err(e) = r {
            error!("error saving to cache: {}", e);
        }
    });

    *res.body_mut() = Body::wrap_stream(resp_rx.map(Ok::<_, hyper::Error>));
}

async fn trigger_transformation_if_required(
    valid_till: chrono::DateTime<Utc>,
    req_headers: &HeaderMap,
    req_method: Method,
    req_uri: &http::Uri,
    cloned_res: ClonedResponse,
    account_secret_key: xchacha20poly1305::Key,
    transformer_client: TransformerClient,
    cache: Cache,
    account_unique_id: AccountUniqueId,
    project_name: ProjectName,
    project_unique_id: ProjectUniqueId,
    mount_point_name: MountPointName,
    max_pop_cache_size_bytes: Byte,
    xchacha20poly1305_secret_key: xchacha20poly1305::Key,
    handler_name: HandlerName,
    handler_checksum: HandlerChecksum,
    requested_url: &http::uri::Uri,
    invocation_log: Arc<parking_lot::Mutex<CacheableInvocationProcessingStep>>,
    log_message_container: Arc<parking_lot::Mutex<LogMessageSendOnDrop>>,
) {
    let r = async move {
        if !cache.is_enough_space() {
            crate::statistics::CACHE_NOT_ENOUGH_SPACE_SAVE_SKIPPED.inc();
            *invocation_log.lock().transformation_mut() = Some(TransformationStatus::Skipped);

            warn!("Not saving content to cache, because cache reached the limit in size");
        } else {
            let maybe_accept = req_headers.typed_get::<typed_headers::Accept>()?;

            let maybe_content_type = cloned_res
                .response
                .headers()
                .typed_get::<typed_headers::ContentType>()?;

            if let (Some(accept), Some(content_type)) = (maybe_accept, maybe_content_type) {
                let transformer_result = transformer_client
                    .request_content(
                        &cloned_res.content_hash,
                        &content_type.0,
                        &handler_name,
                        &project_name,
                        &project_unique_id,
                        &mount_point_name,
                        &requested_url,
                    )
                    .await?;

                let mut resp = cloned_res.response;

                *invocation_log.lock().transformation_mut() = Some(TransformationStatus::Triggered);

                match transformer_result {
                    ProcessResponse::Ready(ready) => {
                        if let Some((best_format, content_type)) = transformer_client
                            .find_best_conversion(&ready, &accept)
                            .await
                        {
                            let download_result = transformer_client
                                .download_best_processed(
                                    best_format,
                                    &content_type,
                                    &cloned_res.content_hash,
                                )
                                .await?;

                            if let Some((transformed_body, encryption_header)) = download_result {
                                let encryption_header =
                                    sodiumoxide::crypto::secretstream::Header::from_slice(
                                        base64::decode(encryption_header)?.as_ref(),
                                    )
                                    .ok_or_else(|| anyhow!("bad encryption header"))?;

                                let io = tokio_util::compat::FuturesAsyncReadCompatExt::compat(
                                    RwStreamSink::new(transformed_body.map_err(|e| {
                                        io::Error::new(
                                            io::ErrorKind::Other,
                                            format!("hyper error: {}", e),
                                        )
                                    })),
                                );
                                let decrypted_stream =
                                    decrypt_reader(io, &account_secret_key, &encryption_header)?;

                                let transformed_content = decrypted_stream
                                    .try_fold(Vec::new(), |mut acc, chunk| async move {
                                        acc.extend_from_slice(&chunk);
                                        Ok(acc)
                                    })
                                    .await?;

                                resp.headers_mut().insert(
                                    "x-exg-transformed",
                                    HeaderValue::try_from("1").unwrap(),
                                );
                                resp.headers_mut()
                                    .insert(CONTENT_TYPE, content_type.parse().unwrap());
                                resp.headers_mut().insert(
                                    CONTENT_LENGTH,
                                    HeaderValue::from(cloned_res.content_length),
                                );
                                resp.headers_mut().insert(
                                    ETAG,
                                    EntityTag::from_data(cloned_res.content_hash.as_ref())
                                        .to_string()
                                        .parse()
                                        .unwrap(),
                                );
                                resp.headers_mut().insert(
                                    LAST_MODIFIED,
                                    ready.transformed_at.to_rfc2822().parse().unwrap(),
                                );

                                *resp.body_mut() = Body::from(transformed_content);

                                save_to_cache(
                                    valid_till,
                                    req_headers,
                                    req_method,
                                    req_uri,
                                    &mut resp,
                                    cache,
                                    account_unique_id,
                                    project_name,
                                    mount_point_name,
                                    max_pop_cache_size_bytes,
                                    xchacha20poly1305_secret_key,
                                    handler_name,
                                    handler_checksum,
                                    None,
                                    &log_message_container,
                                );

                                // FIXME: this is ugly, but we need to consume whole body stream in order
                                // to successfully complete cache saving
                                let mut body_to_consume = resp.into_body();
                                while body_to_consume.next().await.is_some() {}
                            }
                        } else {
                            // no appropriate conversion is available to the provided Accept header.
                            // This is still treated as correctly transformed so that no more requests are made to transformer

                            resp.headers_mut()
                                .insert("x-exg-transformed", HeaderValue::try_from("1").unwrap());

                            save_to_cache(
                                valid_till,
                                req_headers,
                                req_method,
                                req_uri,
                                &mut resp,
                                cache,
                                account_unique_id,
                                project_name,
                                mount_point_name,
                                max_pop_cache_size_bytes,
                                xchacha20poly1305_secret_key,
                                handler_name,
                                handler_checksum,
                                None,
                                &log_message_container,
                            );

                            // FIXME: this is ugly, but we need to consume whole body stream in order to successfuly complete cache saving
                            let mut body_to_consume = resp.into_body();
                            while body_to_consume.next().await.is_some() {}
                        };

                        *invocation_log.lock().transformation_mut() =
                            Some(TransformationStatus::SavedToCache);
                    }
                    ProcessResponse::PendingUpload { upload_id, .. } => {
                        transformer_client
                            .upload(&upload_id, cloned_res.content_length, resp.into_body())
                            .await?;
                    }
                    ProcessResponse::Accepted => {}
                    ProcessResponse::Processing => {}
                }
            }
        }

        Ok::<_, anyhow::Error>(())
    }
    .await;

    if let Err(e) = r {
        error!("error in transformation: {}", e);
    }
}

fn is_eligible_for_transformation_not_considering_status_code(
    resp: &Response<Body>,
    maybe_post_processing: Option<&ResolvedPostProcessing>,
) -> bool {
    match maybe_post_processing {
        Some(post_processing) => {
            let is_from_transformer = resp.headers().get("x-exg-transformed").is_some();

            if is_from_transformer {
                return false;
            }

            if let Ok(Some(content_len)) =
                resp.headers().typed_get::<typed_headers::ContentLength>()
            {
                if content_len.0 > MAX_SIZE_FOR_TRANSFORMATION {
                    // too large file, no transformation
                    return false;
                }
            } else {
                // no content-length, not transforming
                return false;
            }

            let content_type_result = resp.headers().typed_get::<typed_headers::ContentType>();

            match content_type_result {
                Ok(Some(mime_type)) => {
                    (mime_type.0 == IMAGE_JPEG && post_processing.image.is_jpeg)
                        || (mime_type.0 == IMAGE_PNG && post_processing.image.is_png)
                }
                Ok(None) => {
                    // error!("no content-type while checking transformation eligibility");
                    false
                }
                Err(_e) => {
                    // error!("bad content-type while checking transformation eligibility");
                    false
                }
            }
        }
        None => false,
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

        Some(rebased_url)
    }
}

pub fn cache_max_age_without_checks(
    res: &Response<Body>,
    cache_mode: &RuleCacheMode,
) -> Option<chrono::Duration> {
    match cache_mode {
        RuleCacheMode::Headers => {}
        RuleCacheMode::Prohibit => {
            return None;
        }
        RuleCacheMode::Force { max_age } => {
            return Some(chrono::Duration::from_std(max_age.0).unwrap());
        }
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

    if !caching_allowed || max_age.is_none() {
        return None;
    }

    Some(max_age.unwrap())
}

pub fn cache_max_age_if_eligible(
    req: &Request<Body>,
    res: &Response<Body>,
    cache_mode: &RuleCacheMode,
) -> Option<chrono::Duration> {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return None;
    };

    if !res.status().is_success() {
        info!("unsuccessful status");
        return None;
    }

    if req.headers().contains_key(RANGE) {
        info!("range set!");
        return None;
    }

    if res.headers().contains_key(SET_COOKIE) {
        info!("set-cookie set. skip caching!");
        return None;
    }

    cache_max_age_without_checks(res, cache_mode)
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
    ProxyPublic(proxy_public::ResolvedProxyPublic),
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
            ResolvedHandlerVariant::ProxyPublic(p) => Some(p.is_cache_enabled),
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
            ResolvedHandlerVariant::ProxyPublic(p) => Some(&p.post_processing),
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
    pub async fn try_handle_service_paths(
        &self,
        req: &Request<Body>,
        res: &mut Response<Body>,
        requested_url: &http::uri::Uri,
        language: &Option<LanguageTag>,
        log_message_container: &Arc<parking_lot::Mutex<LogMessageSendOnDrop>>,
    ) -> Option<HandlerInvocationResult> {
        match self {
            ResolvedHandlerVariant::Auth(handler) => {
                handler
                    .try_handle_service_paths(
                        req,
                        res,
                        requested_url,
                        language,
                        log_message_container,
                    )
                    .await
            }
            _ => None,
        }
    }

    async fn invoke(
        &self,
        req: &mut Request<Body>,
        res: &mut Response<Body>,
        requested_url: &http::uri::Uri,
        modified_url: &http::uri::Uri,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        language: &Option<LanguageTag>,
        cacheable_invocation_log: Arc<parking_lot::Mutex<CacheableInvocationProcessingStep>>,
        log_message_container: &Arc<parking_lot::Mutex<LogMessageSendOnDrop>>,
    ) -> HandlerInvocationResult {
        assert!(!cacheable_invocation_log.lock().is_not_empty());

        match self {
            ResolvedHandlerVariant::Proxy(proxy) => {
                let mut proxy_log = None;
                let r = proxy
                    .invoke(
                        req,
                        res,
                        requested_url,
                        modified_url,
                        local_addr,
                        remote_addr,
                        language,
                        &mut proxy_log,
                        log_message_container,
                    )
                    .await;

                if let Some(log) = proxy_log {
                    let mut locked = cacheable_invocation_log.lock();
                    let current = locked.transformation_mut().clone();
                    *locked = HandlerProcessingStep {
                        variant: HandlerProcessingStepVariant::Proxy(log),
                        path: modified_url.path_and_query().unwrap().as_str().into(),
                        save_to_cache: None,
                        transformation: current,
                    }
                    .into();
                };

                r
            }
            ResolvedHandlerVariant::StaticDir(static_dir) => {
                let mut static_dir_log = None;

                let r = static_dir
                    .invoke(
                        req,
                        res,
                        requested_url,
                        modified_url,
                        local_addr,
                        remote_addr,
                        language,
                        &mut static_dir_log,
                        log_message_container,
                    )
                    .await;

                if let Some(log) = static_dir_log {
                    let mut locked = cacheable_invocation_log.lock();
                    let current = locked.transformation_mut().clone();
                    *locked = HandlerProcessingStep {
                        variant: HandlerProcessingStepVariant::StaticDir(log),
                        path: modified_url.path_and_query().unwrap().as_str().into(),
                        save_to_cache: None,
                        transformation: current,
                    }
                    .into();
                };

                r
            }
            ResolvedHandlerVariant::Auth(auth) => {
                let mut auth_log = None;

                let r = auth
                    .invoke(req, res, requested_url, language, &mut auth_log)
                    .await;

                if let Some(log) = auth_log {
                    let mut locked = cacheable_invocation_log.lock();
                    let current = locked.transformation_mut().clone();
                    *locked = HandlerProcessingStep {
                        variant: HandlerProcessingStepVariant::Auth(log),
                        path: modified_url.path_and_query().unwrap().as_str().into(),
                        save_to_cache: None,
                        transformation: current,
                    }
                    .into();
                };

                r
            }
            ResolvedHandlerVariant::S3Bucket(s3_bucket) => {
                let mut s3_log = None;
                let r = s3_bucket
                    .invoke(
                        req,
                        res,
                        requested_url,
                        modified_url,
                        language,
                        &mut s3_log,
                        log_message_container,
                    )
                    .await;

                if let Some(log) = s3_log {
                    let mut locked = cacheable_invocation_log.lock();
                    let current = locked.transformation_mut().clone();
                    *locked = HandlerProcessingStep {
                        variant: HandlerProcessingStepVariant::S3Bucket(log),
                        path: modified_url.path_and_query().unwrap().as_str().into(),
                        save_to_cache: None,
                        transformation: current,
                    }
                    .into();
                };

                r
            }
            ResolvedHandlerVariant::GcsBucket(gcs_bucket) => {
                let mut gcs_log = None;

                let r = gcs_bucket
                    .invoke(
                        req,
                        res,
                        requested_url,
                        modified_url,
                        language,
                        &mut gcs_log,
                        log_message_container,
                    )
                    .await;

                if let Some(log) = gcs_log {
                    let mut locked = cacheable_invocation_log.lock();
                    let current = locked.transformation_mut().clone();
                    *locked = HandlerProcessingStep {
                        variant: HandlerProcessingStepVariant::GcsBucket(log),
                        path: modified_url.path_and_query().unwrap().as_str().into(),
                        save_to_cache: None,
                        transformation: current,
                    }
                    .into();
                };

                r
            }
            ResolvedHandlerVariant::PassThrough(pass_through) => {
                pass_through
                    .invoke(req, res, requested_url, modified_url)
                    .await
            }
            ResolvedHandlerVariant::ProxyPublic(proxy_public) => {
                let mut proxy_public_log = None;
                let r = proxy_public
                    .invoke(
                        req,
                        res,
                        requested_url,
                        modified_url,
                        &local_addr,
                        &remote_addr,
                        language,
                        &mut proxy_public_log,
                        log_message_container,
                    )
                    .await;

                if let Some(log) = proxy_public_log {
                    let mut locked = cacheable_invocation_log.lock();
                    let current = locked.transformation_mut().clone();
                    *locked = HandlerProcessingStep {
                        variant: HandlerProcessingStepVariant::ProxyPublic(log),
                        path: modified_url.path_and_query().unwrap().as_str().into(),
                        save_to_cache: None,
                        transformation: current,
                    }
                    .into();
                };

                r
            }
        }
    }
}

#[derive(Debug)]
enum ResolvedRuleAction {
    Invoke {
        rescues: Vec<ResolvedRescueItem>,
        scope: Scope,
    },
    NextHandler,
    Throw {
        exception: Exception,
        data: HashMap<SmolStr, SmolStr>,
    },
    Respond(Box<ResolvedStaticResponseAction>),
}

impl ResolvedRuleAction {
    pub fn rescues(&self) -> Vec<ResolvedRescueItem> {
        match self {
            ResolvedRuleAction::Invoke { rescues, .. } => rescues.clone(),
            ResolvedRuleAction::NextHandler => Default::default(),
            ResolvedRuleAction::Throw { .. } => Default::default(),
            ResolvedRuleAction::Respond(action) => action.rescues.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct ResolvedStaticResponseAction {
    // static_response_name: StaticResponseName,
    pub static_response: Result<ResolvedStaticResponse, referenced::Error>,
    pub rescues: Vec<ResolvedRescueItem>,
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
        language: &Option<LanguageTag>,
        log_message_container: &Arc<parking_lot::Mutex<LogMessageSendOnDrop>>,
    ) -> ResolvedHandlerProcessingResult {
        let facts = log_message_container.lock().as_mut().facts.clone();

        *res = Response::new(Body::empty());

        match &self.static_response {
            Err(e) => {
                let mut data = additional_data.cloned().unwrap_or_default();

                data.insert(SmolStr::from("error"), SmolStr::from(e.to_string()));

                let rescuable = Rescuable::Exception {
                    exception: exceptions::STATIC_RESPONSE_NOT_DEFINED.clone(),
                    data,
                };

                handler.handle_rescuable(
                    req,
                    res,
                    requested_url,
                    rescuable,
                    &Default::default(),
                    true,
                    &self.rescues,
                    &language,
                    log_message_container,
                )
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

                log_message_container
                    .lock()
                    .as_mut()
                    .steps
                    .push(ProcessingStep::StaticResponse(
                        StaticResponseProcessingStep {
                            data: static_response.data.clone(),
                            config_name: handler.config_name.clone(),
                            scope: container_scope_to_log(&static_response.container_scope),
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
                    language,
                ) {
                    Ok(()) => ResolvedHandlerProcessingResult::Processed {
                        cache_mode: Default::default(),
                    },
                    Err((exception, data)) => {
                        *res = Response::new(Body::empty());
                        if !is_in_exception {
                            let rescuable = Rescuable::Exception { exception, data };
                            // error!("could not invoke static resp; call handle_rescuable. rescue handlers: {:?}", self.rescues);
                            handler.handle_rescuable(
                                req,
                                res,
                                requested_url,
                                rescuable,
                                &Default::default(),
                                false,
                                &self.rescues,
                                &language,
                                log_message_container,
                            )
                        } else {
                            *res.body_mut() = Body::from("Internal server error");
                            *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;

                            ResolvedHandlerProcessingResult::Processed {
                                cache_mode: Default::default(),
                            }
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
    NextHandler {
        scope: Scope,
    },
}

// impl ResolvedCatchAction {
//     pub fn scope(&self) -> &Scope {
//         match self {
//             ResolvedCatchAction::StaticResponse(resp) => &resp.scope,
//             ResolvedCatchAction::Throw {  .. } => &scope,
//             ResolvedCatchAction::NextHandler { scope } => scope,
//         }
//     }
// }

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
    Choice(Box<AhoCorasick>),
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
                ResolvedMatchQueryValue::Choice(Box::new(aho_corasick))
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
                ResolvedMatchPathSegment::Choice(Box::new(aho_corasick))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum ResolvedMatchPathSegment {
    Any,
    Exact(UrlPathSegment),
    Regex(Box<Regex>),
    Choice(Box<AhoCorasick>),
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
                None => match query_pairs.get(expected_key) {
                    Some(provided_val) => {
                        let mut values = provided_val
                            .split('/')
                            .filter(|s| !s.is_empty())
                            .map(|s| s.into())
                            .collect::<Vec<_>>();

                        if values.len() == 1 {
                            h.insert(expected_key.clone(), Matched::Single(values.pop().unwrap()));
                        } else {
                            h.insert(expected_key.clone(), Matched::Segments(values));
                        }
                    }
                    None => {
                        h.insert(expected_key.clone(), Matched::None);
                    }
                },
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
        let is_trailing_slash = url.path().ends_with('/');

        if !self.method.is_match(method) {
            return None;
        }

        // We should preserve the order of query parameters
        let req_query_pairs: LinkedHashMap<SmolStr, SmolStr> = url
            .to_url()
            .query_pairs()
            .map(|(k, v)| (SmolStr::from(k), SmolStr::from(v)))
            .collect();

        let query_matches = self.query_match(req_query_pairs)?;

        let mut segments = vec![];
        {
            let mut path_segments = url.path_segments().into_iter();
            let base_segments = self.base_path_replacement.iter();

            for expected_base_segment in base_segments {
                if let Some(segment) = path_segments.next() {
                    if segment != expected_base_segment.as_str() {
                        return None;
                    }
                } else {
                    return None;
                }
            }

            for segment in path_segments {
                if !segment.is_empty() {
                    segments.push(SmolStr::from(segment.to_string()));
                }
            }
        }

        let matcher = || -> Option<HashMap<SmolStr, Matched>> {
            let mut matches = HashMap::new();

            match &self.path {
                ResolvedMatchingPath::Root
                    if segments.is_empty() || (segments.len() == 1 && segments[0].is_empty()) => {}
                ResolvedMatchingPath::Wildcard => {
                    matches.insert("0".to_string().into(), Matched::Segments(segments.to_vec()));
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
                            Matched::Segments(wildcard_part.to_vec()),
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
                            Matched::Segments(wildcard_part.to_vec()),
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
                            Matched::Segments(wildcard_part.to_vec()),
                        );
                    }
                }
                _ => return None,
            }

            Some(matches)
        };

        let path_match = (matcher)()?;

        match self.trailing_slash {
            TrailingSlashFilterRule::Require if !is_trailing_slash => {
                return None;
            }
            TrailingSlashFilterRule::Deny if is_trailing_slash => {
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
    cache_mode: RuleCacheMode,
}

#[derive(Debug, Clone, Default)]
pub struct ResolvedModifyQuery(ModifyQuery);

impl ResolvedModifyQuery {
    pub(crate) fn add_query(
        &self,
        uri: &mut http::Uri,
        initial_query_params: &LinkedHashMap<String, String>,
        filter_matchers: &HashMap<SmolStr, Matched>,
        language: &Option<LanguageTag>,
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
                            substitute_str_with_filter_matches(value, filter_matchers, language)?
                                .to_string(),
                        );
                    }
                }
                query_params
            }
        };

        for (param, value) in self.0.set.iter() {
            params.insert(
                param.to_string(),
                substitute_str_with_filter_matches(value, filter_matchers, language)?.to_string(),
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
        &RuleCacheMode,
        &ResolvedRequestModifications,
        &Vec<OnResponse>,
    )> {
        let (matches, replaced_base_path_len) = self.filter.matches(rebased_url, method)?;

        Some((
            matches,
            replaced_base_path_len,
            &self.action,
            &self.cache_mode,
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

    rescues: Vec<ResolvedRescueItem>,

    resolved_rules: Vec<ResolvedRule>,

    account_unique_id: AccountUniqueId,
    project_unique_id: ProjectUniqueId,
    rules_counter: AccountCounters,

    languages: Option<Languages>,
}

#[derive(Clone, Debug)]
enum Rescuable {
    Exception {
        exception: Exception,
        data: HashMap<SmolStr, SmolStr>,
    },
    StatusCode(StatusCode),
}

impl Rescuable {
    fn data(&self) -> Option<&HashMap<SmolStr, SmolStr>> {
        match self {
            Rescuable::Exception { data, .. } => Some(data),
            Rescuable::StatusCode(_) => None,
        }
    }
}

#[must_use]
#[derive(Debug)]
enum ResolvedHandlerProcessingResult {
    Processed { cache_mode: RuleCacheMode },
    FiltersNotMatched,
    NextHandler,
}

fn container_scope_to_log(container_scope: &ContainerScope) -> ScopeLog {
    match container_scope {
        ContainerScope::Inline { scope } | ContainerScope::Referenced { scope } => match scope {
            Scope::ProjectConfig => ScopeLog::ProjectConfig,
            Scope::ClientConfig { config, revision } => ScopeLog::ClientConfig {
                config_name: config.clone(),
                revision: *revision,
            },
            Scope::ProjectMount { mount_point } => ScopeLog::ProjectMount {
                mount_point: mount_point.clone(),
            },
            Scope::ClientMount {
                config,
                revision,
                mount_point,
            } => ScopeLog::ClientMount {
                config_name: config.clone(),
                revision: *revision,
                mount_point: mount_point.clone(),
            },
            Scope::ProjectHandler {
                mount_point,
                handler,
            } => ScopeLog::ProjectHandler {
                mount_point: mount_point.clone(),
                handler_name: handler.clone(),
            },
            Scope::ClientHandler {
                config,
                revision,
                mount_point,
                handler,
            } => ScopeLog::ClientHandler {
                config_name: config.clone(),
                revision: *revision,
                mount_point: mount_point.clone(),
                handler_name: handler.clone(),
            },
            Scope::ProjectRule {
                mount_point,
                handler,
                rule_num,
            } => ScopeLog::ProjectRule {
                mount_point: mount_point.clone(),
                handler_name: handler.clone(),
                rule_num: *rule_num,
            },
            Scope::ClientRule {
                config,
                revision,
                mount_point,
                handler,
                rule_num,
            } => ScopeLog::ClientRule {
                config_name: config.clone(),
                revision: *revision,
                mount_point: mount_point.clone(),
                handler_name: handler.clone(),
                rule_num: *rule_num,
            },
        },
        ContainerScope::Parameter { name } => ScopeLog::Parameter {
            parameter_name: name.clone(),
        },
    }
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
                .any(|code| code.as_u16() == status_code.as_u16()),
        }
    }

    fn find_exception_handler(
        rescues: &[ResolvedRescueItem],
        rescuable: &Rescuable,
    ) -> Option<ResolvedRescueItem> {
        for rescue_item in rescues.iter() {
            match (rescuable, &rescue_item.catch) {
                (
                    Rescuable::Exception { exception, .. },
                    ResolvedCatchMatcher::Exception(exception_matcher),
                ) if Self::is_exception_matches(exception_matcher, exception) => {
                    return Some(rescue_item.clone())
                }
                (
                    Rescuable::StatusCode(status_code),
                    ResolvedCatchMatcher::StatusCode(status_code_range),
                ) if Self::is_status_code_matches(status_code_range, status_code) => {
                    return Some(rescue_item.clone())
                }
                _ => {}
            }
        }

        None
    }

    /// Handle exception in the right order
    fn handle_rescuable(
        &self,
        req: &Request<Body>,
        res: &mut Response<Body>,
        requested_url: &http::uri::Uri,
        mut rescuable: Rescuable,
        cache_mode: &RuleCacheMode,
        is_in_exception: bool,
        rescues: &[ResolvedRescueItem],
        language: &Option<LanguageTag>,
        log_message_container: &Arc<parking_lot::Mutex<LogMessageSendOnDrop>>,
    ) -> ResolvedHandlerProcessingResult {
        if let Rescuable::Exception { exception, data } = &rescuable {
            log_message_container
                .lock()
                .as_mut()
                .steps
                .push(ProcessingStep::ThrowException(ExceptionProcessingStep {
                    exception: exception.clone(),
                    handler_name: Some(SmolStr::from(&self.handler_name)),
                    data: data.clone(),
                }));
        }

        let mut maybe_resolved_rescue_item = Self::find_exception_handler(rescues, &rescuable);
        let mut collected_data: HashMap<SmolStr, SmolStr> = if let Some(d) = rescuable.data() {
            d.clone()
        } else {
            Default::default()
        };

        let result = loop {
            // iterate over the chain of exceptions

            if let Some(rescue_item) = maybe_resolved_rescue_item {
                // some catch block is found

                let catch_step = match (&rescuable, &rescue_item.catch) {
                    (
                        Rescuable::Exception { exception, .. },
                        ResolvedCatchMatcher::Exception(exception_matcher),
                    ) => CatchProcessingStep {
                        catch_matcher: exception_matcher.to_string(),
                        variant: CatchProcessingVariantStep::Exception {
                            exception: exception.to_string(),
                        },
                        scope: container_scope_to_log(&rescue_item.container_scope),
                    },
                    (
                        Rescuable::StatusCode(status_code),
                        ResolvedCatchMatcher::StatusCode(status_code_range),
                    ) => CatchProcessingStep {
                        catch_matcher: status_code_range.to_string(),
                        variant: CatchProcessingVariantStep::StatusCode {
                            status_code: *status_code,
                        },
                        scope: container_scope_to_log(&rescue_item.container_scope),
                    },
                    r => {
                        unreachable!("BAD rescuable matching => {:?}", r)
                    }
                };

                log_message_container
                    .lock()
                    .as_mut()
                    .steps
                    .push(ProcessingStep::CatchException(catch_step));

                match rescue_item.handle {
                    ResolvedCatchAction::Throw {
                        exception,
                        data: rethrow_data,
                        rescues,
                    } => {
                        collected_data
                            .extend(rethrow_data.iter().map(|(a, b)| (a.clone(), b.clone())));

                        let rethrow = Rescuable::Exception {
                            exception: exception.clone(),
                            data: rethrow_data.clone(),
                        };

                        rescuable = rethrow;

                        log_message_container.lock().as_mut().steps.push(
                            ProcessingStep::ThrowException(ExceptionProcessingStep {
                                exception: exception.clone(),
                                // FIXME
                                handler_name: None,
                                data: collected_data.clone(),
                            }),
                        );

                        maybe_resolved_rescue_item =
                            Self::find_exception_handler(&rescues, &rescuable);

                        match maybe_resolved_rescue_item {
                            Some(_) => {
                                continue;
                            }
                            None => match &rescuable {
                                Rescuable::Exception { .. } => {
                                    break RescuableHandleResult::UnhandledException {
                                        exception_name: exception,
                                        data: collected_data.clone(),
                                    };
                                }
                                Rescuable::StatusCode(_) => {
                                    break RescuableHandleResult::FinishProcessing {
                                        cache_mode: cache_mode.clone(),
                                    }
                                }
                            },
                        }
                    }
                    ResolvedCatchAction::StaticResponse(ResolvedStaticResponseAction {
                        static_response,
                        rescues,
                    }) => {
                        if let Ok(resp) = &static_response {
                            collected_data
                                .extend(resp.data.iter().map(|(a, b)| (a.clone(), b.clone())));
                        }

                        // FIXME: this will probably break data merging if static-resp is involved
                        // FIXME: merged data should be stored to the container, so that on exception new exception queue is processed
                        break RescuableHandleResult::StaticResponse(
                            ResolvedStaticResponseAction {
                                static_response,
                                rescues,
                            },
                        );
                    }
                    ResolvedCatchAction::NextHandler { scope } => {
                        break RescuableHandleResult::NextHandler { scope }
                    }
                }
            } else {
                match &rescuable {
                    Rescuable::Exception { exception, data } => {
                        collected_data.extend(data.iter().map(|(a, b)| (a.clone(), b.clone())));
                        break RescuableHandleResult::UnhandledException {
                            exception_name: exception.clone(),
                            data: collected_data.clone(),
                        };
                    }
                    Rescuable::StatusCode(_) => {
                        break RescuableHandleResult::FinishProcessing {
                            cache_mode: cache_mode.clone(),
                        }
                    }
                }
            }
        };

        match result {
            RescuableHandleResult::StaticResponse(action) => action.handle_static_response(
                self,
                req,
                res,
                requested_url,
                Some(&collected_data),
                None,
                is_in_exception,
                &language,
                log_message_container,
            ),
            RescuableHandleResult::NextHandler { .. } => {
                ResolvedHandlerProcessingResult::NextHandler
            }
            RescuableHandleResult::UnhandledException { .. } => {
                self.respond_server_error(res);
                ResolvedHandlerProcessingResult::Processed {
                    cache_mode: Default::default(),
                }
            }
            RescuableHandleResult::FinishProcessing { cache_mode } => {
                ResolvedHandlerProcessingResult::Processed { cache_mode }
            }
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
        &RuleCacheMode,
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

    fn resolve_handler_invocation_result(
        &self,
        invocation_result: HandlerInvocationResult,
        req: &mut Request<Body>,
        res: &mut Response<Body>,
        cache_mode: &RuleCacheMode,
        requested_url: &http::uri::Uri,
        language: &Option<LanguageTag>,
        log_message_container: &Arc<parking_lot::Mutex<LogMessageSendOnDrop>>,
        filter_matches: HashMap<SmolStr, Matched>,
        rescues: &[ResolvedRescueItem],
        on_response: &[OnResponse],
    ) -> ResolvedHandlerProcessingResult {
        match invocation_result {
            HandlerInvocationResult::Responded => {
                for modification in on_response {
                    if modification.when.status_code.is_belongs(&res.status()) {
                        match apply_headers(
                            res.headers_mut(),
                            &modification.modifications.headers,
                            &filter_matches,
                            language,
                        ) {
                            Ok(_) => {}
                            Err(ex) => {
                                let rescuable = Rescuable::Exception {
                                    exception: ex,
                                    data: Default::default(),
                                };

                                return self.handle_rescuable(
                                    req,
                                    res,
                                    requested_url,
                                    rescuable,
                                    &Default::default(),
                                    false,
                                    rescues,
                                    &language,
                                    log_message_container,
                                );
                            }
                        }
                    }
                }

                let rescuable = Rescuable::StatusCode(res.status());

                self.handle_rescuable(
                    req,
                    res,
                    requested_url,
                    rescuable,
                    cache_mode,
                    false,
                    rescues,
                    &language,
                    log_message_container,
                )
            }
            HandlerInvocationResult::ToNextHandler => ResolvedHandlerProcessingResult::NextHandler,
            HandlerInvocationResult::Exception { name, data } => {
                let rescuable = Rescuable::Exception {
                    exception: name,
                    data,
                };
                self.handle_rescuable(
                    req,
                    res,
                    requested_url,
                    rescuable,
                    &Default::default(),
                    false,
                    rescues,
                    &language,
                    log_message_container,
                )
            }
        }
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
        language: &Option<LanguageTag>,
        invocation_log: Arc<parking_lot::Mutex<CacheableInvocationProcessingStep>>,
        log_message_container: &Arc<parking_lot::Mutex<LogMessageSendOnDrop>>,
    ) -> ResolvedHandlerProcessingResult {
        if let Some(invocation_result) = self
            .resolved_variant
            .try_handle_service_paths(req, res, requested_url, language, log_message_container)
            .await
        {
            return self.resolve_handler_invocation_result(
                invocation_result,
                req,
                res,
                &Default::default(),
                requested_url,
                language,
                log_message_container,
                Default::default(),
                &self.rescues,
                &[],
            );
        }

        let (
            filter_matches,
            skip_segments,
            action,
            cache_mode,
            request_modification,
            response_modification,
        ) = match self.find_action(rebased_url, req.method()) {
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
                let replaced = match segment.substitute(&filter_matches, language) {
                    Err(e) => {
                        let mut data = HashMap::new();
                        data.insert("error".into(), e.to_string().into());

                        let rescuable = Rescuable::Exception {
                            exception: MODIFICATION_ERROR.clone(),
                            data,
                        };

                        return self.handle_rescuable(
                            req,
                            res,
                            requested_url,
                            rescuable,
                            cache_mode,
                            false,
                            &action.rescues(),
                            &language,
                            log_message_container,
                        );
                    }
                    Ok(replaced) => replaced,
                };

                match replaced {
                    Replaced::Multiple(multiple) => {
                        for s in multiple {
                            modified_url.push_segment(&s);
                        }
                    }
                    Replaced::Single(single) => {
                        modified_url.push_segment(&single);
                    }
                    Replaced::Empty => {
                        // Push nothing
                    }
                }
            }
        }

        match request_modification.trailing_slash {
            TrailingSlashModification::Keep => {
                modified_url.ensure_trailing_slash(requested_url.path().ends_with('/'));
            }
            TrailingSlashModification::Set => modified_url.ensure_trailing_slash(true),
            TrailingSlashModification::Unset => modified_url.ensure_trailing_slash(false),
        }

        match apply_headers(
            req.headers_mut(),
            &request_modification.headers,
            &filter_matches,
            language,
        ) {
            Ok(()) => {}
            Err(ex) => {
                let rescuable = Rescuable::Exception {
                    exception: ex,
                    data: Default::default(),
                };
                return self.handle_rescuable(
                    req,
                    res,
                    requested_url,
                    rescuable,
                    cache_mode,
                    false,
                    &action.rescues(),
                    &language,
                    log_message_container,
                );
            }
        }

        match request_modification.modify_query.add_query(
            &mut modified_url,
            &query_modifications,
            &filter_matches,
            language,
        ) {
            Ok(()) => {}
            Err(ex) => {
                let mut data: HashMap<SmolStr, SmolStr> = Default::default();
                data.insert("error".into(), ex.to_string().into());

                let rescuable = Rescuable::Exception {
                    exception: MODIFICATION_ERROR.clone(),
                    data,
                };

                return self.handle_rescuable(
                    req,
                    res,
                    requested_url,
                    rescuable,
                    cache_mode,
                    false,
                    &action.rescues(),
                    &language,
                    log_message_container,
                );
            }
        }

        match action {
            ResolvedRuleAction::Invoke { rescues, .. } => {
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
                        invocation_log.clone(),
                        log_message_container,
                    )
                    .await;

                if let HandlerInvocationResult::Responded = invocation_result {
                    if invocation_log.lock().is_not_empty() {
                        // handler saved cacheable invocation result. Save it to logs

                        log_message_container
                            .lock()
                            .as_mut()
                            .steps
                            .push(ProcessingStep::Invoke(invocation_log));
                    }
                }

                self.resolve_handler_invocation_result(
                    invocation_result,
                    req,
                    res,
                    cache_mode,
                    requested_url,
                    language,
                    log_message_container,
                    filter_matches,
                    rescues,
                    response_modification,
                )
            }
            ResolvedRuleAction::NextHandler => {
                return ResolvedHandlerProcessingResult::NextHandler;
            }
            ResolvedRuleAction::Throw { exception, data } => {
                let rescuable = Rescuable::Exception {
                    exception: exception.clone(),
                    data: data.clone(),
                };
                return self.handle_rescuable(
                    req,
                    res,
                    requested_url,
                    rescuable,
                    cache_mode,
                    false,
                    &self.rescues,
                    &language,
                    log_message_container,
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
                    log_message_container,
                );
            }
        }
    }
}

fn apply_headers(
    headers: &mut HeaderMap<HeaderValue>,
    modification: &ModifyHeaders,
    filter_matches: &HashMap<SmolStr, Matched>,
    language: &Option<LanguageTag>,
) -> Result<(), Exception> {
    for (header_name, header_value) in &modification.append.0 {
        let substituted = substitute_str_with_filter_matches(
            header_value.to_str().unwrap(),
            filter_matches,
            language,
        )
        .map_err(|_e| MODIFICATION_ERROR.clone())?;

        headers.append(
            header_name.clone(),
            substituted.to_string().parse().unwrap(),
        );
    }
    for (header_name, header_value) in &modification.insert.0 {
        let substituted = substitute_str_with_filter_matches(
            header_value.to_str().unwrap(),
            filter_matches,
            language,
        )
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
enum RescuableHandleResult {
    /// Respond with static response
    StaticResponse(ResolvedStaticResponseAction),
    /// Move on to next handler
    NextHandler { scope: Scope },
    /// Exception hasn't been handled by ant of handlers
    UnhandledException {
        exception_name: Exception,
        data: HashMap<SmolStr, SmolStr>,
    },
    /// Finish processing normally, respond with prepared response
    FinishProcessing { cache_mode: RuleCacheMode },
}

fn resolve_static_response(
    static_response_container: Container<StaticResponse, StaticResponseName>,
    status_code: &Option<exogress_common::config_core::StatusCode>,
    data: &BTreeMap<SmolStr, SmolStr>,
    params: &HashMap<ParameterName, Parameter>,
    refined: &RefinableSet,
    current_scope: &Scope,
) -> Result<ResolvedStaticResponse, referenced::Error> {
    let (static_response, static_response_scope) =
        static_response_container.resolve(params, refined, current_scope)?;

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

        container_scope: static_response_scope,
    };

    Ok(resolved)
}

fn resolve_catch_action(
    client_config_info: &Option<(ConfigName, ClientConfigRevision)>,
    params: &HashMap<ParameterName, Parameter>,
    catch_action: &CatchAction,
    refinable_set: &RefinableSet,
    rescue_item_scope: &Scope,
    current_scope: &Scope,
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
                rescue_item_scope,
            ),
            rescues: if let Some(prev_scope) = current_scope.prev(client_config_info) {
                resolve_rescue_items(client_config_info, &params, &refinable_set, &prev_scope)?
            } else {
                Default::default()
            },
        }),
        CatchAction::Throw { exception, data } => ResolvedCatchAction::Throw {
            exception: exception.clone(),
            data: data.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            rescues: if let Some(prev_scope) = current_scope.prev(client_config_info) {
                resolve_rescue_items(client_config_info, &params, &refinable_set, &prev_scope)?
            } else {
                Default::default()
            },
        },
        CatchAction::NextHandler => ResolvedCatchAction::NextHandler {
            scope: rescue_item_scope.clone(),
        },
    })
}

fn resolve_rescue_items(
    client_config_info: &Option<(ConfigName, ClientConfigRevision)>,
    params: &HashMap<ParameterName, Parameter>,
    refinable_set: &RefinableSet,
    current_scope: &Scope,
) -> Option<Vec<ResolvedRescueItem>> {
    let available_exception_handlers = refinable_set.joined_for_scope(current_scope);

    available_exception_handlers
        .rescue
        .iter()
        .map(|(rescue_item, rescue_item_scope)| {
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
                    rescue_item_scope,
                    current_scope,
                )?,
                container_scope: ContainerScope::Inline {
                    scope: rescue_item_scope.clone(),
                },
            })
        })
        .collect::<Option<_>>()
}
impl RequestsProcessor {
    pub fn new(
        resp: ConfigsResponse,
        google_oauth2_client: super::auth::google::GoogleOauth2Client,
        github_oauth2_client: super::auth::github::GithubOauth2Client,
        gcs_credentials_file: String,
        assistant_base_url: Url,
        transformer_base_url: Url,
        client_tunnels: ClientTunnels,
        rules_counter: AccountCounters,
        individual_hostname: SmolStr,
        maybe_identity: Option<Vec<u8>>,
        public_counters_tx: tokio::sync::mpsc::Sender<RecordedTrafficStatistics>,
        log_messages_tx: tokio::sync::mpsc::UnboundedSender<LogMessage>,
        gw_location: &str,
        cache: Cache,
        presence_client: presence::Client,
        dbip: Option<GeoipReader>,
        resolver: TokioAsyncResolver,
    ) -> anyhow::Result<RequestsProcessor> {
        let xchacha20poly1305_secret_key =
            xchacha20poly1305::Key::from_slice(&hex::decode(&resp.xchacha20poly1305_secret_key)?)
                .ok_or_else(|| anyhow!("could not parse xchacha20poly1305 secret key"))?;

        crate::statistics::ACTIVE_REQUESTS_PROCESSORS.inc();

        let max_pop_cache_size_bytes = resp.max_pop_cache_size_bytes;
        let traffic_counters = TrafficCounters::new(resp.account_unique_id, resp.project_unique_id);

        let refinable = Arc::new(resp.refinable());

        let grouped = resp.configs.iter().group_by(|item| &item.config_name);

        let jwt_ecdsa = JwtEcdsa {
            private_key: resp.jwt_ecdsa.private_key.into(),
            public_key: resp.jwt_ecdsa.public_key.into(),
        };

        let mount_point_fqdn = resp.fqdn;
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
                    .map(|entry| (entry.instances.len(), entry))
                    .sorted_by(|(left, _), (right, _)| left.cmp(&right).reverse())
                    .into_iter()
                    .next() //keep only revision with largest number of instances
                    .unwrap()
                    .1;

                let config = &entry.config;
                let config_revision = &entry.revision;
                let instances = entry.instances.clone();
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
                                Some(*config_revision),
                                Some(upstreams.clone()),
                                Some(instances.clone()),
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
            .get(0)
            .ok_or_else(|| anyhow!("no mount points returned"))?
            .0
            .clone();

        // let project_static_responses = resp.project_config.refinable.static_responses.clone();
        //
        let mut merged_resolved_handlers = vec![];
        let public_client = hyper::Client::builder().build::<_, Body>(MeteredHttpConnector {
            public_counters_tx: public_counters_tx.clone(),
            resolver: resolver.clone(),
            counters: traffic_counters.clone(),
            sent_counter: crate::statistics::PUBLIC_ENDPOINT_BYTES_SENT.clone(),
            recv_counter: crate::statistics::PUBLIC_ENDPOINT_BYTES_RECV.clone(),
            maybe_identity: None,
        });
        let int_metered_client = hyper::Client::builder().build::<_, Body>(MeteredHttpConnector {
            public_counters_tx: public_counters_tx.clone(),
            resolver: resolver.clone(),
            counters: traffic_counters.clone(),
            sent_counter: crate::statistics::PUBLIC_ENDPOINT_BYTES_SENT.clone(),
            recv_counter: crate::statistics::PUBLIC_ENDPOINT_BYTES_RECV.clone(),
            maybe_identity: maybe_identity.clone(),
        });

        for (_mp_name, (config_name, config_revision, upstreams, instances, active_profile, mp)) in
            grouped_mount_points.into_iter()
        {
            shadow_clone!(
                instances,
                jwt_ecdsa,
                mount_point_fqdn,
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
                presence_client,
                params,
                active_profile
            );

            let client_config_info = config_name.clone().zip(config_revision);

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
                    shadow_clone!(active_profile, mount_point_name, refinable, public_client, public_counters_tx, resolver, traffic_counters);

                    move |(handler_name, handler)| {
                        let replace_base_path = handler
                            .variant
                            .rebase()
                            .map(|r| r.replace_base_path.clone())
                            .unwrap_or_default();

                        let handler_scope = Scope::handler(
                            config_name.clone().zip(config_revision),
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
                                        mount_point_fqdn: mount_point_fqdn.clone(),
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
                                                is_png: static_dir.post_processing.image_optimization.enabled && static_dir.post_processing.image_optimization.png,
                                                is_jpeg: static_dir.post_processing.image_optimization.enabled && static_dir.post_processing.image_optimization.jpeg,
                                            }
                                        },
                                        config: static_dir,
                                        handler_name: handler_name.clone(),
                                        instances: instances
                                            .as_ref()
                                            .expect("try to access instances on project-level config")
                                            .iter()
                                            .map(|(instance_id, instance_info)| {
                                                (*instance_id, instance_info.labels.clone())
                                            })
                                            .collect(),
                                        balancer: {
                                            let mut balancer = SmoothWeight::<InstanceId>::new();

                                            let instance_ids = instances
                                                .as_ref()
                                                .expect("[BUG] try to access instance_ids on project-level config")
                                                .keys();

                                            for instance_id in instance_ids {
                                                balancer.add(*instance_id, 1);
                                            }

                                            Mutex::new(balancer)
                                        },
                                        client_tunnels: client_tunnels.clone(),
                                        config_id: ConfigId {
                                            account_name: account_name.clone(),
                                            account_unique_id,
                                            project_name: project_name.clone(),
                                            config_name: config_name.as_ref().expect("[BUG] try to access config_name on project-level config").clone(),
                                        },
                                        individual_hostname: individual_hostname.clone(),
                                        public_hostname: mount_point_fqdn.to_string().into(),
                                    })
                                }
                                ClientHandlerVariant::Proxy(proxy) => {
                                    ResolvedHandlerVariant::Proxy(proxy::ResolvedProxy {
                                        handler_name: handler_name.clone(),
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
                                                is_png: proxy.post_processing.image_optimization.enabled && proxy.post_processing.image_optimization.png,
                                                is_jpeg: proxy.post_processing.image_optimization.enabled && proxy.post_processing.image_optimization.jpeg,
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
                                        instances: instances
                                            .as_ref()
                                            .expect("[BUG] try to access instances on project-level config")
                                            .iter()
                                            .map(|(instance_id, instance_info)| {
                                                (*instance_id, instance_info.labels.clone())
                                            })
                                            .collect(),
                                        balancer: {
                                            let mut balancer = SmoothWeight::<InstanceId>::new();
                                            let instances = instances
                                                .as_ref()
                                                .expect("[BUG] try to access instance_ids on project-level config")
                                                .iter();
                                            for (instance_id, instance_info) in instances {
                                                if instance_info.upstreams.get(&proxy.upstream) == Some(&true) {
                                                    balancer.add(*instance_id, 1);
                                                }
                                            }

                                            Mutex::new(balancer)
                                        },
                                        client_tunnels: client_tunnels.clone(),
                                        config_id: ConfigId {
                                            account_name: account_name.clone(),
                                            account_unique_id,
                                            project_name: project_name.clone(),
                                            config_name: config_name.as_ref().expect("[BUG] try to access config_name on project-level config").clone(),
                                        },
                                        individual_hostname: individual_hostname.clone(),
                                        public_hostname: mount_point_fqdn.to_string().into(),
                                        presence_client: presence_client.clone(),
                                        is_cache_enabled: proxy.cache.enabled,
                                        is_websockets_enabled: proxy.websockets,
                                    })
                                }
                                ClientHandlerVariant::S3Bucket(s3_bucket) => {
                                    ResolvedHandlerVariant::S3Bucket(s3_bucket::ResolvedS3Bucket {
                                        handler_name: handler_name.clone(),
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
                                                is_png: s3_bucket.post_processing.image_optimization.enabled && s3_bucket.post_processing.image_optimization.png,
                                                is_jpeg: s3_bucket.post_processing.image_optimization.enabled && s3_bucket.post_processing.image_optimization.jpeg,
                                            }
                                        },
                                        client: public_client.clone(),
                                        bucket: {
                                            shadow_clone!(params, s3_bucket);

                                            (move || {
                                                let s3_bucket_cfg = s3_bucket.bucket
                                                    .resolve_non_referenced(
                                                        &params,
                                                    )?;

                                                let bucket = rusty_s3::Bucket::new(
                                                    s3_bucket_cfg.region.endpoint(),
                                                    false,
                                                    s3_bucket_cfg.name.into(),
                                                    s3_bucket_cfg.region.to_string(),
                                                ).ok_or(s3_bucket::BucketError::BadConfig)?;

                                                Ok::<_, s3_bucket::BucketError>(bucket)
                                            })()
                                        },
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
                                        is_cache_enabled: s3_bucket.cache.enabled,
                                    })
                                }
                                ClientHandlerVariant::GcsBucket(gcs_bucket) => {
                                    let bucket = gcs_bucket::ResolvedGcsBucket {
                                        handler_name: handler_name.clone(),
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
                                                is_png: gcs_bucket.post_processing.image_optimization.enabled && gcs_bucket.post_processing.image_optimization.png,
                                                is_jpeg: gcs_bucket.post_processing.image_optimization.enabled && gcs_bucket.post_processing.image_optimization.jpeg,
                                            }
                                        },
                                        client: public_client.clone(),
                                        auth: {
                                            shadow_clone!(params, gcs_bucket);

                                            (move || {
                                                let creds = gcs_bucket.credentials.resolve_non_referenced(
                                                    &params,
                                                )?;
                                                let service_account = tame_oauth::gcp::ServiceAccountInfo::deserialize(
                                                    creds.json.as_str()
                                                )?;
                                                let service_account_access = tame_oauth::gcp::ServiceAccountAccess::new(service_account)?;

                                                Ok::<_, gcs_bucket::AuthError>(service_account_access)
                                            })()
                                        },
                                        bucket_name: gcs_bucket.bucket
                                            .resolve_non_referenced(
                                                &params,
                                            ),
                                        token: Default::default(),
                                        is_cache_enabled: gcs_bucket.cache.enabled,
                                    };

                                    ResolvedHandlerVariant::GcsBucket(bucket)
                                }
                                ClientHandlerVariant::ProxyPublic(proxy_public) => {
                                    let proxy_public = proxy_public::ResolvedProxyPublic {
                                        handler_name: handler_name.clone(),
                                        host: proxy_public.host.clone(),
                                        post_processing: ResolvedPostProcessing {
                                            encoding: ResolvedEncoding {
                                                mime_types: proxy_public
                                                    .post_processing
                                                    .encoding
                                                    .mime_types
                                                    .clone()
                                                    .resolve_non_referenced(
                                                        &params,
                                                    )
                                                    .map(|m| m.0.iter().map(|mt| mt.0.essence_str().into()).collect()),
                                                brotli: proxy_public.post_processing.encoding.brotli,
                                                gzip: proxy_public.post_processing.encoding.gzip,
                                                deflate: proxy_public.post_processing.encoding.deflate,
                                                min_size: proxy_public.post_processing.encoding.min_size,
                                            },
                                            image: ResolvedImage {
                                                is_png: proxy_public.post_processing.image_optimization.enabled && proxy_public.post_processing.image_optimization.png,
                                                is_jpeg: proxy_public.post_processing.image_optimization.enabled && proxy_public.post_processing.image_optimization.jpeg,
                                            }
                                        },
                                        client: public_client.clone(),
                                        is_cache_enabled: proxy_public.cache.enabled,
                                        public_counters_tx: public_counters_tx.clone(),
                                        resolver: resolver.clone(),
                                        counters: traffic_counters.clone(),
                                        sent_counter: crate::statistics::PUBLIC_ENDPOINT_BYTES_SENT.clone(),
                                        recv_counter: crate::statistics::PUBLIC_ENDPOINT_BYTES_RECV.clone(),
                                        is_websockets_enabled: proxy_public.websockets,
                                        individual_hostname: individual_hostname.clone(),
                                        public_hostname: mount_point_fqdn.to_string().into(),
                                    };

                                    ResolvedHandlerVariant::ProxyPublic(proxy_public)
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
                            rescues: resolve_rescue_items(
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
                                        config_name.clone().zip(config_revision),
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
                                                rescues: {
                                                    resolve_rescue_items(
                                                        &client_config_info,
                                                        &params,
                                                        &refinable,
                                                        &rule_scope,
                                                    )?
                                                },
                                                scope: handler_scope.clone(),
                                            },
                                            Action::NextHandler => ResolvedRuleAction::NextHandler,
                                            Action::Throw { exception, data } => ResolvedRuleAction::Throw {
                                                exception,
                                                data: data.iter().map(|(k,v)| (k.as_str().into(), v.as_str().into())).collect(),
                                            },
                                            Action::Respond {
                                                static_response, status_code, data, ..
                                            } => ResolvedRuleAction::Respond(Box::new(ResolvedStaticResponseAction {
                                                static_response: resolve_static_response(
                                                    static_response,
                                                    &status_code,
                                                    &data,
                                                    &params,
                                                    &refinable,
                                                    &rule_scope
                                                ),
                                                rescues: resolve_rescue_items(
                                                    &client_config_info,
                                                    &params,
                                                    &refinable,
                                                    &rule_scope,
                                                )?,
                                            })),
                                        },
                                        cache_mode: rule.cache,
                                    })
                                })
                                .collect::<Option<_>>()?,
                            account_unique_id,
                            project_unique_id,
                            rules_counter: rules_counter.clone(),
                            languages: handler.languages,
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
            is_transformations_limited: resp.is_transformations_limited,
            ordered_handlers: if resp.is_active {
                merged_resolved_handlers
            } else {
                vec![]
            },
            project_unique_id,
            generated_at: resp.generated_at,
            google_oauth2_client,
            github_oauth2_client,
            assistant_base_url,
            maybe_identity: maybe_identity.clone(),
            strict_transport_security: resp.strict_transport_security,
            rules_counter,
            account_unique_id,
            cache,
            project_name,
            fqdn: mount_point_fqdn,
            mount_point_name,
            xchacha20poly1305_secret_key,
            max_pop_cache_size_bytes,
            gw_location: gw_location.into(),
            transformer_client: TransformerClient::new(
                account_unique_id,
                transformer_base_url,
                gcs_credentials_file,
                int_metered_client,
                maybe_identity,
            )?,
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
        language: &Option<LanguageTag>,
    ) -> anyhow::Result<Replaced> {
        match matches {
            None => Ok(Replaced::Single(segment.0.clone())),
            Some(matches) => Ok(segment.substitute(matches, language)?),
        }
    }

    pub fn to_destination_string(
        &self,
        query_pairs: &LinkedHashMap<String, String>,
        query_modify: &ResolvedModifyQuery,
        filter_matches: Option<&HashMap<SmolStr, Matched>>,
        language: &Option<LanguageTag>,
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
                    let replaced = Self::replace_segment(segment, filter_matches, language)?;
                    replaced.push_to_url(&mut url);
                }
                (url, false)
            }
            ResolvedModifieableRedirectTo::Segments(segments) => {
                let mut url = http::Uri::from_static("http://base");
                for segment in segments {
                    let replaced = Self::replace_segment(segment, filter_matches, language)?;
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
                    language,
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
    container_scope: ContainerScope,
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
        handler_best_language: &Option<LanguageTag>,
        facts: Arc<Mutex<serde_json::Value>>,
        language: &Option<LanguageTag>,
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
                language,
            ) {
                Ok(s) => {
                    res.headers_mut().insert(LOCATION, s.parse().unwrap());
                }
                Err(_e) => {
                    return Err((
                        exceptions::STATIC_RESPONSE_REDIRECT_ERROR.clone(),
                        merged_data,
                    ));
                }
            }
        }

        *res.status_mut() = self.status_code;

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
                    merged_data,
                ));
            }
            (Ok(None), _) => {
                return Err((
                    exceptions::STATIC_RESPONSE_NO_ACCEPT_HEADER.clone(),
                    merged_data,
                ));
            }
        };

        match best_content_type {
            Some((resp_content_type, resp)) => {
                res.headers_mut()
                    .typed_insert::<ContentType>(&ContentType(resp_content_type));
                let body = match &resp.engine {
                    None => resp.content.to_string(),

                    Some(TemplateEngine::Handlebars) => {
                        let handlebars = Handlebars::new();

                        let rendering_data = json!({
                            "data": merged_data,
                            "language": handler_best_language,
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
    container_scope: ContainerScope,
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
