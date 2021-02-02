use crate::http_serve::cache::cache_scope::ResolvedCacheScope;
use crate::http_serve::cache::{Cache, HandlerChecksum};
use crate::http_serve::requests_processor::ResolvedHandler;
use byte_unit::Byte;
use exogress_common::config_core::{CacheScope, ClientConfigRevision};
use exogress_common::entities::{
    AccountUniqueId, HandlerName, InstanceId, MountPointName, ProjectName,
};
use exogress_server_common::logging::{LogMessage, ProcessingStep};
use http::{Method, Request, Response, StatusCode};
use hyper::Body;
use pin_utils::core_reexport::fmt::Formatter;
use sodiumoxide::crypto::secretstream::xchacha20poly1305;
use std::fmt;
use typed_headers::HeaderMapExt;

#[derive(Clone)]
pub struct Cacheable {
    pub cache: Cache,
    pub account_unique_id: AccountUniqueId,
    pub project_name: ProjectName,
    pub mount_point_name: MountPointName,
    pub handler_name: HandlerName,
    pub handler_checksum: HandlerChecksum,
    pub xchacha20poly1305_secret_key: xchacha20poly1305::Key,
    pub cache_config: exogress_common::config_core::Cache,
    pub config_revision: Option<ClientConfigRevision>,
}

impl fmt::Debug for Cacheable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cacheable")
            .field("account_unique_id", &self.account_unique_id)
            .field("project_name", &self.project_name)
            .field("mount_point_name", &self.mount_point_name)
            .field("handler_name", &self.handler_name)
            .field("handler_checksum", &self.handler_checksum)
            .field("cache_config", &self.cache_config)
            .field("config_revision", &self.config_revision)
            .finish()
    }
}

impl Cacheable {
    pub async fn try_serve_from_cache(
        &self,
        req: &Request<Body>,
        res: &mut Response<Body>,
        instance_id: InstanceId,
        log_message: &mut LogMessage,
    ) -> bool {
        if self.cache_config.enabled == false {
            return false;
        }

        if req.method() == &Method::GET || req.method() == &Method::HEAD {
            // eligible for caching
            // lookup for cache response and respond if exists

            let cache_scope = ResolvedCacheScope {
                config_revision: None,
                instance_id: None,
            };

            let cached_response = self
                .cache
                .serve_from_cache(
                    &self.account_unique_id,
                    &self.project_name,
                    &self.mount_point_name,
                    &self.handler_name,
                    &self.handler_checksum,
                    cache_scope,
                    req.headers(),
                    req.method(),
                    req.uri().path_and_query().expect("FIXME").as_str(),
                    &self.xchacha20poly1305_secret_key,
                )
                .await;

            match cached_response {
                Ok(Some(resp)) => {
                    if resp.status().is_success() || resp.status() == StatusCode::NOT_MODIFIED {
                        // respond from the cache only if success response

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

                        return true;
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
        };

        false
    }
}
