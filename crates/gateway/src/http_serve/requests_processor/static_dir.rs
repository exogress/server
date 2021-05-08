use crate::{
    clients::{ClientTunnels, HttpConnector},
    http_serve::{
        logging::{save_body_info_to_log_message, LogMessageSendOnDrop},
        requests_processor::{
            helpers::{
                add_forwarded_headers, copy_headers_from_proxy_res_to_res,
                copy_headers_to_proxy_req,
            },
            post_processing::ResolvedPostProcessing,
            HandlerInvocationResult,
        },
    },
};
use chrono::Utc;
use core::fmt;
use exogress_common::{
    config_core::StaticDir,
    entities::{exceptions, ConfigId, HandlerName, InstanceId, LabelName, LabelValue},
    tunnel::ConnectTarget,
};
use exogress_server_common::logging::{
    HttpBodyLog, InstanceLog, ProxyAttemptLogMessage, ProxyOriginResponseInfo,
    ProxyRequestToOriginInfo, StaticDirHandlerLogMessage,
};
use hashbrown::HashMap;
use http::{Method, Request, Response};
use hyper::Body;
use langtag::LanguageTagBuf;
use parking_lot::Mutex;
use smol_str::SmolStr;
use std::{net::SocketAddr, sync::Arc};
use weighted_rs::{SmoothWeight, Weight};

pub struct ResolvedStaticDir {
    pub config: StaticDir,
    pub handler_name: HandlerName,
    pub instances: HashMap<InstanceId, HashMap<LabelName, LabelValue>>,
    pub balancer: Mutex<SmoothWeight<InstanceId>>,
    pub client_tunnels: ClientTunnels,
    pub config_id: ConfigId,
    pub individual_hostname: SmolStr,
    pub public_hostname: SmolStr,
    pub is_cache_enabled: bool,
    pub post_processing: ResolvedPostProcessing,
}

impl fmt::Debug for ResolvedStaticDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedStaticDir")
            .field("config", &self.config)
            .field("handler_name", &self.handler_name)
            .field("config_id", &self.config_id)
            .field("is_cache_enabled", &self.is_cache_enabled)
            .finish()
    }
}

impl ResolvedStaticDir {
    pub async fn invoke(
        &self,
        req: &Request<Body>,
        res: &mut Response<Body>,
        _requested_url: &http::uri::Uri,
        rebased_url: &http::uri::Uri,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        language: &Option<LanguageTagBuf>,
        handler_log: &mut Option<StaticDirHandlerLogMessage>,
        log_message_container: &Arc<parking_lot::Mutex<LogMessageSendOnDrop>>,
    ) -> HandlerInvocationResult {
        if req.headers().contains_key("x-exg-proxied") {
            return HandlerInvocationResult::Exception {
                name: exceptions::PROXY_LOOP_DETECTED.clone(),
                data: Default::default(),
            };
        }

        if req.method() != Method::GET && req.method() != Method::HEAD {
            return HandlerInvocationResult::ToNextHandler;
        }

        let instance_id = try_option_or_exception!(
            Weight::next(&mut *self.balancer.lock()),
            exceptions::PROXY_NO_INSTANCES
        );

        let labels = self.instances.get(&instance_id).expect(
            "should never happen. instance exist in balancer, but doesn't exist in hashmap",
        );

        let proxy_response_body = HttpBodyLog::default();

        *handler_log = Some(StaticDirHandlerLogMessage {
            handler_name: self.handler_name.clone(),
            config_name: self.config_id.config_name.clone(),
            language: language.clone(),
            attempts: vec![ProxyAttemptLogMessage {
                attempt: 0,
                attempted_at: Utc::now(),
                instance: Some(InstanceLog {
                    instance_id,
                    labels: labels.clone(),
                }),
                request: ProxyRequestToOriginInfo {
                    body: Default::default(),
                },
                response: ProxyOriginResponseInfo {
                    body: proxy_response_body.clone(),
                },
            }],
        });

        let mut proxy_to = rebased_url.clone();

        let connect_target = ConnectTarget::Internal(self.handler_name.clone());
        connect_target.update_url(&mut proxy_to);

        let mut proxy_req = Request::<Body>::new(Body::empty());
        *proxy_req.method_mut() = req.method().clone();
        *proxy_req.uri_mut() = proxy_to.clone();

        copy_headers_to_proxy_req(req, &mut proxy_req);

        add_forwarded_headers(
            &mut proxy_req,
            local_addr,
            remote_addr,
            &self.public_hostname,
            Some(proxy_to.host().unwrap()),
        );

        proxy_req
            .headers_mut()
            .append("x-exg", "1".parse().unwrap());

        let http_client = try_option_or_exception!(
            self.client_tunnels
                .retrieve_connector::<HttpConnector>(
                    &self.config_id,
                    &instance_id,
                    self.individual_hostname.clone(),
                )
                .await,
            exceptions::PROXY_INSTANCE_UNREACHABLE.clone()
        );

        let proxy_res = try_or_exception!(
            http_client.request(proxy_req).await,
            exceptions::PROXY_UPSTREAM_UNREACHABLE.clone()
        );

        copy_headers_from_proxy_res_to_res(proxy_res.headers(), res);

        res.headers_mut()
            .append("x-exg-proxied", "1".parse().unwrap());
        *res.status_mut() = proxy_res.status();

        let instrumented_response = save_body_info_to_log_message(
            proxy_res.into_body(),
            log_message_container.clone(),
            proxy_response_body,
        );

        *res.body_mut() = instrumented_response;

        HandlerInvocationResult::Responded
    }
}
