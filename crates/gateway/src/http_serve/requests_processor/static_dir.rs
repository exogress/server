use crate::clients::{ClientTunnels, HttpConnector};
use crate::http_serve::requests_processor::cache::Cacheable;
use crate::http_serve::requests_processor::helpers::{
    add_forwarded_headers, copy_headers_from_proxy_res_to_res, copy_headers_to_proxy_req,
};
use crate::http_serve::requests_processor::HandlerInvocationResult;
use core::fmt;
use exogress_common::config_core::StaticDir;
use exogress_common::entities::{ConfigId, HandlerName, InstanceId};
use exogress_common::tunnel::ConnectTarget;
use exogress_server_common::logging::{
    HandlerProcessingStep, LogMessage, ProcessingStep, StaticDirHandlerLogMessage,
};
use http::{Method, Request, Response};
use hyper::Body;
use langtag::LanguageTagBuf;
use parking_lot::Mutex;
use smol_str::SmolStr;
use std::convert::TryInto;
use std::net::SocketAddr;
use weighted_rs::{SmoothWeight, Weight};

pub struct ResolvedStaticDir {
    pub config: StaticDir,
    pub handler_name: HandlerName,
    pub instance_ids: Mutex<SmoothWeight<InstanceId>>,
    pub client_tunnels: ClientTunnels,
    pub config_id: ConfigId,
    pub individual_hostname: SmolStr,
    pub public_hostname: SmolStr,
    pub cacheable: Cacheable,
}

impl fmt::Debug for ResolvedStaticDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedStaticDir")
            .field("config", &self.config)
            .field("handler_name", &self.handler_name)
            .field("config_id", &self.config_id)
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
        log_message: &mut LogMessage,
    ) -> HandlerInvocationResult {
        if req.headers().contains_key("x-exg-proxied") {
            return HandlerInvocationResult::Exception {
                name: "proxy-error:loop-detected".parse().unwrap(),
                data: Default::default(),
            };
        }

        if req.method() != &Method::GET && req.method() != &Method::HEAD {
            return HandlerInvocationResult::ToNextHandler;
        }

        let instance_id = try_option_or_exception!(
            Weight::next(&mut *self.instance_ids.lock()),
            "proxy-error:no-instances"
        );

        log_message
            .steps
            .push(ProcessingStep::Invoked(HandlerProcessingStep::StaticDir(
                StaticDirHandlerLogMessage {
                    instance_id: instance_id.clone(),
                    config_name: self.config_id.config_name.clone(),
                    language: language.clone(),
                },
            )));

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
            "proxy-error:instance-unreachable"
        );

        let proxy_res = try_or_exception!(
            http_client.request(proxy_req).await,
            "proxy-error:upstream-unreachable"
        );

        copy_headers_from_proxy_res_to_res(proxy_res.headers(), res);

        res.headers_mut()
            .append("x-exg-proxied", "1".parse().unwrap());
        *res.status_mut() = proxy_res.status();
        *res.body_mut() = proxy_res.into_body();

        HandlerInvocationResult::Responded(Some(instance_id))
    }
}
