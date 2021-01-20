use crate::clients::ClientTunnels;
use crate::http_serve::requests_processor::HandlerInvocationResult;
use anyhow::Context;
use core::{fmt, mem};
use exogress_common::entities::{ConfigId, InstanceId, Upstream};
use exogress_common::tunnel::ConnectTarget;
use exogress_server_common::logging::{
    HandlerProcessingStep, LogMessage, ProcessingStep, ProxyHandlerLogMessage,
};
use exogress_server_common::presence;
use http::header::CONNECTION;
use http::{Method, Request, Response, StatusCode};
use hyper::Body;
use parking_lot::Mutex;
use smol_str::SmolStr;
use std::convert::TryInto;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;
use weighted_rs::{SmoothWeight, Weight};

use super::helpers::{
    add_forwarded_headers, copy_headers_from_proxy_res_to_res, copy_headers_to_proxy_req,
};
use exogress_common::config_core::UpstreamDefinition;

pub struct ResolvedProxy {
    pub name: Upstream,
    pub upstream: UpstreamDefinition,
    pub instance_ids: Mutex<SmoothWeight<InstanceId>>,
    pub client_tunnels: ClientTunnels,
    pub config_id: ConfigId,
    pub individual_hostname: SmolStr,
    pub public_hostname: SmolStr,
    pub presence_client: presence::Client,
}

impl fmt::Debug for ResolvedProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedProxy")
            .field("name", &self.name)
            .field("upstream", &self.upstream)
            .field("config_id", &self.config_id)
            .finish()
    }
}

impl ResolvedProxy {
    pub async fn invoke(
        &self,
        req: &mut Request<Body>,
        res: &mut Response<Body>,
        _requested_url: &Url,
        rebased_url: &Url,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        log_message: &mut LogMessage,
    ) -> HandlerInvocationResult {
        if req.headers().contains_key("x-exg-proxied") {
            return HandlerInvocationResult::Exception {
                name: "proxy-error:loop-detected".parse().unwrap(),
                data: Default::default(),
            };
        }

        let mut proxy_to = rebased_url.clone();

        let connect_target = ConnectTarget::Upstream(self.name.clone());
        connect_target.update_url(&mut proxy_to);

        proxy_to.set_port(None).unwrap();
        if proxy_to.scheme() == "https" {
            proxy_to.set_scheme("http").unwrap();
        } else if proxy_to.scheme() == "wss" {
            proxy_to.set_scheme("ws").unwrap();
        } else {
            unreachable!("unknown scheme: {}", proxy_to.scheme());
        }

        let mut proxy_req = Request::<Body>::new(Body::empty());
        *proxy_req.method_mut() = req.method().clone();
        *proxy_req.uri_mut() = proxy_to.as_str().parse().unwrap();

        copy_headers_to_proxy_req(req, &mut proxy_req, true);

        add_forwarded_headers(
            &mut proxy_req,
            local_addr,
            remote_addr,
            &self.public_hostname,
            None,
        );

        proxy_req
            .headers_mut()
            .append("x-exg", "1".parse().unwrap());

        if req.method() != &Method::GET
            && req
                .headers()
                .get(CONNECTION)
                .map(|h| h.to_str().unwrap().to_lowercase())
                .map(|s| s.contains("upgrade"))
                != Some(true)
        {
            *proxy_req.body_mut() = mem::replace(req.body_mut(), Body::empty());
        }

        'instances: loop {
            let selected_instance_id = Weight::next(&mut *self.instance_ids.lock());

            match selected_instance_id {
                Some(instance_id) => {
                    let http_client = match self
                        .client_tunnels
                        .retrieve_http_connector(
                            &self.config_id,
                            &instance_id,
                            self.individual_hostname.clone(),
                        )
                        .await
                    {
                        Some(http_client) => http_client,
                        None => {
                            warn!(
                                "Failed to connect to instance {}. Try next instance",
                                instance_id
                            );
                            tokio::spawn({
                                let presence_client = self.presence_client.clone();
                                shadow_clone!(instance_id);

                                async move {
                                    info!("Request instance {} to go offline", instance_id);
                                    let res =
                                        presence_client.set_offline(&instance_id, "", true).await;
                                    info!(
                                        "Request instance {} to go offline res = {:?}",
                                        instance_id, res
                                    );
                                }
                            });
                            // TODO: request instance deletion
                            continue 'instances;
                        }
                    };

                    let mut proxy_res = try_or_exception!(
                        http_client.request(proxy_req).await,
                        "proxy-error:upstream-unreachable"
                    );

                    copy_headers_from_proxy_res_to_res(proxy_res.headers(), res, true);

                    res.headers_mut()
                        .append("x-exg-proxied", "1".parse().unwrap());

                    *res.status_mut() = proxy_res.status();

                    if res.status_mut() == &StatusCode::SWITCHING_PROTOCOLS {
                        let req_body = mem::replace(req.body_mut(), Body::empty());
                        let req_for_upgrade = Request::new(req_body);

                        tokio::spawn(
                            #[allow(unreachable_code)]
                            async move {
                                let mut proxy_upgraded =
                                    hyper::upgrade::on(&mut proxy_res)
                                        .await
                                        .with_context(|| "error upgrading proxy connection")?;
                                let mut req_upgraded = hyper::upgrade::on(req_for_upgrade)
                                    .await
                                    .with_context(|| "error upgrading connection")?;

                                let mut buf1 = vec![0u8; 1024];
                                let mut buf2 = vec![0u8; 1024];

                                loop {
                                    tokio::select! {
                                        bytes_read_result = proxy_upgraded.read(&mut buf1) => {
                                            let bytes_read = bytes_read_result
                                                .with_context(|| "error reading from incoming")?;
                                            if bytes_read == 0 {
                                                return Ok(());
                                            } else {
                                                req_upgraded
                                                    .write_all(&buf1[..bytes_read])
                                                    .await
                                                    .with_context(|| "error writing to forwarded")?;
                                                req_upgraded.flush().await.with_context(|| "error flushing data to cliet")?;
                                            }
                                        },

                                        bytes_read_result = req_upgraded.read(&mut buf2) => {
                                            let bytes_read = bytes_read_result
                                                .with_context(|| "error reading from forwarded")?;
                                            if bytes_read == 0 {
                                                return Ok(());
                                            } else {
                                                proxy_upgraded
                                                    .write_all(&buf2[..bytes_read])
                                                    .await
                                                    .with_context(|| "error writing to incoming")?;
                                                proxy_upgraded
                                                    .flush()
                                                    .await
                                                    .with_context(|| "error flushing data to proxy")?;
                                            }
                                        }
                                    }
                                }

                                Ok::<_, anyhow::Error>(())
                            },
                        );
                    } else {
                        *res.body_mut() = proxy_res.into_body();
                    }

                    log_message
                        .steps
                        .push(ProcessingStep::Invoked(HandlerProcessingStep::Proxy(
                            ProxyHandlerLogMessage {
                                upstream: self.name.clone(),
                                instance_id,
                                config_name: self.config_id.config_name.clone(),
                            },
                        )));

                    return HandlerInvocationResult::Responded;
                }
                None => {
                    return HandlerInvocationResult::Exception {
                        name: "proxy-error:bad-gateway:no-healthy-upstreams"
                            .parse()
                            .unwrap(),
                        data: Default::default(),
                    }
                }
            }
        }
    }
}
