use crate::{
    clients::{ClientTunnels, HttpConnector, TcpConnector},
    http_serve::requests_processor::HandlerInvocationResult,
};
use anyhow::Context;
use core::{fmt, mem};
use exogress_common::{
    entities::{exceptions, ConfigId, InstanceId, Upstream},
    tunnel::{Compression, ConnectTarget},
};

use exogress_server_common::{
    logging::{HandlerProcessingStep, LogMessage, ProcessingStep, ProxyHandlerLogMessage},
    presence,
};
use futures::SinkExt;
use http::{
    header::{CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, UPGRADE},
    HeaderMap, Request, Response,
};
use hyper::Body;
use parking_lot::Mutex;
use smol_str::SmolStr;
use std::net::SocketAddr;
use weighted_rs::{SmoothWeight, Weight};

use super::helpers::{
    add_forwarded_headers, copy_headers_from_proxy_res_to_res, copy_headers_to_proxy_req,
};
use crate::http_serve::requests_processor::post_processing::ResolvedPostProcessing;
use exogress_common::{common_utils::uri_ext::UriExt, config_core::UpstreamDefinition};
use futures::StreamExt;
use langtag::LanguageTagBuf;
use rand::{thread_rng, RngCore};
use std::io;
use tokio_tungstenite::WebSocketStream;

pub struct ResolvedProxy {
    pub name: Upstream,
    pub upstream: UpstreamDefinition,
    pub instance_ids: Mutex<SmoothWeight<InstanceId>>,
    pub client_tunnels: ClientTunnels,
    pub config_id: ConfigId,
    pub individual_hostname: SmolStr,
    pub public_hostname: SmolStr,
    pub presence_client: presence::Client,
    pub is_cache_enabled: bool,
    pub is_websockets_enabled: bool,
    pub post_processing: ResolvedPostProcessing,
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
    fn sec_websocket_accept(key: &str) -> String {
        let s = format!("{}258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);

        let mut m = sha1::Sha1::new();
        m.update(s.as_ref());
        base64::encode(m.digest().bytes().as_ref())
    }

    fn retrieve_connection_failed(&self, instance_id: &InstanceId) {
        warn!(
            "Failed to connect to instance {}. Try next instance",
            instance_id
        );
        tokio::spawn({
            let presence_client = self.presence_client.clone();
            shadow_clone!(instance_id);

            async move {
                info!("Request instance {} to go offline", instance_id);
                let res = presence_client.set_offline(&instance_id, "", true).await;
                info!(
                    "Request instance {} to go offline res = {:?}",
                    instance_id, res
                );
            }
        });
    }
    pub async fn invoke(
        &self,
        req: &mut Request<Body>,
        res: &mut Response<Body>,
        _requested_url: &http::uri::Uri,
        modified_url: &http::uri::Uri,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        language: &Option<LanguageTagBuf>,
        log_message: &mut LogMessage,
    ) -> HandlerInvocationResult {
        if req.headers().contains_key("x-exg-proxied") {
            return HandlerInvocationResult::Exception {
                name: exceptions::PROXY_LOOP_DETECTED.clone(),
                data: Default::default(),
            };
        }

        let mut is_websocket = false;

        if let Some(upgrade) = req.headers().get(UPGRADE) {
            if upgrade
                .to_str()
                .unwrap()
                .to_lowercase()
                .contains("websocket")
            {
                if self.is_websockets_enabled {
                    is_websocket = true;
                } else {
                    return HandlerInvocationResult::Exception {
                        name: exceptions::PROXY_WEBSOCKETS_DISABLED.clone(),
                        data: Default::default(),
                    };
                }
            }
        }

        let mut proxy_to = modified_url.clone();

        let connect_target = ConnectTarget::Upstream(self.name.clone());
        connect_target.update_url(&mut proxy_to);

        if proxy_to.scheme().unwrap() == "https" {
            proxy_to.set_scheme("http");
        } else if proxy_to.scheme().unwrap() == "wss" {
            proxy_to.set_scheme("ws");
        } else {
            unreachable!("unknown scheme: {}", proxy_to);
        }

        let mut proxy_req = Request::<Body>::new(Body::empty());
        *proxy_req.method_mut() = req.method().clone();
        *proxy_req.uri_mut() = proxy_to.clone();

        copy_headers_to_proxy_req(req, &mut proxy_req);

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

        'instances: loop {
            let selected_instance_id = Weight::next(&mut *self.instance_ids.lock());

            match selected_instance_id {
                Some(instance_id) => {
                    let proxy_res = if is_websocket {
                        let mut ws_req = http::Request::new(());

                        *ws_req.headers_mut() = proxy_req.headers().clone();
                        *ws_req.method_mut() = proxy_req.method().clone();

                        let mut rand_key = vec![0u8; 16];
                        thread_rng().fill_bytes(&mut rand_key[..]);

                        proxy_to.set_scheme("ws");
                        *ws_req.uri_mut() = proxy_to.clone();

                        let maybe_tcp = match self
                            .client_tunnels
                            .retrieve_connector::<TcpConnector>(
                                &self.config_id,
                                &instance_id,
                                self.individual_hostname.clone(),
                            )
                            .await
                        {
                            Some(tcp) => {
                                tcp.retrieve_connection(connect_target, Compression::Plain)
                                    .await
                            }
                            None => {
                                self.retrieve_connection_failed(&instance_id);
                                continue 'instances;
                            }
                        };

                        let tcp = try_or_exception!(
                            maybe_tcp,
                            exceptions::PROXY_UPSTREAM_UNREACHABLE_CONNECTION_REJECTED.clone()
                        );

                        let (proxy_ws, mut res) = try_or_exception!(
                            tokio_tungstenite::client_async(ws_req, tcp).await,
                            exceptions::PROXY_WEBSOCKETS_CONNECTION_ERROR
                        );

                        let req_for_upgrade = mem::replace(req, Request::new(Body::empty()));
                        *req.headers_mut() = req_for_upgrade.headers().clone();
                        *req.uri_mut() = req_for_upgrade.uri().clone();
                        *req.method_mut() = req_for_upgrade.method().clone();

                        tokio::spawn(
                            #[allow(unreachable_code)]
                            async move {
                                let forwarder = async move {
                                    let req_upgraded = hyper::upgrade::on(req_for_upgrade)
                                        .await
                                        .with_context(|| "error upgrading connection")?;

                                    let (mut proxy_ws_tx, mut proxy_ws_rx) = proxy_ws.split();

                                    let proxy_ws = WebSocketStream::from_raw_socket(
                                        req_upgraded,
                                        tokio_tungstenite::tungstenite::protocol::Role::Server,
                                        None,
                                    )
                                    .await;

                                    let (mut client_ws_tx, mut client_ws_rx) = proxy_ws.split();

                                    loop {
                                        tokio::select! {
                                            maybe_msg = proxy_ws_rx.next() => {
                                                if let Some(Ok(msg)) = maybe_msg  {
                                                    client_ws_tx.send(msg).await.with_context(|| "could not send WS msg to client")?;
                                                } else {
                                                    break;
                                                }
                                            },

                                            maybe_msg = client_ws_rx.next() => {
                                                if let Some(Ok(msg)) = maybe_msg  {
                                                    proxy_ws_tx.send(msg).await.with_context(|| "could not send WS msg to proxy")?;
                                                } else {
                                                    break;
                                                }
                                            },
                                        }
                                    }

                                    Ok::<_, anyhow::Error>(())
                                };

                                if let Err(e) = forwarder.await {
                                    warn!("error in Websocket forwarder: {}", e);
                                }
                            },
                        );

                        // using wrap_stream here prevents hyper to automatically set content-length
                        let mut hyper_res =
                            Response::new(Body::wrap_stream(futures::stream::empty::<
                                Result<Vec<u8>, io::Error>,
                            >()));

                        *hyper_res.headers_mut() =
                            mem::replace(res.headers_mut(), HeaderMap::new());
                        *hyper_res.status_mut() = res.status();

                        hyper_res
                    } else {
                        let request_body = mem::replace(req.body_mut(), Body::empty());

                        *proxy_req.body_mut() = request_body;

                        let http_client = match self
                            .client_tunnels
                            .retrieve_connector::<HttpConnector>(
                                &self.config_id,
                                &instance_id,
                                self.individual_hostname.clone(),
                            )
                            .await
                        {
                            Some(http_client) => http_client,
                            None => {
                                self.retrieve_connection_failed(&instance_id);
                                continue 'instances;
                            }
                        };

                        try_or_exception!(
                            http_client.request(proxy_req).await,
                            exceptions::PROXY_UPSTREAM_UNREACHABLE.clone()
                        )
                    };

                    copy_headers_from_proxy_res_to_res(proxy_res.headers(), res);

                    if is_websocket {
                        res.headers_mut()
                            .insert(UPGRADE, "websocket".parse().unwrap());
                        res.headers_mut()
                            .insert(CONNECTION, "Upgrade".parse().unwrap());

                        if let Some(ws_key) = req.headers().get(SEC_WEBSOCKET_KEY) {
                            let accept = Self::sec_websocket_accept(ws_key.to_str().unwrap());

                            res.headers_mut()
                                .insert(SEC_WEBSOCKET_ACCEPT, accept.parse().unwrap());
                        }
                    }

                    res.headers_mut()
                        .append("x-exg-proxied", "1".parse().unwrap());

                    *res.status_mut() = proxy_res.status();
                    *res.body_mut() = proxy_res.into_body();

                    log_message
                        .steps
                        .push(ProcessingStep::Invoked(HandlerProcessingStep::Proxy(
                            ProxyHandlerLogMessage {
                                upstream: self.name.clone(),
                                instance_id,
                                config_name: self.config_id.config_name.clone(),
                                language: language.clone(),
                            },
                        )));

                    return HandlerInvocationResult::Responded;
                }
                None => {
                    return HandlerInvocationResult::Exception {
                        name: exceptions::PROXY_BAD_GATEWAY.clone(),
                        data: Default::default(),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_sec_websocket() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        assert_eq!(
            ResolvedProxy::sec_websocket_accept(key),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        )
    }
}
