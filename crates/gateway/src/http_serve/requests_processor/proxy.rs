use core::{fmt, mem};
use std::net::SocketAddr;
use std::{io, sync::Arc, time::Duration};

use anyhow::Context;
use chrono::Utc;
use futures::SinkExt;
use futures::StreamExt;
use hashbrown::HashMap;
use http::{
    header::{CONNECTION, HOST, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, UPGRADE},
    HeaderMap, Request, Response,
};
use hyper::Body;
use language_tags::LanguageTag;
use parking_lot::Mutex;
use rand::{thread_rng, RngCore};
use smol_str::SmolStr;
use tokio::time::sleep;
use tokio_tungstenite::WebSocketStream;
use weighted_rs::{SmoothWeight, Weight};

use exogress_common::{
    common_utils::uri_ext::UriExt,
    config_core::UpstreamDefinition,
    entities::{HandlerName, InvalidationGroupName, LabelName, LabelValue},
};
use exogress_common::{
    entities::{exceptions, ConfigId, InstanceId, Upstream},
    tunnel::{Compression, ConnectTarget},
};
use exogress_server_common::logging::{
    HttpBodyLog, InstanceLog, ProtocolUpgrade, ProxyAttemptLogMessage, ProxyOriginResponseInfo,
    ProxyRequestToOriginInfo,
};
use exogress_server_common::{logging::ProxyHandlerLogMessage, presence};

use crate::http_serve::{
    logging::{save_body_info_to_log_message, LogMessageSendOnDrop},
    requests_processor::{post_processing::ResolvedPostProcessing, utils, ResolvedInvalidation},
};
use crate::{
    clients::{ClientTunnels, HttpConnector, TcpConnector},
    http_serve::requests_processor::HandlerInvocationResult,
};

use super::helpers::{
    add_forwarded_headers, copy_headers_from_proxy_res_to_res, copy_headers_to_proxy_req,
};

pub struct ResolvedProxy {
    pub name: Upstream,
    pub handler_name: HandlerName,
    pub upstream: UpstreamDefinition,
    pub instances: HashMap<InstanceId, HashMap<LabelName, LabelValue>>,
    pub balancer: Mutex<SmoothWeight<InstanceId>>,
    pub client_tunnels: ClientTunnels,
    pub config_id: ConfigId,
    pub individual_hostname: SmolStr,
    pub public_hostname: SmolStr,
    pub presence_client: presence::Client,
    pub is_cache_enabled: bool,
    pub invalidations: HashMap<InvalidationGroupName, ResolvedInvalidation>,
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
    pub async fn invoke(
        &self,
        req: &mut Request<Body>,
        res: &mut Response<Body>,
        _requested_url: &http::uri::Uri,
        modified_url: &http::uri::Uri,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        language: &Option<LanguageTag>,
        handler_log: &mut Option<ProxyHandlerLogMessage>,
        log_message_container: &Arc<parking_lot::Mutex<LogMessageSendOnDrop>>,
    ) -> HandlerInvocationResult {
        if req.headers().contains_key("x-exg") {
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

        let mut attempts = Vec::new();

        'instances: for attempt in 0..4 {
            let selected_instance_id = Weight::next(&mut *self.balancer.lock());

            match selected_instance_id {
                Some(instance_id) => {
                    let labels = self
                        .instances
                        .get(&instance_id)
                        .expect("should never happen. instance exist in balancer, but doesn't exist in hashmap");
                    let proxy_response_body = HttpBodyLog::default();
                    let proxy_request_body = HttpBodyLog::default();

                    attempts.push(ProxyAttemptLogMessage {
                        attempted_at: Utc::now(),
                        attempt,
                        instance: Some(InstanceLog {
                            instance_id,
                            labels: labels.clone(),
                        }),
                        request: ProxyRequestToOriginInfo {
                            body: proxy_request_body.clone(),
                        },
                        response: ProxyOriginResponseInfo {
                            body: proxy_response_body.clone(),
                        },
                    });

                    let proxy_res = if is_websocket {
                        let mut ws_req = http::Request::new(());

                        *ws_req.headers_mut() = proxy_req.headers().clone();
                        *ws_req.method_mut() = proxy_req.method().clone();

                        // otherwise host is added two times.
                        ws_req.headers_mut().remove(HOST);

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
                                // self.retrieve_connection_failed(&instance_id);
                                sleep(Duration::from_millis(50)).await;
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
                        let instrumented_request_body = save_body_info_to_log_message(
                            mem::replace(req.body_mut(), Body::empty()),
                            log_message_container.clone(),
                            proxy_request_body,
                        );

                        *proxy_req.body_mut() = instrumented_request_body;

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
                                // self.retrieve_connection_failed(&instance_id);
                                sleep(Duration::from_millis(50)).await;
                                continue 'instances;
                            }
                        };

                        try_or_exception!(
                            http_client.request(proxy_req).await,
                            exceptions::PROXY_UPSTREAM_UNREACHABLE.clone()
                        )
                    };

                    if proxy_res.headers().contains_key("x-exg-proxied") {
                        return HandlerInvocationResult::Exception {
                            name: exceptions::PROXY_LOOP_DETECTED.clone(),
                            data: Default::default(),
                        };
                    }

                    copy_headers_from_proxy_res_to_res(proxy_res.headers(), res);

                    if is_websocket {
                        res.headers_mut()
                            .insert(UPGRADE, "websocket".parse().unwrap());
                        res.headers_mut()
                            .insert(CONNECTION, "Upgrade".parse().unwrap());

                        if let Some(ws_key) = req.headers().get(SEC_WEBSOCKET_KEY) {
                            let accept = utils::ws::sec_websocket_accept(ws_key.to_str().unwrap());

                            res.headers_mut()
                                .insert(SEC_WEBSOCKET_ACCEPT, accept.parse().unwrap());
                        }
                    }

                    res.headers_mut()
                        .append("x-exg-proxied", "1".parse().unwrap());

                    *res.status_mut() = proxy_res.status();

                    let instrumented_response_body = save_body_info_to_log_message(
                        proxy_res.into_body(),
                        log_message_container.clone(),
                        proxy_response_body,
                    );

                    *res.body_mut() = instrumented_response_body;

                    *handler_log = Some(ProxyHandlerLogMessage {
                        upstream: self.name.clone(),
                        config_name: self.config_id.config_name.clone(),
                        handler_name: self.handler_name.clone(),
                        upgrade: if is_websocket {
                            Some(ProtocolUpgrade::WebSocket)
                        } else {
                            None
                        },
                        language: language.clone(),
                        attempts,
                    });

                    return HandlerInvocationResult::Responded;
                }
                None => {
                    return HandlerInvocationResult::Exception {
                        name: exceptions::PROXY_BAD_GATEWAY_NO_HEALTHY_UPSTREAMS.clone(),
                        data: Default::default(),
                    }
                }
            }
        }

        HandlerInvocationResult::Exception {
            name: exceptions::PROXY_INSTANCE_UNREACHABLE.clone(),
            data: Default::default(),
        }
    }
}
