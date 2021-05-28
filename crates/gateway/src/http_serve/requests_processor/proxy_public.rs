use crate::{
    clients::traffic_counter::{RecordedTrafficStatistics, TrafficCounters},
    http_serve::{
        logging::{save_body_info_to_log_message, LogMessageSendOnDrop},
        requests_processor::{
            helpers::{
                add_forwarded_headers, copy_headers_from_proxy_res_to_res,
                copy_headers_to_proxy_req,
            },
            post_processing::ResolvedPostProcessing,
            utils, HandlerInvocationResult, ResolvedInvalidation,
        },
    },
    public_hyper_client::{connect_metered, MeteredHttpConnector},
};
use anyhow::Context;
use chrono::Utc;
use core::{fmt, mem};
use exogress_common::{
    common_utils::uri_ext::UriExt,
    entities::{exceptions, HandlerName, InvalidationGroupName},
};
use exogress_server_common::logging::{
    HttpBodyLog, ProtocolUpgrade, ProxyOriginResponseInfo, ProxyPublicAttemptLogMessage,
    ProxyPublicHandlerLogMessage, ProxyRequestToOriginInfo,
};
use futures::{SinkExt, StreamExt};
use hashbrown::HashMap;
use http::{
    header::{CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, UPGRADE},
    HeaderMap, Request, Response,
};
use hyper::Body;
use language_tags::LanguageTag;
use prometheus::IntCounter;
use rand::{thread_rng, RngCore};
use smol_str::SmolStr;
use std::{io, net::SocketAddr, sync::Arc};
use tokio_tungstenite::WebSocketStream;
use trust_dns_resolver::TokioAsyncResolver;

pub struct ResolvedProxyPublic {
    pub handler_name: HandlerName,
    pub client: hyper::Client<MeteredHttpConnector, hyper::Body>,
    pub host: SmolStr,
    pub individual_hostname: SmolStr,
    pub public_hostname: SmolStr,
    pub is_cache_enabled: bool,
    pub invalidations: HashMap<InvalidationGroupName, ResolvedInvalidation>,
    pub is_websockets_enabled: bool,
    pub post_processing: ResolvedPostProcessing,
    pub public_counters_tx: tokio::sync::mpsc::Sender<RecordedTrafficStatistics>,
    pub resolver: TokioAsyncResolver,
    pub counters: Arc<TrafficCounters>,
    pub sent_counter: IntCounter,
    pub recv_counter: IntCounter,
}

impl fmt::Debug for ResolvedProxyPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedProxyPublic")
            .field("host", &self.host)
            .finish()
    }
}

impl ResolvedProxyPublic {
    pub async fn invoke(
        &self,
        req: &mut Request<Body>,
        res: &mut Response<Body>,
        _requested_url: &http::uri::Uri,
        modified_url: &http::uri::Uri,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        language: &Option<LanguageTag>,
        handler_log: &mut Option<ProxyPublicHandlerLogMessage>,
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
        proxy_to.set_hostname(self.host.as_ref());
        proxy_to.unset_port();

        let mut proxy_req = Request::<Body>::new(Body::empty());
        *proxy_req.method_mut() = req.method().clone();
        *proxy_req.uri_mut() = proxy_to.clone();

        copy_headers_to_proxy_req(req, &mut proxy_req);

        add_forwarded_headers(
            &mut proxy_req,
            local_addr,
            remote_addr,
            &self.public_hostname,
            Some(self.host.as_ref()),
        );

        proxy_req
            .headers_mut()
            .append("x-exg", "1".parse().unwrap());

        let proxy_response_body = HttpBodyLog::default();
        let proxy_request_body = HttpBodyLog::default();

        *handler_log = Some(ProxyPublicHandlerLogMessage {
            base_url: Default::default(),
            handler_name: self.handler_name.clone(),
            language: language.clone(),
            attempts: vec![ProxyPublicAttemptLogMessage {
                attempt: 0,
                attempted_at: Utc::now(),
                request: ProxyRequestToOriginInfo {
                    body: proxy_request_body.clone(),
                },
                response: ProxyOriginResponseInfo {
                    body: proxy_response_body.clone(),
                },
            }],
            upgrade: if is_websocket {
                Some(ProtocolUpgrade::WebSocket)
            } else {
                None
            },
        });

        let proxy_res = if is_websocket {
            let mut ws_req = http::Request::new(());

            *ws_req.headers_mut() = proxy_req.headers().clone();
            *ws_req.method_mut() = proxy_req.method().clone();

            let mut rand_key = vec![0u8; 16];
            thread_rng().fill_bytes(&mut rand_key[..]);

            *ws_req.uri_mut() = proxy_to.clone();

            if proxy_to.scheme_str() == Some("https") {
                ws_req.uri_mut().set_scheme("wss");
            } else if proxy_to.scheme_str() == Some("http") {
                ws_req.uri_mut().set_scheme("ws");
            }

            let dst_port = proxy_to.port_u16().unwrap_or(443);

            let maybe_tcp = connect_metered(
                self.public_counters_tx.clone(),
                self.resolver.clone(),
                self.counters.clone(),
                self.sent_counter.clone(),
                self.recv_counter.clone(),
                &self.host,
                dst_port,
                true,
                None,
            )
            .await;

            let conn = try_or_exception!(
                maybe_tcp,
                exceptions::PROXY_UPSTREAM_UNREACHABLE_CONNECTION_REJECTED.clone()
            );

            let (proxy_ws, mut res) = try_or_exception!(
                tokio_tungstenite::client_async(ws_req, conn).await,
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
            let mut hyper_res = Response::new(Body::wrap_stream(futures::stream::empty::<
                Result<Vec<u8>, io::Error>,
            >()));

            *hyper_res.headers_mut() = mem::replace(res.headers_mut(), HeaderMap::new());
            *hyper_res.status_mut() = res.status();

            hyper_res
        } else {
            let instrumented_request_body = save_body_info_to_log_message(
                mem::replace(req.body_mut(), Body::empty()),
                log_message_container.clone(),
                proxy_request_body,
            );

            *proxy_req.body_mut() = instrumented_request_body;

            try_or_exception!(
                self.client.request(proxy_req).await,
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

        return HandlerInvocationResult::Responded;
    }
}
