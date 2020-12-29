use futures::{SinkExt, StreamExt};

use crate::clients::ClientTunnels;
use crate::registry::RequestsProcessorsRegistry;
use crate::stop_reasons::{AppStopHandle, StopReason};
use crate::webapp;
use exogress_common::ws_client::{connect_ws, Error};
use exogress_server_common::assistant::{
    Action, GatewayConfigMessage, WsFromGwMessage, WsToGwMessage,
};
use futures::channel::mpsc;
use futures::pin_mut;
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::sleep;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::tungstenite::handshake::client::Request;
use tokio_tungstenite::tungstenite::http::Method;
use tokio_tungstenite::{tungstenite, WebSocketStream};
use tokio_util::either::Either;
use trust_dns_resolver::TokioAsyncResolver;
use url::Url;

pub struct AssistantClient {
    stream: WebSocketStream<Either<TlsStream<TcpStream>, TcpStream>>,
    client_tunnels: ClientTunnels,
    stop_handle: AppStopHandle,
    webapp_client: webapp::Client,
    mappings: RequestsProcessorsRegistry,
    tls_gw_common: Arc<RwLock<Option<GatewayConfigMessage>>>,
    statistics_rx: mpsc::Receiver<WsFromGwMessage>,
}

impl AssistantClient {
    pub async fn new(
        assistant_base_url: Url,
        individual_hostname: &str,
        gw_location: &str,
        mappings: &RequestsProcessorsRegistry,
        client_tunnels: &ClientTunnels,
        tls_gw_common: Arc<RwLock<Option<GatewayConfigMessage>>>,
        statistics_rx: mpsc::Receiver<WsFromGwMessage>,
        maybe_identity: Option<Vec<u8>>,
        webapp_client: &webapp::Client,
        resolver: TokioAsyncResolver,
        app_stop_handle: &AppStopHandle,
    ) -> Result<AssistantClient, Error> {
        shadow_clone!(mappings);
        let scheme = assistant_base_url.scheme().to_string();

        let mut url = assistant_base_url;
        {
            let mut segments = url.path_segments_mut().unwrap();
            segments
                .push("int_api")
                .push("v1")
                .push("gateways")
                .push(individual_hostname)
                .push("notifications");
        }
        url.query_pairs_mut().append_pair("location", gw_location);

        if scheme == "https" {
            url.set_scheme("wss").unwrap();
        } else if scheme == "http" {
            url.set_scheme("ws").unwrap();
        };

        let notifier_req = Request::builder()
            .method(Method::GET)
            .uri(url.to_string())
            .body(())
            .unwrap();

        info!("connecting to notification listener..");
        let (stream, _resp) = connect_ws(notifier_req, resolver, maybe_identity).await?;

        Ok(AssistantClient {
            client_tunnels: client_tunnels.clone(),
            stream,
            webapp_client: webapp_client.clone(),
            stop_handle: app_stop_handle.clone(),
            mappings,
            tls_gw_common,
            statistics_rx,
        })
    }

    pub async fn spawn(self) {
        info!("spawning assistant client consumer...");

        let stop_handle = self.stop_handle.clone();

        let (mut ws_tx, mut ws_rx) = self.stream.split();
        let (ch_ws_tx, mut ch_ws_rx) = mpsc::channel(16);
        let (mut pong_tx, pong_rx) = mpsc::channel::<()>(16);

        let forward_to_ws = async move {
            while let Some(msg) = ch_ws_rx.next().await {
                ws_tx.send(msg).await?;
            }

            Ok::<_, anyhow::Error>(())
        };

        let tls_gw_common = self.tls_gw_common;
        let client_tunnels = self.client_tunnels;
        let webapp_client = self.webapp_client;
        let mappings = self.mappings;
        let mut statistics_rx = self.statistics_rx;

        #[allow(unreachable_code)]
        let consume = {
            shadow_clone!(stop_handle);

            async move {
                while let Some(msg) = ws_rx.next().await {
                    match msg {
                        Err(e) => {
                            warn!("Error while receiving from Notifier: {}", e);
                            stop_handle.stop(StopReason::NotificationChannelError);
                        }
                        Ok(msg) if msg.is_text() => {
                            let text = msg.into_text().unwrap();

                            match serde_json::from_str::<WsToGwMessage>(text.as_str()) {
                                Ok(ws_message) => {
                                    info!("Process message {:?}", ws_message);
                                    match ws_message {
                                        WsToGwMessage::WebAppNotification(notification) => {
                                            match notification.action {
                                                Action::Invalidate {
                                                    url_prefixes,
                                                    config_ids,
                                                } => {
                                                    for url_prefix in url_prefixes.into_iter() {
                                                        let domain_only = url_prefix.domain_only();
                                                        mappings
                                                            .remove_by_notification_if_time_applicable(
                                                                &domain_only,
                                                                &notification.generated_at,
                                                            );

                                                        let host = url_prefix.host().to_string();

                                                        info!(
                                                            "invalidate certificate for: {}",
                                                            host
                                                        );

                                                        webapp_client.forget_certificate(host);
                                                    }

                                                    for config_id in &config_ids {
                                                        client_tunnels.close_tunnel(config_id);
                                                    }
                                                }
                                            }
                                        }
                                        WsToGwMessage::GwConfig(gw_tls) => {
                                            info!("Received common gateway TLS config");
                                            *tls_gw_common.write() = Some(gw_tls);
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("error parsing notification in redis: {}", e);
                                    stop_handle.stop(StopReason::NotificationChannelError);
                                }
                            }
                        }
                        Ok(msg) if msg.is_ping() => {
                            // pong is sent automatically
                        }
                        Ok(msg) if msg.is_pong() => {
                            pong_tx.send(()).await?;
                        }
                        Ok(msg) => {
                            error!("received unexpected message from assistant: {:?}", msg);
                            stop_handle.stop(StopReason::NotificationChannelError);
                        }
                    }
                }

                Ok::<_, anyhow::Error>(())
            }
        };

        #[allow(unreachable_code)]
        let ensure_pong_received = async move {
            let timeout_stream = tokio_stream::StreamExt::timeout(pong_rx, Duration::from_secs(30));

            pin_mut!(timeout_stream);

            while let Some(r) = timeout_stream.next().await {
                r?;
            }

            Ok::<_, anyhow::Error>(())
        };

        let produce = {
            shadow_clone!(mut ch_ws_tx);
            shadow_clone!(stop_handle);

            async move {
                while let Some(report) = statistics_rx.next().await {
                    info!(
                        "received statistics report. will send to assistant WS: {:?}",
                        report
                    );
                    let report = serde_json::to_string(&report).unwrap();
                    if let Err(e) = ch_ws_tx.send(tungstenite::Message::Text(report)).await {
                        error!("send statistics error: {:?}", e);
                        stop_handle.stop(StopReason::NotificationChannelError);
                    }
                }
            }
        };

        #[allow(unreachable_code)]
        let periodically_send_ping = {
            shadow_clone!(mut ch_ws_tx);

            async move {
                loop {
                    sleep(Duration::from_secs(15)).await;

                    tokio::time::timeout(
                        Duration::from_secs(5),
                        ch_ws_tx.send(tungstenite::Message::Ping(vec![])),
                    )
                    .await??;
                }

                Ok::<_, anyhow::Error>(())
            }
        };

        tokio::select! {
            _ = consume => {},
            _ = produce => {},
            r = periodically_send_ping => {
                warn!("periodically_send_ping error: {:?}", r);
            },
            r = forward_to_ws => {
                warn!("forward_to_ws error: {:?}", r);
            },
            r = ensure_pong_received => {
                warn!("ensure_pong_received error: {:?}", r);
            },
        }

        stop_handle.stop(StopReason::NotificationChannelError);
    }
}
