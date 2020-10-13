use futures::{SinkExt, StreamExt};

use crate::clients::ClientTunnels;
use crate::stop_reasons::{AppStopHandle, StopReason};
use crate::url_mapping::registry::Configs;
use crate::webapp;
use exogress_common_utils::ws_client::{connect_ws, Error};
use exogress_server_common::assistant::{
    Action, GatewayConfigMessage, WsFromGwMessage, WsToGwMessage,
};
use futures::channel::mpsc;
use parking_lot::RwLock;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_either::Either;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::tungstenite::handshake::client::Request;
use tokio_tungstenite::tungstenite::http::Method;
use tokio_tungstenite::WebSocketStream;
use trust_dns_resolver::TokioAsyncResolver;
use url::Url;

pub struct AssistantClient {
    stream: WebSocketStream<Either<TlsStream<TcpStream>, TcpStream>>,
    client_tunnels: ClientTunnels,
    stop_handle: AppStopHandle,
    webapp_client: webapp::Client,
    mappings: Configs,
    tls_gw_common: Arc<RwLock<Option<GatewayConfigMessage>>>,
    statistics_rx: mpsc::Receiver<WsFromGwMessage>,
}

impl AssistantClient {
    pub async fn new(
        assistant_base_url: Url,
        individual_hostname: &str,
        gw_location: &str,
        mappings: &Configs,
        client_tunnels: &ClientTunnels,
        tls_gw_common: Arc<RwLock<Option<GatewayConfigMessage>>>,
        statistics_rx: mpsc::Receiver<WsFromGwMessage>,
        webapp_client: &webapp::Client,
        resolver: TokioAsyncResolver,
        app_stop_handle: &AppStopHandle,
    ) -> Result<AssistantClient, Error> {
        shadow_clone!(mappings);

        let mut url = assistant_base_url;
        {
            let mut segments = url.path_segments_mut().unwrap();
            segments
                .push("api")
                .push("v1")
                .push("gateways")
                .push(individual_hostname)
                .push("notifications");
        }
        url.query_pairs_mut().append_pair("location", gw_location);
        let notifier_req = Request::builder()
            .method(Method::GET)
            .uri(url.to_string())
            .body(())
            .unwrap();

        info!("connecting to notification listener..");
        let (stream, _resp) = connect_ws(notifier_req, resolver).await?;

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

        let tls_gw_common = self.tls_gw_common;
        let client_tunnels = self.client_tunnels;
        let webapp_client = self.webapp_client;
        let mappings = self.mappings;
        let mut statistics_rx = self.statistics_rx;

        let consume = {
            let stop_handle = stop_handle.clone();

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
                                                                notification.generated_at,
                                                            )
                                                            .await;

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
                        Ok(msg) if msg.is_ping() => {}
                        Ok(msg) => {
                            error!("received unexpected message from assistant: {:?}", msg);
                            stop_handle.stop(StopReason::NotificationChannelError);
                        }
                    }
                }
            }
        };

        let produce = async move {
            while let Some(report) = statistics_rx.next().await {
                info!(
                    "received statistics report. will send to assistant WS: {:?}",
                    report
                );
                let report = serde_json::to_string(&report).unwrap();
                if let Err(e) = ws_tx.send(tungstenite::Message::Text(report)).await {
                    error!("send statistics error: {:?}", e);
                    stop_handle.stop(StopReason::NotificationChannelError);
                }
            }
        };

        tokio::select! {
            _ = consume => {},
            _ = produce => {},
        }
    }
}
