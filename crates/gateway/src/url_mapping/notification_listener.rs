use chrono::serde::ts_milliseconds;
use chrono::{DateTime, Utc};
use futures::StreamExt;

use crate::clients::ClientTunnels;
use crate::stop_reasons::{AppStopHandle, StopReason};
use crate::url_mapping::registry::Configs;
use crate::webapp;
use exogress_common_utils::ws_client::{connect_ws, Error};
use exogress_server_common::assistant::{
    Action, GatewayCommonTlsConfigMessage, Notification, WsMessage,
};
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

pub struct AssistantConsumer {
    stream: WebSocketStream<Either<TlsStream<TcpStream>, TcpStream>>,
    client_tunnels: ClientTunnels,
    stop_handle: AppStopHandle,
    webapp_client: webapp::Client,
    mappings: Configs,
    tls_gw_common: Arc<RwLock<Option<GatewayCommonTlsConfigMessage>>>,
}

impl AssistantConsumer {
    pub async fn new(
        assistant_base_url: Url,
        individual_hostname: &str,
        mappings: &Configs,
        client_tunnels: &ClientTunnels,
        tls_gw_common: Arc<RwLock<Option<GatewayCommonTlsConfigMessage>>>,
        webapp_client: &webapp::Client,
        resolver: TokioAsyncResolver,
        app_stop_handle: &AppStopHandle,
    ) -> Result<AssistantConsumer, Error> {
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
        let notifier_req = Request::builder()
            .method(Method::GET)
            .uri(url.to_string())
            .body(())
            .unwrap();

        info!("connecting to notification listener..");
        let (stream, _resp) = connect_ws(notifier_req, resolver).await?;

        Ok(AssistantConsumer {
            client_tunnels: client_tunnels.clone(),
            stream,
            webapp_client: webapp_client.clone(),
            stop_handle: app_stop_handle.clone(),
            mappings,
            tls_gw_common,
        })
    }

    pub async fn spawn(mut self) {
        info!("spawning assistant client consumer...");

        let stop_handle = self.stop_handle.clone();

        while let Some(msg) = self.stream.next().await {
            match msg {
                Err(e) => {
                    warn!("Error while receiving from Notifier: {}", e);
                    stop_handle.stop(StopReason::NotificationChannelError);
                }
                Ok(msg) if msg.is_text() => {
                    let text = msg.into_text().unwrap();

                    match serde_json::from_str::<WsMessage>(text.as_str()) {
                        Ok(ws_message) => {
                            info!("Process message {:?}", ws_message);
                            match ws_message {
                                WsMessage::WebAppNotification(notification) => {
                                    match notification.action {
                                        Action::InvalidateUrlPrefixes { url_prefixes } => {
                                            for url_prefix in url_prefixes.into_iter() {
                                                let domain_only = url_prefix.domain_only();
                                                self.mappings
                                                    .remove_by_notification_if_time_applicable(
                                                        &domain_only,
                                                        notification.generated_at,
                                                    );

                                                let host = url_prefix.host().to_string();

                                                info!("invalidate certificate for: {}", host);
                                                self.webapp_client.forget_certificate(host);

                                                // FIXME: should rely on invalidation message
                                                self.client_tunnels.close_all();
                                            }
                                        }
                                    }
                                }
                                WsMessage::GwTls(gw_tls) => {
                                    info!("Received common gateway TLS config");
                                    *self.tls_gw_common.write() = Some(gw_tls);
                                }
                            }
                        }
                        Err(e) => {
                            error!("error parsing notification in redis: {}", e);
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
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_deserialize() {
        static JSON: &'static str = r#"{
    "generated_at": 1594736221163,
    "action": {
        "type": "invalidate_url_prefixes",
        "url_prefixes": ["test.exg.link/prefix"]
    }
}
"#;

        let n: Notification = serde_json::from_str(JSON).unwrap();
        assert_eq!(
            "2020-07-14T14:17:01.163Z".parse::<DateTime<Utc>>().unwrap(),
            n.generated_at
        );
        assert!(matches!(
            n.action,
            Action::InvalidateUrlPrefixes { url_prefixes }
                if url_prefixes.as_slice() == [UrlPrefix::from_str("test.exg.link/prefix").unwrap()]
        ));
    }
}
