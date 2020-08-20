use chrono::serde::ts_milliseconds;
use chrono::{DateTime, Utc};
use futures::StreamExt;

use crate::clients::ClientTunnels;
use crate::stop_reasons::{AppStopHandle, StopReason};
use crate::url_mapping::registry::Configs;
use crate::webapp;
use exogress_common_utils::ws_client::{connect_ws, Error};
use smartstring::alias::*;
use tokio::net::TcpStream;
use tokio_either::Either;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::tungstenite::handshake::client::Request;
use tokio_tungstenite::tungstenite::http::Method;
use tokio_tungstenite::WebSocketStream;
use trust_dns_resolver::TokioAsyncResolver;
use url::Url;

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum Action {
    #[serde(rename = "invalidate_url_prefixes")]
    InvalidateUrlPrefixes { url_prefixes: Vec<String> },
}

#[derive(Debug, Clone, Deserialize)]
pub struct Notification {
    #[serde(with = "ts_milliseconds")]
    generated_at: DateTime<Utc>,
    action: Action,
}

pub struct Consumer {
    stream: WebSocketStream<Either<TlsStream<TcpStream>, TcpStream>>,
    client_tunnels: ClientTunnels,
    stop_handle: AppStopHandle,
    webapp_client: webapp::Client,
    mappings: Configs,
}

impl Consumer {
    pub async fn new(
        assistant_base_url: Url,
        individual_hostname: &str,
        mappings: &Configs,
        client_tunnels: &ClientTunnels,
        webapp_client: &webapp::Client,
        resolver: TokioAsyncResolver,
        app_stop_handle: &AppStopHandle,
    ) -> Result<Consumer, Error> {
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

        Ok(Consumer {
            client_tunnels: client_tunnels.clone(),
            stream,
            webapp_client: webapp_client.clone(),
            stop_handle: app_stop_handle.clone(),
            mappings,
        })
    }

    pub async fn spawn(mut self) {
        info!("spawning redis consumer...");

        let stop_handle = self.stop_handle.clone();

        while let Some(msg) = self.stream.next().await {
            match msg {
                Err(e) => {
                    warn!("Error while receiving from Notifier: {}", e);
                    stop_handle.stop(StopReason::NotificationChannelError);
                }
                Ok(msg) if msg.is_text() => {
                    let text = msg.into_text().unwrap();
                    info!("Received invalidation message: {:?}", text);

                    match serde_json::from_str::<Notification>(text.as_str()) {
                        Ok(notification) => {
                            info!("Process invalidation notification {:?}", notification);
                            match notification.action {
                                Action::InvalidateUrlPrefixes { url_prefixes } => {
                                    for url_prefix in url_prefixes.into_iter() {
                                        self.mappings.remove_by_notification_if_time_applicable(
                                            url_prefix.clone(),
                                            notification.generated_at,
                                        );
                                        match Url::parse(format!("http://{}", url_prefix).as_str())
                                        {
                                            Ok(url) if url.host_str().is_some() => {
                                                let host = url.host_str().unwrap().to_string();
                                                info!("invalidate certificate for: {}", host);
                                                self.webapp_client.forget_certificate(host)
                                            }
                                            r => {
                                                warn!("could not invalidate certificate: {:?}", r);
                                            }
                                        };

                                        // FIXME: should rely on invalidation message
                                        self.client_tunnels.close_all();
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!("error parsing notification in redis: {}", e);
                        }
                    }
                }
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
    use std::str::FromStr;

    use super::*;

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
                if url_prefixes.as_slice() == [String::from("test.exg.link/prefix")]
        ));
    }
}
