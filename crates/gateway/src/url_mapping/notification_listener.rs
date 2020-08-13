use chrono::serde::ts_milliseconds;
use chrono::{DateTime, Utc};
use futures::StreamExt;

use crate::clients::ClientTunnels;
use crate::stop_reasons::{AppStopHandle, StopReason};
use crate::url_mapping::registry::Configs;
use redis::RedisError;
use smartstring::alias::*;

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

pub struct RedisConsumer {
    consumer: redis::aio::PubSub,
    client_tunnels: ClientTunnels,
    stop_handle: AppStopHandle,
    mappings: Configs,
}

impl RedisConsumer {
    pub async fn new(
        redis_client: redis::Client,
        mappings: &Configs,
        client_tunnels: &ClientTunnels,
        app_stop_handle: &AppStopHandle,
    ) -> Result<RedisConsumer, RedisError> {
        shadow_clone!(mappings);

        let mut pubsub = redis_client
            .get_tokio_connection_tokio()
            .await?
            .into_pubsub();

        pubsub.subscribe("invalidations").await?;

        Ok(RedisConsumer {
            client_tunnels: client_tunnels.clone(),
            consumer: pubsub,
            stop_handle: app_stop_handle.clone(),
            mappings,
        })
    }

    pub async fn spawn(mut self) {
        info!("spawning redis consumer...");

        let stop_handle = self.stop_handle.clone();

        let mut message_stream = self.consumer.on_message();

        while let Some(msg) = message_stream.next().await {
            match msg.get_payload::<std::string::String>() {
                Err(e) => {
                    warn!("Error while receiving from Redis: {}", e);
                    stop_handle.stop(StopReason::RedisConsumeError);
                }
                Ok(msg) => {
                    info!("Received invalidation message: {:?}", msg);

                    match serde_json::from_str::<Notification>(msg.as_str()) {
                        Ok(msg) => {
                            info!("Process redis notification {:?}", msg);
                            match msg.action {
                                Action::InvalidateUrlPrefixes { url_prefixes } => {
                                    for url_prefix in url_prefixes.into_iter() {
                                        self.mappings.remove_by_notification_if_time_applicable(
                                            url_prefix,
                                            msg.generated_at,
                                        );
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
