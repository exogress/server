use chrono::serde::ts_milliseconds;
use chrono::{DateTime, Utc};
use futures::StreamExt;
use rdkafka::config::ClientConfig;
use rdkafka::consumer::StreamConsumer;
use rdkafka::consumer::{Consumer, ConsumerContext, Rebalance};
use rdkafka::error::KafkaResult;
use rdkafka::{ClientContext, Message};

use crate::stop_reasons::{AppStopHandle, StopReason};
use crate::url_mapping::registry::Mappings;
use smartstring::alias::*;

pub struct CustomContext {}

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

const KAFKA_INVALIDATION_TOPIC: &str = "invalidations";

impl ClientContext for CustomContext {}

impl ConsumerContext for CustomContext {
    fn pre_rebalance(&self, rebalance: &Rebalance<'_>) {
        info!("Pre rebalance {:?}", rebalance);
    }

    fn post_rebalance(&self, rebalance: &Rebalance<'_>) {
        info!("Post rebalance {:?}", rebalance);
    }

    fn commit_callback(
        &self,
        result: KafkaResult<()>,
        _offsets: &rdkafka::topic_partition_list::TopicPartitionList,
    ) {
        info!("Committing offsets: {:?}", result);
    }
}

pub struct KafkaConsumer {
    consumer: StreamConsumer<CustomContext>,
    stop_handle: AppStopHandle,
    mappings: Mappings,
}

impl KafkaConsumer {
    pub fn new(
        kafka_bootstrap_servers: &str,
        exg_gw_id: &str,
        mappings: &Mappings,
        app_stop_handle: &AppStopHandle,
    ) -> KafkaResult<KafkaConsumer> {
        shadow_clone!(mappings);

        let consumer = ClientConfig::new()
            .set("group.id", &format!("exg_gw:{}", exg_gw_id))
            .set("bootstrap.servers", kafka_bootstrap_servers)
            .set("enable.partition.eof", "false")
            .set("session.timeout.ms", "6000")
            .set("enable.auto.commit", "true")
            .set("auto.offset.reset", "latest")
            .create_with_context::<_, StreamConsumer<_>>(CustomContext {})?;

        Ok(KafkaConsumer {
            consumer,
            stop_handle: app_stop_handle.clone(),
            mappings,
        })
    }

    pub async fn spawn(self) {
        info!("spawning kafka consumer...");

        self.consumer
            .subscribe(&[&KAFKA_INVALIDATION_TOPIC])
            .expect("Can't subscribe to notifications topic");
        info!("subscribed to topic successfully");

        let mut message_stream = self.consumer.start();

        while let Some(res) = message_stream.next().await {
            match res {
                Err(e) => {
                    warn!("Error while receiving from Kafka: {}", e);
                    self.stop_handle.stop(StopReason::KafkaConsumeError(e));
                }
                Ok(msg) => {
                    info!("Received kafka message: {:?}", msg);

                    let owned_message = msg.detach();
                    let maybe_payload = owned_message.payload();

                    if let Some(payload) = maybe_payload {
                        if msg.topic() == KAFKA_INVALIDATION_TOPIC {
                            self.handle_notification(payload);
                        }
                    } else {
                        error!("Couldn't process notification message {:?}", maybe_payload);
                    }
                }
            }
        }
    }

    fn handle_notification(&self, payload: &[u8]) {
        match serde_json::from_slice::<Notification>(payload) {
            Ok(msg) => {
                info!("Process kafka notification {:?}", msg);
                match msg.action {
                    Action::InvalidateUrlPrefixes { url_prefixes } => {
                        for url_prefix in url_prefixes.into_iter() {
                            self.mappings.remove_by_notification_if_time_applicable(
                                url_prefix,
                                msg.generated_at,
                            );
                        }
                    }
                }
            }
            Err(e) => {
                error!("error parsing notification in kafka: {}", e);
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
