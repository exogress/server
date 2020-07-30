use std::convert::TryFrom;
use std::time::SystemTime;

use chrono::serde::ts_milliseconds;
use chrono::{DateTime, Utc};
use futures::StreamExt;
use rdkafka::config::ClientConfig;
use rdkafka::consumer::StreamConsumer;
use rdkafka::consumer::{Consumer, ConsumerContext, Rebalance};
use rdkafka::error::KafkaResult;
use rdkafka::{ClientContext, Message};
use smartstring::alias::String;

use exogress_entities::MountPointId;

use crate::stop_reasons::{AppStopHandle, StopReason};
use crate::url_mapping::registry::Mappings;

pub struct CustomContext {
    pub log: slog::Logger,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum Action {
    #[serde(rename = "invalidate")]
    Invalidate { mount_point_ids: Vec<MountPointId> },
}

#[derive(Debug, Clone, Deserialize)]
pub struct Notification {
    #[serde(with = "ts_milliseconds")]
    generated_at: DateTime<Utc>,
    action: Action,
}

const KAFKA_GUARDIAN_NOTIFICATIONS_TOPIC: &str = "exg_notifications";

impl ClientContext for CustomContext {}

impl ConsumerContext for CustomContext {
    fn pre_rebalance(&self, rebalance: &Rebalance<'_>) {
        info!(self.log, "Pre rebalance {:?}", rebalance);
    }

    fn post_rebalance(&self, rebalance: &Rebalance<'_>) {
        info!(self.log, "Post rebalance {:?}", rebalance);
    }

    fn commit_callback(
        &self,
        result: KafkaResult<()>,
        _offsets: &rdkafka::topic_partition_list::TopicPartitionList,
    ) {
        info!(self.log, "Committing offsets: {:?}", result);
    }
}

pub struct KafkaConsumer {
    consumer: StreamConsumer<CustomContext>,
    stop_handle: AppStopHandle,
    mappings: Mappings,
    log: slog::Logger,
}

impl KafkaConsumer {
    pub fn new(
        kafka_bootstrap_servers: &str,
        exg_gw_id: &str,
        mappings: &Mappings,
        app_stop_handle: &AppStopHandle,
        log: &slog::Logger,
    ) -> KafkaResult<KafkaConsumer> {
        shadow_clone!(mappings);

        let consumer = ClientConfig::new()
            .set("group.id", &format!("exg_gw:{}", exg_gw_id))
            .set("bootstrap.servers", kafka_bootstrap_servers)
            .set("enable.partition.eof", "false")
            .set("session.timeout.ms", "6000")
            .set("enable.auto.commit", "true")
            .set("auto.offset.reset", "latest")
            .create_with_context::<_, StreamConsumer<_>>(CustomContext { log: log.clone() })?;

        Ok(KafkaConsumer {
            consumer,
            stop_handle: app_stop_handle.clone(),
            mappings,
            log: log.clone(),
        })
    }

    pub async fn spawn(self) {
        let log = self.log.new(o!("subsys" => "kafka_consumer"));

        info!(log, "spawning kafka consumer...");

        self.consumer
            .subscribe(&[&KAFKA_GUARDIAN_NOTIFICATIONS_TOPIC])
            .expect("Can't subscribe to notifications topic");
        info!(log, "subscribed to topic successfully");

        let mut message_stream = self.consumer.start();

        while let Some(res) = message_stream.next().await {
            match res {
                Err(e) => {
                    warn!(log, "Error while receiving from Kafka: {}", e);
                    self.stop_handle.stop(StopReason::KafkaConsumeError(e));
                }
                Ok(msg) => {
                    let owned_message = msg.detach();
                    let maybe_payload = owned_message.payload();

                    if let Some(payload) = maybe_payload {
                        if msg.topic() == KAFKA_GUARDIAN_NOTIFICATIONS_TOPIC {
                            self.handle_notification(payload, &log);
                        }
                    } else {
                        error!(
                            log,
                            "Couldn't process notification message {:?}", maybe_payload
                        );
                    }
                }
            }
        }
    }

    fn handle_notification(&self, payload: &[u8], log: &slog::Logger) {
        match serde_json::from_slice::<Notification>(payload) {
            Ok(msg) => {
                info!(log, "Process kafka notification {:?}", msg);
                match msg.action {
                    Action::Invalidate { mount_point_ids } => {
                        // self.mappings.remove_by_notification_if_time_applicable(
                        //     url_prefix,
                        //     generated_at,
                        // );

                        todo!("handle notification")
                    }
                }
            }
            Err(e) => {
                error!(log, "error parsing notification in kafka: {}", e);
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
        "type": "invalidate",
        "mount_point_ids": ["01ED93DMR0WKD4E7ZESZRJVSTK"]
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
            Action::Invalidate { mount_point_ids }
                if mount_point_ids.as_slice() == [MountPointId::from_str("01ED93DMR0WKD4E7ZESZRJVSTK").unwrap()]
        ));
    }
}
