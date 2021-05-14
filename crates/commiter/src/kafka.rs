use crate::{elasticsearch::ElasticsearchClient, reporting::MongoDbClient};
use core::mem;
use exogress_server_common::{
    kafka::{GwStatisticsReport, LOGS_TOPIC, STATISTICS_TOPIC},
    logging::LogMessage,
};
use itertools::Itertools;
use rdkafka::{
    config::RDKafkaLogLevel,
    consumer::{CommitMode, Consumer, ConsumerContext, Rebalance, StreamConsumer},
    error::KafkaResult,
    ClientConfig, ClientContext, Message, TopicPartitionList,
};
use std::{sync::Arc, time::Duration};

struct CustomContext;

impl ClientContext for CustomContext {}

impl ConsumerContext for CustomContext {
    fn pre_rebalance(&self, rebalance: &Rebalance<'_>) {
        info!("Pre rebalance {:?}", rebalance);
    }

    fn post_rebalance(&self, rebalance: &Rebalance<'_>) {
        info!("Post rebalance {:?}", rebalance);
    }

    fn commit_callback(&self, result: KafkaResult<()>, _offsets: &TopicPartitionList) {
        info!("Committing offsets: {:?}", result);
    }
}
type LoggingConsumer = StreamConsumer<CustomContext>;

pub async fn spawn(
    brokers: &str,
    group_id: &str,
    max_concurrency: usize,
    mongodb_client: MongoDbClient,
    elastic_client: ElasticsearchClient,
) -> anyhow::Result<()> {
    let context = CustomContext;

    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrency));

    let consumer: LoggingConsumer = ClientConfig::new()
        .set("group.id", group_id)
        .set("bootstrap.servers", brokers)
        .set("enable.partition.eof", "false")
        .set("session.timeout.ms", "6000")
        .set("enable.auto.commit", "true")
        .set("fetch.message.max.bytes", "536870912")
        .set("message.max.bytes", "536870912")
        .set("fetch.message.max.bytes", "536870912")
        //.set("statistics.interval.ms", "30000")
        //.set("auto.offset.reset", "smallest")
        .set_log_level(RDKafkaLogLevel::Debug)
        .create_with_context(context)?;

    consumer.subscribe(&[LOGS_TOPIC, STATISTICS_TOPIC])?;

    loop {
        match consumer.recv().await {
            Err(e) => warn!("Kafka error: {}", e),
            Ok(m) => {
                let permit = semaphore.clone().acquire_owned().await?;
                let topic = m.topic();
                match m.payload_view::<[u8]>() {
                    None => {}
                    Some(Ok(s)) => {
                        let r = consumer.commit_message(&m, CommitMode::Async);

                        if topic == LOGS_TOPIC {
                            if let Ok(messages) = serde_json::from_slice::<Vec<LogMessage>>(s) {
                                tokio::spawn({
                                    shadow_clone!(elastic_client);

                                    async move {
                                        let grouped =
                                            messages.into_iter().into_group_map_by(|msg| {
                                                format!("account-{}", msg.account_unique_id)
                                                    .to_lowercase()
                                            });

                                        for (index, messages_for_index) in grouped {
                                            let start_time =
                                                crate::statistics::ACCOUNT_LOGS_SAVE_TIME
                                                    .start_timer();

                                            let res = tokio::time::timeout(
                                                Duration::from_secs(5),
                                                elastic_client
                                                    .save_log_messages(index, messages_for_index),
                                            )
                                            .await;

                                            let is_ok = match res {
                                                Err(e) => {
                                                    error!(
                                                        "Failed to save to elasticsearch: {}",
                                                        e
                                                    );
                                                    false
                                                }
                                                Ok(Err(e)) => {
                                                    error!(
                                                        "Failed to save to elasticsearch: {}",
                                                        e
                                                    );
                                                    false
                                                }
                                                Ok(Ok(_)) => {
                                                    start_time.observe_duration();
                                                    true
                                                }
                                            };

                                            crate::statistics::ACCOUNT_LOGS_SAVE
                                                .with_label_values(&[if is_ok { "" } else { "1" }])
                                                .inc();
                                        }

                                        mem::drop(permit);
                                    }
                                });
                            }
                        } else if topic == STATISTICS_TOPIC {
                            if let Ok(msg) = serde_json::from_slice::<GwStatisticsReport>(s) {
                                tokio::spawn({
                                    shadow_clone!(mongodb_client);

                                    async move {
                                        let start_time =
                                            crate::statistics::STATISTICS_REPORT_SAVE_TIME
                                                .start_timer();

                                        match tokio::time::timeout(
                                            Duration::from_secs(5),
                                            mongodb_client.register_statistics_report(
                                                msg.report,
                                                &msg.gw_hostname,
                                                &msg.gw_location,
                                            ),
                                        )
                                        .await
                                        {
                                            Ok(Err(e)) => {
                                                error!("Error saving statistics to mongo: {:?}", e);
                                            }
                                            Err(_) => {
                                                error!("Timeout saving report to mongo");
                                            }
                                            Ok(_) => {}
                                        };

                                        start_time.observe_duration();

                                        mem::drop(permit);
                                    }
                                });
                            };
                        }
                    }
                    Some(Err(e)) => {
                        warn!("Error while deserializing message payload: {:?}", e);
                    }
                };
            }
        };
    }
}
