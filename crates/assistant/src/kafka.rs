use exogress_server_common::{
    kafka::{GwStatisticsReport, LOGS_TOPIC, STATISTICS_TOPIC},
    logging::LogMessage,
};
use rdkafka::{
    producer::{FutureProducer, FutureRecord},
    ClientConfig,
};
use std::time::Duration;

#[derive(Clone)]
pub struct KafkaProducer {
    producer: FutureProducer,
}

impl KafkaProducer {
    pub fn new(brokers: &str) -> anyhow::Result<Self> {
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .set("message.timeout.ms", "20000")
            .set("fetch.message.max.bytes", "536870912")
            .set("message.max.bytes", "536870912")
            .create()?;

        Ok(KafkaProducer { producer })
    }

    pub async fn send_log_message(&self, log_messages: Vec<LogMessage>) -> anyhow::Result<()> {
        let serialized = serde_json::to_vec(&log_messages).unwrap();
        info!("Try to send {} bytes to kafka", serialized.len());

        self.producer
            .send(
                FutureRecord::<(), _>::to(LOGS_TOPIC).payload(&serialized),
                Duration::from_millis(10),
            )
            .await
            .map_err(|(e, _)| e)?;

        Ok(())
    }

    pub async fn send_statistics_report(&self, report: &GwStatisticsReport) -> anyhow::Result<()> {
        self.producer
            .send(
                FutureRecord::<(), _>::to(STATISTICS_TOPIC)
                    .payload(&serde_json::to_vec(report).unwrap()),
                Duration::from_millis(10),
            )
            .await
            .map_err(|(e, _)| e)?;

        Ok(())
    }
}
