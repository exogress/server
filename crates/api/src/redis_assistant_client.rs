use exogress_server_common::assistant;
use redis::{AsyncCommands, Client};

#[derive(Clone)]
pub struct RedisAssistantClient {
    redis: redis::Client,
    connection_manager: redis::aio::ConnectionManager,
}

impl RedisAssistantClient {
    pub async fn health(&self) -> bool {
        let res = async move {
            let mut redis_conn = self.redis.get_async_connection().await?;
            let r = redis_conn.set("api_healthcheck", "1").await?;
            Ok::<String, redis::RedisError>(r)
        }
        .await;

        if let Err(e) = res {
            error!("health check: redis error: {}", e);
            false
        } else {
            true
        }
    }
}

impl RedisAssistantClient {
    pub async fn new(redis_addr: &str) -> anyhow::Result<Self> {
        let redis = Client::open(redis_addr)?;
        let connection_manager = redis.get_tokio_connection_manager().await?;

        Ok(Self {
            redis,
            connection_manager,
        })
    }

    pub async fn send_gw_notification(
        &mut self,
        invalidation: &assistant::Notification,
    ) -> anyhow::Result<u16> {
        let s = serde_json::to_string_pretty(invalidation).unwrap();

        Ok(self.connection_manager.publish("invalidations", s).await?)
    }
}
