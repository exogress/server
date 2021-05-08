use redis::{AsyncCommands, Client};

#[derive(Clone)]
pub struct RedisClient {
    redis: redis::Client,
    connection_manager: redis::aio::ConnectionManager,
}

impl RedisClient {
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

#[derive(Serialize, Deserialize, Debug)]
pub enum Provider {
    #[serde(rename = "auth0")]
    Auth0,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserInfo {
    provider: Provider,
    uid: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionPayload {
    userinfo: UserInfo,
}

impl RedisClient {
    pub async fn new(redis_addr: &str) -> anyhow::Result<Self> {
        let redis = Client::open(redis_addr)?;
        let connection_manager = redis.get_tokio_connection_manager().await?;

        Ok(Self {
            redis,
            connection_manager,
        })
    }

    pub async fn get_uid_from_session_id(
        &mut self,
        session_id: &str,
    ) -> anyhow::Result<Option<String>> {
        let maybe_session: Option<String> = self
            .connection_manager
            .get(format!("app:session:{}", session_id))
            .await?;

        if let Some(session) = maybe_session {
            let payload: SessionPayload = serde_json::from_str(session.as_str())?;
            Ok(Some(payload.userinfo.uid))
        } else {
            Ok(None)
        }
    }
}
