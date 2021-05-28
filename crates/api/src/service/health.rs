use crate::service::Service;
use futures::future::join4;

impl Service {
    pub(crate) async fn health(&self) -> bool {
        let (elastic, mongo, redis_sessions, redis_assistant) = join4(
            self.elasticsearch.health(),
            self.mongodb.health(),
            self.redis_sessions.health(),
            self.redis_assistant.health(),
        )
        .await;

        elastic && mongo && redis_sessions && redis_assistant
    }
}
