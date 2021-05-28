use crate::service::Service;
use exogress_common::entities::ConfigId;
use exogress_server_common::assistant;

impl Service {
    pub(crate) async fn send_invalidation_message_to_gateways(
        &mut self,
        fqdns: Vec<String>,
        config_ids: Vec<ConfigId>,
    ) -> anyhow::Result<()> {
        let notification = assistant::Notification {
            generated_at: chrono::Utc::now(),
            action: assistant::Action::Invalidate { fqdns, config_ids },
        };

        self.redis_assistant
            .send_gw_notification(&notification)
            .await?;

        Ok(())
    }
}
