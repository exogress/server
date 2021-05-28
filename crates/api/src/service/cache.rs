use crate::{mongodb::Account, service::Service};
use anyhow::bail;
use exogress_common::{
    api::SingleInvalidationRequest,
    entities::{ConfigId, ProjectName},
};

impl Service {
    pub(crate) async fn invalidate_groups(
        &mut self,
        account: &Account,
        project_name: &ProjectName,
        reqs: &[SingleInvalidationRequest],
    ) -> anyhow::Result<()> {
        let mut invalidations = vec![];
        for req in reqs {
            let maybe_mount_point = self
                .mongodb
                .get_mount_point_by_mount_point_name_and_account_id_and_project_name(
                    &account._id,
                    project_name,
                    &req.mount_point_name,
                )
                .await?;

            if let Some(mount_point) = maybe_mount_point {
                let domains = self.mongodb.get_domains(&mount_point).await?;

                let maybe_invalidation = self
                    .mongodb
                    .get_invalidation(
                        &mount_point,
                        &req.handler_name,
                        &req.config_name,
                        &req.invalidation_name,
                    )
                    .await?;
                if let Some(invalidation) = maybe_invalidation {
                    invalidations.push((invalidation, domains));
                } else {
                    bail!(
                        "invalidation group '{}' was not found",
                        req.invalidation_name
                    )
                }
            } else {
                bail!("mount point was not found")
            }
        }

        let mut fqdns_to_invaliadte = vec![];
        let mut configs_to_invalidate = vec![];

        let res = async {
            for (invalidation, domains) in invalidations {
                for domain in domains {
                    fqdns_to_invaliadte.push(domain.fqdn);
                }

                if let Ok(()) = self.mongodb.invalidate_group(&invalidation).await {
                    if let Some(config_name) = invalidation.config_name {
                        configs_to_invalidate.push(ConfigId {
                            account_name: account.name.clone(),
                            account_unique_id: account.unique_id.clone(),
                            project_name: project_name.clone(),
                            config_name,
                        });
                    }
                }
            }

            Ok::<_, anyhow::Error>(())
        }
        .await;

        if let Err(e) = res {
            error!("Error during invalidation: {}", e);
        }

        self.send_invalidation_message_to_gateways(fqdns_to_invaliadte, configs_to_invalidate)
            .await?;

        Ok(())
    }
}
