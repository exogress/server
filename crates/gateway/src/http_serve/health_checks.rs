use chrono::Utc;
use core::mem;
use exogress_entities::{AccountName, InstanceId, ProjectName, Upstream};
use exogress_server_common::assistant::UpstreamReport;
use exogress_server_common::health::{HealthEndpoint, HealthState};
use futures::channel::mpsc;
use futures::SinkExt;
use hashbrown::hash_map::Entry;
use hashbrown::HashMap;
use parking_lot::Mutex;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct HealthStorage {
    inner: Arc<Mutex<HashMap<HealthEndpoint, HealthState>>>,
    notify_on_change_tx: mpsc::Sender<UpstreamReport>,
    account_name: AccountName,
    project_name: ProjectName,
}

impl HealthStorage {
    pub fn new(
        account_name: &AccountName,
        project_name: &ProjectName,
        notify_on_change_tx: mpsc::Sender<UpstreamReport>,
    ) -> Self {
        HealthStorage {
            inner: Arc::new(Default::default()),
            notify_on_change_tx,
            account_name: account_name.clone(),
            project_name: project_name.clone(),
        }
    }
}

impl HealthStorage {
    async fn set_health(
        &mut self,
        instance_id: &InstanceId,
        upstream: &Upstream,
        state: HealthState,
    ) -> Result<(), mpsc::SendError> {
        let endpoint = HealthEndpoint {
            instance_id: instance_id.clone(),
            upstream: upstream.clone(),
        };

        match self.inner.lock().entry(endpoint.clone()) {
            Entry::Vacant(vacant) => {
                vacant.insert(state.clone());
            }
            Entry::Occupied(mut occupied) => {
                if occupied.get() == &state {
                    return Ok(());
                };
                occupied.insert(state.clone());
            }
        }

        self.notify_on_change_tx
            .send(UpstreamReport {
                account_name: self.account_name.clone(),
                project_name: self.project_name.clone(),
                health_endpoint: endpoint,
                health: Some(state),
                datetime: Utc::now(),
            })
            .await?;

        Ok(())
    }

    pub(crate) fn get_health(
        &self,
        instance_id: &InstanceId,
        upstream: &Upstream,
    ) -> Option<HealthState> {
        let endpoint = HealthEndpoint {
            instance_id: instance_id.clone(),
            upstream: upstream.clone(),
        };

        self.inner.lock().get(&endpoint).cloned()
    }

    pub async fn health_deleted(&self) -> Result<(), mpsc::SendError> {
        let old = mem::replace(&mut *self.inner.lock(), Default::default());

        let mut notify_on_change_tx = self.notify_on_change_tx.clone();

        for (endpoint, _) in old.into_iter() {
            notify_on_change_tx
                .send(UpstreamReport {
                    account_name: self.account_name.clone(),
                    project_name: self.project_name.clone(),
                    health_endpoint: endpoint,
                    health: None,
                    datetime: Utc::now(),
                })
                .await?;
        }

        Ok(())
    }
}
