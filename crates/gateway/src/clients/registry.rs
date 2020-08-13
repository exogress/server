use std::sync::Arc;
use std::time::Duration;

use futures_intrusive::sync::ManualResetEvent;
use hashbrown::HashMap;
use parking_lot::Mutex;
use rand::rngs::SmallRng;
use rand::seq::IteratorRandom;
use rand::SeedableRng;
use smartstring::alias::*;
use tokio::time::timeout;

use exogress_tunnel::Connector;

use crate::clients::signaling::request_connection;
use exogress_entities::{AccountName, ConfigName, InstanceId, ProjectName};
use futures::channel::oneshot;
use url::Url;

#[derive(Clone)]
pub struct ConnectedTunnel {
    pub connector: Connector,
    pub hyper: hyper::client::Client<Connector>,
    pub config_name: ConfigName,
    pub instance_id: InstanceId,
    pub stop_tx: Arc<oneshot::Sender<()>>,
}

pub enum TunnelConnectionState {
    Requested(Arc<ManualResetEvent>),
    Connected(HashMap<InstanceId, ConnectedTunnel>),
    // Blocked,
}

#[derive(Clone)]
pub struct ClientTunnels {
    pub inner: Arc<Mutex<HashMap<ConfigName, TunnelConnectionState>>>,
    pub int_base_url: Url,
}

const WAIT_TIME: Duration = Duration::from_secs(10);

impl ClientTunnels {
    pub fn new(int_base_url: Url) -> Self {
        ClientTunnels {
            inner: Arc::new(Mutex::new(Default::default())),
            int_base_url,
        }
    }

    pub fn close_all(&self) {
        self.inner.lock().clear();
    }

    pub async fn retrieve_client_target(
        &self,
        account_name: AccountName,
        project_name: ProjectName,
        config_name: ConfigName,
        individual_hostname: String,
    ) -> Option<ConnectedTunnel> {
        // TODO:
        // 1. Figure out when to request connection
        // 2. figure out how to request all connections

        let (maybe_reset_event, should_request) = {
            let locked = &mut *self.inner.lock();
            let maybe_clients = locked.get(&config_name);

            match maybe_clients {
                None => {
                    let reset_event = Arc::new(ManualResetEvent::new(false));
                    locked.insert(
                        config_name.clone(),
                        TunnelConnectionState::Requested(reset_event.clone()),
                    );

                    (Some(reset_event), true)
                }
                Some(state) => match state {
                    TunnelConnectionState::Requested(reset_event) => {
                        (Some(reset_event.clone()), false)
                    }
                    _ => (None, false),
                },
            }
        };

        if should_request {
            match request_connection(
                self.int_base_url.clone(),
                individual_hostname,
                account_name.clone(),
                project_name.clone(),
                config_name.clone(),
            )
            .await
            {
                Ok(()) => {}
                Err(e) => {
                    error!("Error requesting connection: {}", e);
                    self.inner.lock().remove(&config_name);
                    return None;
                }
            }
        }

        if let Some(reset_event) = maybe_reset_event {
            if let Err(_e) = timeout(WAIT_TIME, reset_event.wait()).await {
                error!("Timeout waiting for tunnel");
                self.inner.lock().remove(&config_name);
                return None;
            }
        }

        // at this point we probably have connection accepted
        {
            match self.inner.lock().get(&config_name) {
                None => {}
                Some(state) => {
                    if let TunnelConnectionState::Connected(connections) = state {
                        let mut rng = SmallRng::from_entropy();
                        return connections.values().choose(&mut rng).cloned();
                    }
                }
            }
        }

        None
    }
}
