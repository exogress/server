use std::sync::Arc;
use std::time::Duration;

use futures_intrusive::sync::ManualResetEvent;
use hashbrown::HashMap;
use parking_lot::Mutex;
use smartstring::alias::*;
use tokio::time::timeout;

use exogress_tunnel::Connector;

use crate::clients::signaling::request_connection;
use exogress_entities::{AccountName, ConfigName, InstanceId, ProjectName};
use futures::channel::oneshot;
use generational_arena::Arena;
use rand::prelude::*;
use url::Url;

#[derive(Clone, Debug)]
pub struct ConnectedTunnel {
    pub connector: Connector,
    pub hyper: hyper::client::Client<Connector>,
    pub config_name: ConfigName,
    pub instance_id: InstanceId,
    pub stop_tx: Arc<oneshot::Sender<()>>,
}

#[derive(Debug)]
pub enum TunnelConnectionState {
    Requested(Arc<ManualResetEvent>),
    Connected(HashMap<InstanceId, Arena<ConnectedTunnel>>),
    // Blocked,
}

pub struct ClientTunnelsInner {
    rng: SmallRng,
    pub(crate) by_config: HashMap<(AccountName, ProjectName, ConfigName), TunnelConnectionState>,
}

#[derive(Clone)]
pub struct ClientTunnels {
    pub inner: Arc<Mutex<ClientTunnelsInner>>,
    pub int_base_url: Url,
}

const WAIT_TIME: Duration = Duration::from_secs(10);

impl ClientTunnels {
    pub fn new(int_base_url: Url) -> Self {
        ClientTunnels {
            inner: Arc::new(Mutex::new(ClientTunnelsInner {
                rng: SmallRng::from_entropy(),
                by_config: Default::default(),
            })),
            int_base_url,
        }
    }

    pub fn close_tunnel(
        &self,
        account_name: &AccountName,
        project_name: &ProjectName,
        config_name: &ConfigName,
    ) {
        info!(
            "Close tunnels for {}/{}{}",
            account_name, project_name, config_name
        );
        self.inner.lock().by_config.remove(&(
            account_name.clone(),
            project_name.clone(),
            config_name.clone(),
        ));
    }

    /// Return active client tunnel if exists.
    /// Otherwise, request new tunnel through signalling channel and
    /// wait for the actual connection
    pub async fn retrieve_client_tunnel(
        &self,
        account_name: AccountName,
        project_name: ProjectName,
        config_name: ConfigName,
        instance_id: InstanceId,
        individual_hostname: String,
    ) -> Option<ConnectedTunnel> {
        // TODO:
        // 1. Figure out when to request connection
        // 2. figure out how to request all connections

        let (maybe_reset_event, should_request) = {
            let mut locked = self.inner.lock();
            let maybe_clients = locked.by_config.get(&(
                account_name.clone(),
                project_name.clone(),
                config_name.clone(),
            ));

            match maybe_clients {
                None => {
                    let reset_event = Arc::new(ManualResetEvent::new(false));
                    locked.by_config.insert(
                        (
                            account_name.clone(),
                            project_name.clone(),
                            config_name.clone(),
                        ),
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
                    self.inner.lock().by_config.remove(&(
                        account_name.clone(),
                        project_name.clone(),
                        config_name.clone(),
                    ));
                    return None;
                }
            }
        }

        if let Some(reset_event) = maybe_reset_event {
            if let Err(_e) = timeout(WAIT_TIME, reset_event.wait()).await {
                error!("Timeout waiting for tunnel");
                self.inner.lock().by_config.remove(&(
                    account_name.clone(),
                    project_name.clone(),
                    config_name.clone(),
                ));
                return None;
            }
        }

        // at this point we probably have connection accepted
        {
            let locked = &mut *self.inner.lock();

            let by_config_name = &locked.by_config;
            let rng = &mut locked.rng;

            match by_config_name.get(&(
                account_name.clone(),
                project_name.clone(),
                config_name.clone(),
            )) {
                None => {}
                Some(state) => {
                    if let TunnelConnectionState::Connected(connections) = state {
                        return connections.get(&instance_id).and_then(|arena| {
                            arena
                                .iter()
                                .choose(rng)
                                .map(|(_idx, tunnel)| tunnel.clone())
                        });
                    }
                }
            }
        }

        None
    }
}
