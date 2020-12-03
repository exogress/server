use std::sync::Arc;
use std::time::Duration;

use futures_intrusive::sync::ManualResetEvent;
use hashbrown::HashMap;
use parking_lot::Mutex;
use tokio::time::timeout;

use exogress_tunnel::Connector;

use crate::clients::signaling::request_connection;
use exogress_entities::{ConfigId, InstanceId, TunnelId};
use futures::channel::oneshot;
use rand::prelude::*;
use smol_str::SmolStr;
use url::Url;

#[derive(Clone, Debug)]
pub struct ConnectedTunnel {
    pub connector: Connector,
    pub hyper: hyper::client::Client<Connector>,
    pub config_id: ConfigId,
    pub instance_id: InstanceId,
}

#[derive(Debug)]
pub enum TunnelConnectionState {
    Requested(Arc<ManualResetEvent>),
    Connected(
        HashMap<InstanceId, HashMap<TunnelId, (ConnectedTunnel, Option<oneshot::Sender<()>>)>>,
    ),
    // Blocked,
}

impl TunnelConnectionState {
    pub fn count_tunnels(&self) -> usize {
        match self {
            TunnelConnectionState::Requested(_) => 0,
            TunnelConnectionState::Connected(s) => s.values().map(|inner| inner.len()).sum(),
        }
    }

    pub fn close(&mut self) {
        if let TunnelConnectionState::Connected(s) = self {
            for inner in s.values_mut() {
                for (_, stop_tx) in inner.values_mut() {
                    if let Some(stop) = stop_tx.take() {
                        let _ = stop.send(());
                    }
                }
            }
        };
    }
}

pub struct ClientTunnelsInner {
    rng: SmallRng,
    pub(crate) by_config: HashMap<ConfigId, TunnelConnectionState>,
}

#[derive(Clone)]
pub struct ClientTunnels {
    pub inner: Arc<Mutex<ClientTunnelsInner>>,
    pub signaler_base_url: Url,
    pub maybe_identity: Option<Vec<u8>>,
}

const WAIT_TIME: Duration = Duration::from_secs(10);

impl ClientTunnels {
    pub fn new(signaler_base_url: Url, maybe_identity: Option<Vec<u8>>) -> Self {
        ClientTunnels {
            inner: Arc::new(Mutex::new(ClientTunnelsInner {
                rng: SmallRng::from_entropy(),
                by_config: Default::default(),
            })),
            signaler_base_url,
            maybe_identity,
        }
    }

    pub fn close_tunnel(&self, config_id: &ConfigId) {
        let mut locked = self.inner.lock();
        let tunnel = locked.by_config.get_mut(config_id);
        if let Some(tunnel) = tunnel {
            tunnel.close();
        }
    }

    /// Return active client tunnel if exists.
    /// Otherwise, request a new tunnel through signalling channel and
    /// wait for the actual connection
    pub async fn retrieve_client_tunnel(
        &self,
        config_id: ConfigId,
        instance_id: InstanceId,
        individual_hostname: SmolStr,
    ) -> Option<ConnectedTunnel> {
        let maybe_identity = self.maybe_identity.clone();

        let (maybe_reset_event, should_request) = {
            let mut locked = self.inner.lock();
            let maybe_clients = locked.by_config.get(&config_id);

            match maybe_clients {
                None => {
                    let reset_event = Arc::new(ManualResetEvent::new(false));
                    locked.by_config.insert(
                        config_id.clone(),
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
                self.signaler_base_url.clone(),
                individual_hostname,
                config_id.clone(),
                maybe_identity,
            )
            .await
            {
                Ok(()) => {}
                Err(e) => {
                    error!("Error requesting connection: {}", e);
                    self.inner.lock().by_config.remove(&config_id);
                    return None;
                }
            }
        }

        if let Some(reset_event) = maybe_reset_event {
            if let Err(_e) = timeout(WAIT_TIME, reset_event.wait()).await {
                error!("Timeout waiting for tunnel");
                self.inner.lock().by_config.remove(&config_id);
                return None;
            }
        }

        // at this point we probably have connection accepted
        {
            let locked = &mut *self.inner.lock();

            let by_config_name = &locked.by_config;
            let rng = &mut locked.rng;

            match by_config_name.get(&config_id) {
                None => {}
                Some(state) => {
                    if let TunnelConnectionState::Connected(connections) = state {
                        return connections.get(&instance_id).and_then(|tunnels| {
                            tunnels
                                .iter()
                                .choose(rng)
                                .map(|(_tunnel_id, (tunnel, _))| tunnel.clone())
                        });
                    }
                }
            }
        }

        None
    }
}
