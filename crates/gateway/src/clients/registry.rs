use std::sync::Arc;
use std::time::Duration;

use futures_intrusive::sync::ManualResetEvent;
use hashbrown::HashMap;
use parking_lot::Mutex;
use tokio::time::timeout;

use exogress::tunnel::{Compression, ConnectTarget, Connector, TunneledConnection};

use crate::clients::signaling::request_connection;
use exogress::entities::{ConfigId, InstanceId, TunnelId};
use futures::channel::oneshot;
use futures::future::BoxFuture;
use futures::FutureExt;
use http::Uri;
use smol_str::SmolStr;
use std::task;
use std::task::Poll;
use url::Url;
use weighted_rs::{SmoothWeight, Weight};

#[derive(Clone, Debug)]
pub struct ConnectedTunnel {
    pub connector: Connector,
    pub config_id: ConfigId,
    pub instance_id: InstanceId,
}

#[derive(Clone)]
pub struct InstanceConnector {
    inner: Arc<Mutex<SmoothWeight<Connector>>>,
}

impl InstanceConnector {
    pub fn new() -> Self {
        InstanceConnector {
            inner: Arc::new(Mutex::new(SmoothWeight::<Connector>::new())),
        }
    }

    pub fn sync(
        &self,
        storage: &HashMap<TunnelId, (ConnectedTunnel, Option<oneshot::Sender<()>>)>,
    ) {
        let balancer = &mut *self.inner.lock();
        balancer.remove_all();

        for (_, (connected_tunnel, _)) in storage {
            balancer.add(connected_tunnel.connector.clone(), 1);
        }
    }
}

#[inline]
fn extract_connect_target(uri: Uri) -> Result<ConnectTarget, exogress::tunnel::Error> {
    Ok(uri
        .host()
        .ok_or(exogress::tunnel::Error::EmptyHost)?
        .parse::<ConnectTarget>()?)
}

impl tower::Service<Uri> for InstanceConnector {
    type Response = TunneledConnection;
    type Error = exogress::tunnel::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    // TODO: implement poll_ready?
    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let target_result: Result<ConnectTarget, exogress::tunnel::Error> =
            extract_connect_target(dst);
        match target_result {
            Ok(target) => self
                .inner
                .lock()
                .next()
                .unwrap()
                .retrieve_connection(target, Compression::Zstd),
            Err(e) => futures::future::ready(Err(e)).boxed(),
        }
    }
}

pub struct InstanceConnections {
    pub storage: HashMap<TunnelId, (ConnectedTunnel, Option<oneshot::Sender<()>>)>,
    pub http_client: hyper::client::Client<InstanceConnector>,

    // Reference the same shared storage which hyper client uses
    pub instance_connector: InstanceConnector,
}

pub enum TunnelConnectionState {
    Requested(Arc<ManualResetEvent>),
    Connected(HashMap<InstanceId, InstanceConnections>),
    // Blocked,
}

impl TunnelConnectionState {
    pub fn close(&mut self) {
        if let TunnelConnectionState::Connected(s) = self {
            for inner in s.values_mut() {
                for (_, stop_tx) in inner.storage.values_mut() {
                    if let Some(stop) = stop_tx.take() {
                        let _ = stop.send(());
                    }
                }
            }
        };
    }
}

pub struct ClientTunnelsInner {
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
    pub async fn retrieve_http_connector(
        &self,
        config_id: &ConfigId,
        instance_id: &InstanceId,
        individual_hostname: SmolStr,
    ) -> Option<hyper::client::Client<InstanceConnector>> {
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

            match by_config_name.get(&config_id) {
                None => {}
                Some(state) => {
                    if let TunnelConnectionState::Connected(connections) = state {
                        return connections
                            .get(&instance_id)
                            .map(|instance_connections| instance_connections.http_client.clone());
                    }
                }
            }
        }

        None
    }
}
