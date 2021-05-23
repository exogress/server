use std::{sync::Arc, time::Duration};

use futures_intrusive::sync::ManualResetEvent;
use hashbrown::HashMap;
use parking_lot::Mutex;
use tokio::time::{sleep, timeout};

use exogress_common::tunnel::{Compression, ConnectTarget, Connector, TunneledConnection};

use crate::clients::signaling::request_connection;
use core::fmt;
use exogress_common::entities::{ConfigId, InstanceId, TunnelId};
use futures::{channel::oneshot, future::BoxFuture, FutureExt};
use hashbrown::hash_map::Entry;
use http::Uri;
use smol_str::SmolStr;
use std::{task, task::Poll};
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

    pub fn retrieve_connection(
        &self,
        target: ConnectTarget,
        compression: Compression,
    ) -> BoxFuture<'static, Result<TunneledConnection, exogress_common::tunnel::Error>> {
        self.inner
            .lock()
            .next()
            .unwrap()
            .retrieve_connection(target, compression)
    }
}

#[inline]
fn extract_connect_target(uri: Uri) -> Result<ConnectTarget, exogress_common::tunnel::Error> {
    Ok(uri
        .host()
        .ok_or(exogress_common::tunnel::Error::EmptyHost)?
        .parse::<ConnectTarget>()?)
}

impl hyper::service::Service<Uri> for InstanceConnector {
    type Response = TunneledConnection;
    type Error = exogress_common::tunnel::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    // TODO: implement poll_ready?
    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let target_result: Result<ConnectTarget, exogress_common::tunnel::Error> =
            extract_connect_target(dst);
        match target_result {
            Ok(target) => self.retrieve_connection(target, Compression::Plain),
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

pub struct TunnelRequestedInner {
    pub(crate) reset_event: Arc<ManualResetEvent>,
    _requestor_stop_tx: oneshot::Sender<()>,
}

pub enum TunnelConnectionState {
    Requested(TunnelRequestedInner),
    Connected(HashMap<InstanceId, InstanceConnections>),
    // Blocked,
}

impl fmt::Debug for TunnelConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TunnelConnectionState::Requested(_) => {
                write!(f, "requested")
            }
            TunnelConnectionState::Connected(_) => {
                write!(f, "connected")
            }
        }
    }
}

pub struct ClientTunnelsInner {
    pub(crate) by_config: HashMap<ConfigId, TunnelConnectionState>,
}

#[derive(Clone)]
pub struct ClientTunnels {
    pub inner: Arc<tokio::sync::Mutex<ClientTunnelsInner>>,
    pub signaler_base_url: Url,
    pub maybe_identity: Option<Vec<u8>>,
}

const WAIT_TIME: Duration = Duration::from_secs(10);

pub struct TcpConnector {}

pub struct HttpConnector {}

pub trait RetrieveConnector {
    type Connector;

    fn retrieve(instance_connections: &InstanceConnections) -> Self::Connector;
}

impl RetrieveConnector for HttpConnector {
    type Connector = hyper::client::Client<InstanceConnector>;

    fn retrieve(instance_connections: &InstanceConnections) -> Self::Connector {
        instance_connections.http_client.clone()
    }
}

impl RetrieveConnector for TcpConnector {
    type Connector = InstanceConnector;

    fn retrieve(instance_connections: &InstanceConnections) -> Self::Connector {
        instance_connections.instance_connector.clone()
    }
}

impl ClientTunnels {
    pub fn new(signaler_base_url: Url, maybe_identity: Option<Vec<u8>>) -> Self {
        ClientTunnels {
            inner: Arc::new(tokio::sync::Mutex::new(ClientTunnelsInner {
                by_config: Default::default(),
            })),
            signaler_base_url,
            maybe_identity,
        }
    }

    pub async fn close_all_config_tunnels(&self, config_id: &ConfigId) {
        let mut locked = self.inner.lock().await;
        let tunnel_entry = locked.by_config.entry(config_id.clone());
        if let Entry::Occupied(mut tunnel) = tunnel_entry {
            // not sure why do we need to explicitly send stop signal. just removing the whole entry should dbe enough
            match tunnel.get_mut() {
                TunnelConnectionState::Requested(requested) => {
                    // We make the request move on to the next stage
                    // The whole record will be deleted after the reset event
                    requested.reset_event.reset();
                }
                TunnelConnectionState::Connected(s) => {
                    for inner in s.values_mut() {
                        for (_, stop_tx) in inner.storage.values_mut() {
                            if let Some(stop) = stop_tx.take() {
                                let _ = stop.send(());
                            }
                        }
                    }
                }
            }
            tunnel.remove_entry();
        }
    }

    /// Return active client tunnel if exists.
    /// Otherwise, request a new tunnel through signalling channel and
    /// wait for the actual connection
    #[instrument(skip(self, individual_hostname), fields(config_id = %config_id, instance_id=%instance_id))]
    pub async fn retrieve_connector<R>(
        &self,
        config_id: &ConfigId,
        instance_id: &InstanceId,
        individual_hostname: SmolStr,
    ) -> Option<R::Connector>
    where
        R: RetrieveConnector,
    {
        let maybe_identity = self.maybe_identity.clone();

        info!("retrieve connection");

        let (maybe_reset_event, maybe_requestor_stop_rx) = {
            let mut locked = self.inner.lock().await;
            let maybe_clients = locked.by_config.get(&config_id);

            match maybe_clients {
                None => {
                    info!("no data in clients storage");
                    let (requestor_stop_tx, requestor_stop_rx) = oneshot::channel();
                    let reset_event = Arc::new(ManualResetEvent::new(false));
                    let tunnel_requested = TunnelRequestedInner {
                        reset_event: reset_event.clone(),
                        _requestor_stop_tx: requestor_stop_tx,
                    };
                    locked.by_config.insert(
                        config_id.clone(),
                        TunnelConnectionState::Requested(tunnel_requested),
                    );

                    (Some(reset_event), Some(requestor_stop_rx))
                }
                Some(state) => {
                    info!("data for clients found. state: {:?}", state);

                    match state {
                        TunnelConnectionState::Requested(runnel_requested) => {
                            info!("already requested! return reset-event to wait for");

                            (Some(runnel_requested.reset_event.clone()), None)
                        }
                        state => {
                            info!("current state  is {:?}. nothing to wait and don't trigger connect request", state);

                            (None, None)
                        }
                    }
                }
            }
        };

        let start_time = crate::statistics::TUNNEL_ESTABLISHMENT_TIME.start_timer();

        if let Some(requestor_stop_rx) = maybe_requestor_stop_rx {
            info!(
                "request instances with config_id `{}` to establish tunnels",
                config_id
            );

            let signaler_base_url = self.signaler_base_url.clone();

            let requestor = {
                shadow_clone!(config_id);

                async move {
                    loop {
                        let res = request_connection(
                            signaler_base_url.clone(),
                            &individual_hostname,
                            config_id.clone(),
                            &maybe_identity,
                        )
                        .await;
                        match res {
                            Ok(()) => {}
                            Err(e) => {
                                error!("Error requesting connection: {}", e);
                            }
                        }
                        sleep(Duration::from_secs(1)).await;
                    }
                }
            };

            let stoppable_requestor = async {
                tokio::select! {
                    _ = requestor => {},
                    _ = requestor_stop_rx => {},
                }
            };

            tokio::spawn(stoppable_requestor);
        }

        if let Some(reset_event) = maybe_reset_event {
            if let Err(_e) = timeout(WAIT_TIME, reset_event.wait()).await {
                error!("Timeout waiting for tunnel");
                self.inner.lock().await.by_config.remove(&config_id);
                return None;
            }
        }

        start_time.observe_duration();

        // at this point we probably have connection accepted
        {
            let locked = self.inner.lock().await;

            let by_config_name = &locked.by_config;

            match by_config_name.get(&config_id) {
                None => {
                    info!(
                        "no storage for config_id {} exist after reset event happened",
                        config_id
                    );
                    None
                }
                Some(state) => {
                    if let TunnelConnectionState::Connected(connections) = state {
                        if let Some(instance_connector) = connections.get(&instance_id) {
                            Some(R::retrieve(instance_connector))
                        } else {
                            info!(
                                "after reset event, expected instance {} is not connected. state = {:?}",
                                instance_id, state
                            );
                            None
                        }
                    } else {
                        info!("after reset event tunnel connection state is not in connected state. state is {:?}", state);
                        None
                    }
                }
            }
        }
    }
}
