use crate::termination::StopReason;
use exogress_entities::{ConfigName, InstanceId};
use exogress_signaling::{TunnelRequest, TunnelRequestResponse};
use futures::FutureExt;
use redis::AsyncCommands;
use std::net::SocketAddr;
use stop_handle::StopWait;
use warp::Filter;

pub async fn server(
    listen_addr: SocketAddr,
    redis: redis::Client,
    stop_wait: StopWait<stop_handle::StopReason<StopReason>>,
) {
    let connection_manager = redis
        .get_tokio_connection_manager()
        .await
        .expect("redis connection error");

    let tunnels_api = warp::path!("api" / "v1" / "instances" / ConfigName / "tunnels")
        .and(warp::filters::method::put())
        .and(warp::header("authorization"))
        .and(warp::body::json())
        .and_then({
            move |config_name: ConfigName, authorization: String, body: TunnelRequest| {
                let mut connection_manager = connection_manager.clone();

                async move {
                    let serialized = serde_json::to_string_pretty(&body).unwrap();

                    let num_recipients: u16 = connection_manager
                        .publish(format!("signaler.config.{}", config_name), serialized)
                        .await
                        .expect("redis error");

                    debug!("delivered to {} recipients", num_recipients);

                    if num_recipients == 0 {
                        Err(warp::reject::not_found())
                    } else {
                        Ok(warp::reply::json(&TunnelRequestResponse { num_recipients }))
                    }
                }
            }
        });

    let (_, server) = warp::serve(tunnels_api).bind_with_graceful_shutdown(
        listen_addr,
        stop_wait.map({ move |r| info!("private HTTP server stop request received: {}", r) }),
    );

    server.await;

    info!("private HTTP server stopped");
}

#[derive(Debug)]
pub struct BadInstanceId {}

impl warp::reject::Reject for BadInstanceId {}
