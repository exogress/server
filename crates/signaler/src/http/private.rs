use crate::termination::StopReason;
use exogress_common::{
    entities::{AccountName, ConfigName, ProjectName},
    signaling::{TunnelRequest, TunnelRequestResponse},
};
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
    info!("Will spawn private HTTP server on {}", listen_addr);

    let tunnels_api = warp::path!(
        "int_api"
            / "v1"
            / "accounts"
            / AccountName
            / "projects"
            / ProjectName
            / "configs"
            / ConfigName
            / "tunnels"
    )
    .and(warp::filters::method::put())
    .and(warp::header("authorization"))
    .and(warp::body::json())
    .and_then({
        shadow_clone!(redis);

        move |account: AccountName,
              project: ProjectName,
              config_name: ConfigName,
              _authorization: String, //TODO: check authorization
              body: TunnelRequest| {
            shadow_clone!(mut redis);

            async move {
                let serialized = serde_json::to_string_pretty(&body).unwrap();

                match redis.get_async_connection().await {
                    Ok(mut conn) => {
                        let channel = format!("signaler.{}.{}.{}", account, project, config_name);
                        info!("publish to channel {}", channel);

                        match conn.publish(channel, serialized).await {
                            Ok(num_recipients) => {
                                info!("delivered to {} recipients", num_recipients);

                                if num_recipients == 0 {
                                    Err(warp::reject::not_found())
                                } else {
                                    Ok(warp::reply::json(&TunnelRequestResponse { num_recipients }))
                                }
                            }
                            Err(e) => {
                                error!("redis server error: {}", e);
                                Err(warp::reject::custom(InternalServerError {}))
                            }
                        }
                    }
                    Err(e) => {
                        error!("redis server connection  error: {}", e);
                        Err(warp::reject::custom(InternalServerError {}))
                    }
                }
            }
        }
    });

    let health = warp::path!("int" / "healthcheck")
        .and(warp::filters::method::get())
        .and_then({
            shadow_clone!(redis);

            move || {
                shadow_clone!(redis);

                async move {
                    let res: Result<String, redis::RedisError> = async move {
                        let mut redis_conn = redis.get_async_connection().await?;
                        let r = redis_conn.set("signaler_healthcheck", "1").await?;
                        Ok(r)
                    }
                    .await;

                    match res {
                        Ok(_) => Ok::<_, warp::reject::Rejection>(warp::http::StatusCode::OK),
                        Err(e) => {
                            error!("health check: redis error: {}", e);
                            Ok::<_, warp::reject::Rejection>(
                                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                            )
                        }
                    }
                }
            }
        });

    let metrics = warp::path!("metrics").map(|| crate::statistics::dump_prometheus());

    info!("Spawning...");
    let (_, server) = warp::serve(
        health
            .or(metrics)
            .or(tunnels_api.with(warp::trace::request())),
    )
    .bind_with_graceful_shutdown(
        listen_addr,
        stop_wait.map(move |r| info!("private HTTP server stop request received: {}", r)),
    );

    server.await;

    info!("private HTTP server stopped");
}

#[derive(Debug)]
pub struct BadInstanceId {}

impl warp::reject::Reject for BadInstanceId {}

#[derive(Debug)]
pub struct InternalServerError {}

impl warp::reject::Reject for InternalServerError {}
