use crate::{
    elasticsearch::ElasticsearchClient, reporting::MongoDbClient, termination::StopReason,
};
use futures::FutureExt;
use std::net::SocketAddr;
use stop_handle::{StopHandle, StopWait};
use warp::Filter;

pub async fn server(
    listen_addr: SocketAddr,
    db_client: MongoDbClient,
    elastic_client: ElasticsearchClient,
    stop_handle: StopHandle<StopReason>,
    stop_wait: StopWait<StopReason>,
) {
    info!("Will spawn HTTP server on {}", listen_addr);

    let health = warp::path!("int" / "healthcheck")
        .and(warp::filters::method::get())
        .and_then({
            shadow_clone!(db_client, elastic_client);

            move || {
                shadow_clone!(db_client, elastic_client);

                async move {
                    if !elastic_client.health().await {
                        return Ok::<_, warp::reject::Rejection>(
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        );
                    }

                    if !db_client.health().await {
                        return Ok::<_, warp::reject::Rejection>(
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        );
                    }

                    Ok::<_, warp::reject::Rejection>(warp::http::StatusCode::OK)
                }
            }
        });

    let metrics = warp::path!("metrics").map(crate::statistics::dump_prometheus);

    info!("Spawning...");

    let combined = warp::serve(metrics.or(health));

    combined
        .bind_with_graceful_shutdown(
            listen_addr,
            stop_wait.map(move |r| info!("private HTTP server stop request received: {}", r)),
        )
        .1
        .await;

    info!("HTTP server stopped");
}

#[derive(Debug)]
pub struct InternalServerError {}

impl warp::reject::Reject for InternalServerError {}
