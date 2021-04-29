use exogress_common::entities::{AccountName, ProjectName, Ulid};
use futures::prelude::*;
use std::{convert::Infallible, net::SocketAddr};
use stop_handle::StopWait;
use warp::{http::StatusCode, Filter, Rejection, Reply};

#[derive(Debug)]
enum ApiError {
    InternalServerError,
    Unauthorized,
    ProjectNotFound,
    RequestIdNotFound,
}

impl warp::reject::Reject for ApiError {}

pub async fn run_http_server(
    service: crate::service::Service,
    listen_addr: SocketAddr,
    stop_wait: StopWait<crate::termination::StopReason>,
) {
    let request_info = warp::path!(
        "api" / "v0" / "accounts" / AccountName / "projects" / ProjectName / "requests" / Ulid
    )
    .and(warp::filters::method::get())
    .and(warp::filters::cookie::optional("session"))
    .and(warp::header::optional("authorization"))
    .and_then({
        shadow_clone!(service);

        move |account_name: AccountName,
              project_name: ProjectName,
              request_id: Ulid,
              maybe_session_cookie: Option<String>,
              maybe_authorization_header: Option<String>| {
            shadow_clone!(mut service);

            async move {
                let mut account = if let Some(session_cookie) = maybe_session_cookie {
                    match service
                        .find_user_by_session_id(session_cookie.as_ref())
                        .await
                    {
                        Ok(Some(user_id)) => {
                            match service.find_account(user_id, &account_name).await {
                                Ok(maybe_account) => maybe_account,
                                Err(e) => {
                                    error!(
                                        "Error finding account when validating cookie auth: {}",
                                        e
                                    );
                                    return Err(warp::reject::custom(
                                        ApiError::InternalServerError,
                                    ));
                                }
                            }
                        }
                        Ok(None) => None,
                        Err(e) => {
                            error!("Error checking cookie auth: {}", e);
                            return Err(warp::reject::custom(ApiError::InternalServerError));
                        }
                    }
                } else {
                    None
                };

                if account.is_none() {
                    if let Some(auth_header) = maybe_authorization_header {
                        if let Some(token) = auth_header.strip_prefix("Bearer ") {
                            match service.find_account_by_bearer_token(token).await {
                                Ok(Some(found_account)) => {
                                    if &account_name == &found_account.name {
                                        account = Some(found_account)
                                    }
                                }
                                Ok(None) => {}
                                Err(e) => {
                                    error!("Error checking bearer auth: {}", e);
                                    return Err(warp::reject::custom(
                                        ApiError::InternalServerError,
                                    ));
                                }
                            }
                        }
                    }
                }

                let account = if let Some(account) = account {
                    account
                } else {
                    return Err(warp::reject::custom(ApiError::Unauthorized));
                };

                match service.find_project(&account, &project_name).await {
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        return Err(warp::reject::custom(ApiError::ProjectNotFound));
                    }
                    Err(e) => {
                        error!("Error finding project: {}", e);
                        return Err(warp::reject::custom(ApiError::InternalServerError));
                    }
                };

                match service.find_request_by_request_id(&request_id).await {
                    Ok(Some(r)) => Ok(warp::reply::json(&r)),
                    Ok(None) => Err(warp::reject::custom(ApiError::RequestIdNotFound)),
                    Err(_e) => Err(warp::reject::custom(ApiError::InternalServerError)),
                }
            }
        }
    });

    // let health = warp::path!("int" / "healthcheck")
    //     .and(warp::filters::method::get())
    //     .and_then({
    //         move || {
    //
    //             async move {
    //                 let res = async move {
    //                     let mut redis_conn = redis.get_async_connection().await?;
    //                     let r = redis_conn.set("assistant_healthcheck", "1").await?;
    //                     Ok::<String, redis::RedisError>(r)
    //                 }
    //                     .await;
    //
    //                 if let Err(e) = res {
    //                     error!("health check: redis error: {}", e);
    //                     return Ok::<_, warp::reject::Rejection>(
    //                         warp::http::StatusCode::INTERNAL_SERVER_ERROR,
    //                     );
    //                 }
    //
    //                 if !elastic_client.health().await {
    //                     return Ok::<_, warp::reject::Rejection>(
    //                         warp::http::StatusCode::INTERNAL_SERVER_ERROR,
    //                     );
    //                 }
    //
    //                 if !db_client.health().await {
    //                     return Ok::<_, warp::reject::Rejection>(
    //                         warp::http::StatusCode::INTERNAL_SERVER_ERROR,
    //                     );
    //                 }
    //
    //                 Ok::<_, warp::reject::Rejection>(warp::http::StatusCode::OK)
    //             }
    //         }
    //     });

    let metrics = warp::path!("metrics").map(|| crate::statistics::dump_prometheus());

    info!("Spawning...");

    let combined = warp::serve(request_info.or(metrics).recover(handle_rejection));

    combined
        .bind_with_graceful_shutdown(
            listen_addr,
            stop_wait.map(move |r| info!("HTTP server stop request received: {}", r)),
        )
        .1
        .await;
}

// An API error serializable to JSON.
#[derive(Serialize)]
struct ErrorMessage {
    code: u16,
    message: String,
}

async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
    let code;
    let message;

    if let Some(err) = err.find::<ApiError>() {
        match err {
            ApiError::InternalServerError => {
                code = StatusCode::INTERNAL_SERVER_ERROR;
                message = "internal server error";
            }
            ApiError::Unauthorized => {
                code = StatusCode::UNAUTHORIZED;
                message = "unauthorized";
            }
            ApiError::ProjectNotFound => {
                code = StatusCode::NOT_FOUND;
                message = "project not found";
            }
            ApiError::RequestIdNotFound => {
                code = StatusCode::NOT_FOUND;
                message = "request_id not found";
            }
        }
    } else if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "not found";
    } else {
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = "internal server error";
    }

    let json = warp::reply::json(&ErrorMessage {
        code: code.as_u16(),
        message: message.into(),
    });

    Ok(warp::reply::with_status(json, code))
}
