use crate::{mongodb::Account, service::Service};
use exogress_common::{
    api::InvalidationRequest,
    entities::{AccountName, ProjectName, RequestId},
};
use futures::prelude::*;
use rweb::{http::StatusCode, *};
use std::{borrow::Cow, convert::Infallible, net::SocketAddr};
use stop_handle::StopWait;

#[derive(Debug)]
enum ApiError {
    InternalServerError,
    Unauthorized,
    ProjectNotFound,
    RequestIdNotFound,
    InvalidationError { err: String },
}

impl rweb::reject::Reject for ApiError {}

#[derive(Debug)]
enum Authorization {
    None,
    Session(String),
    Jwt(String),
}

fn authorization() -> impl Filter<Extract = (Authorization,), Error = Rejection> + Copy {
    let jwt = rweb::header("authorization").and_then(|jwt: String| async move {
        if let Some(token) = jwt.strip_prefix("Bearer ") {
            Ok::<_, Rejection>(Authorization::Jwt(token.to_string()))
        } else {
            Err(rweb::reject::reject())
        }
    });
    let session = rweb::cookie("session")
        .and_then(|s| async move { Ok::<_, Rejection>(Authorization::Session(s)) });

    jwt.or(session)
        .unify()
        .or_else(|_| async move { Ok::<_, Rejection>((Authorization::None,)) })
}

async fn require_account(
    authorization: Authorization,
    expected_account_name: &AccountName,
    service: &mut Service,
) -> Result<Account, Rejection> {
    let account = match authorization {
        Authorization::None => {
            return Err(rweb::reject::custom(ApiError::Unauthorized));
        }
        Authorization::Session(session_cookie) => {
            match service
                .find_user_by_session_id(session_cookie.as_ref())
                .await
            {
                Ok(Some(user_id)) => {
                    match service.find_account(user_id, &expected_account_name).await {
                        Ok(Some(found_account)) if expected_account_name == &found_account.name => {
                            found_account
                        }
                        Ok(Some(_)) => {
                            return Err(rweb::reject::custom(ApiError::Unauthorized));
                        }
                        Ok(None) => {
                            return Err(rweb::reject::custom(ApiError::Unauthorized));
                        }
                        Err(e) => {
                            error!("Error finding account when validating cookie auth: {}", e);
                            return Err(rweb::reject::custom(ApiError::InternalServerError));
                        }
                    }
                }
                Ok(None) => {
                    return Err(rweb::reject::custom(ApiError::Unauthorized));
                }
                Err(e) => {
                    error!("Error checking cookie auth: {}", e);
                    return Err(rweb::reject::custom(ApiError::InternalServerError));
                }
            }
        }
        Authorization::Jwt(jwt) => match service.find_account_by_bearer_token(jwt.as_ref()).await {
            Ok(Some(found_account)) if expected_account_name == &found_account.name => {
                found_account
            }
            Ok(Some(_)) => {
                return Err(rweb::reject::custom(ApiError::Unauthorized));
            }
            Err(e) => {
                error!("Error checking bearer auth: {}", e);
                return Err(rweb::reject::custom(ApiError::InternalServerError));
            }
            Ok(None) => {
                return Err(rweb::reject::custom(ApiError::Unauthorized));
            }
        },
    };

    Ok(account)
}

#[allow(unused_mut)]
#[get("/api/v1/accounts/{account_name}/projects/{project_name}/requests/{request_id}")]
#[openapi(summary = "get log entry by request_id")]
async fn request_info(
    account_name: AccountName,
    project_name: ProjectName,
    request_id: RequestId,
    #[filter = "authorization"] authorization: Authorization,
    #[data] mut service: Service,
) -> Result<Json<serde_json::Value>, Rejection> {
    let account = require_account(authorization, &account_name, &mut service).await?;

    match service.find_project(&account, &project_name).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err(rweb::reject::custom(ApiError::ProjectNotFound));
        }
        Err(e) => {
            error!("Error finding project: {}", e);
            return Err(rweb::reject::custom(ApiError::InternalServerError));
        }
    };

    match service
        .find_request_by_request_id(&account.unique_id, &request_id)
        .await
    {
        Ok(Some(r)) => Ok(r.into()),
        Ok(None) => Err(rweb::reject::custom(ApiError::RequestIdNotFound)),
        Err(e) => {
            error!("Error searching in elasticsearch: {}", e);
            Err(rweb::reject::custom(ApiError::InternalServerError))
        }
    }
}

#[allow(unused_mut)]
#[post("/api/v1/accounts/{account_name}/projects/{project_name}/invalidate")]
#[openapi(summary = "invalidate cache")]
async fn invalidate_cache(
    account_name: AccountName,
    project_name: ProjectName,
    #[json] req: InvalidationRequest,
    #[filter = "authorization"] authorization: Authorization,
    #[data] mut service: Service,
) -> Result<Json<InvalidationOk>, Rejection> {
    let account = require_account(authorization, &account_name, &mut service).await?;

    match service
        .invalidate_groups(&account, &project_name, &req.groups)
        .await
    {
        Ok(()) => Ok(InvalidationOk { status: "ok" }.into()),
        Err(e) => {
            error!("Error invalidating group: {}", e);
            Err(rweb::reject::custom(ApiError::InvalidationError {
                err: e.to_string(),
            }))
        }
    }
}

#[get("/api/v1/regions")]
#[openapi(summary = "get list of regions")]
async fn regions(#[data] service: Service) -> Result<impl Reply, Rejection> {
    match service.get_regions().await {
        Ok(regions) => Ok(rweb::reply::json(&regions)),
        Err(e) => {
            error!("Error getting regions: {}", e);
            Err(rweb::reject::custom(ApiError::InternalServerError))
        }
    }
}

#[get("/metrics")]
fn metrics() -> String {
    crate::statistics::dump_prometheus()
}

#[get("/int/healthcheck")]
async fn healthcheck(#[data] service: Service) -> Result<impl Reply, Rejection> {
    if !service.health().await {
        Err(rweb::reject::custom(ApiError::InternalServerError))
    } else {
        Ok(rweb::reply())
    }
}

pub async fn run_http_server(
    service: crate::service::Service,
    listen_addr: SocketAddr,
    stop_wait: StopWait<crate::termination::StopReason>,
) {
    let heathcheck_with_state = healthcheck(service.clone());
    let regions_with_state = regions(service.clone());
    let request_info_with_state = request_info(service.clone());
    let invalidate_cache_with_state = invalidate_cache(service.clone());

    info!("Spawning...");

    let (spec, filter) = openapi::spec().build(move || {
        regions_with_state
            .or(request_info_with_state)
            .or(invalidate_cache_with_state)
    });

    rweb::serve(
        filter
            .or(openapi_docs(spec))
            .or(heathcheck_with_state)
            .or(metrics())
            .recover(handle_rejection),
    )
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
    message: Cow<'static, str>,
}

#[derive(Serialize, Schema)]
struct InvalidationOk {
    status: &'static str,
}

// impl ResponseEntity for InvalidationOk {
//     fn describe_responses() -> Responses {
//         Default::default()
//     }
// }

async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
    let code;
    let message;

    if let Some(err) = err.find::<ApiError>() {
        match err {
            ApiError::InternalServerError => {
                code = StatusCode::INTERNAL_SERVER_ERROR;
                message = Cow::Borrowed("internal server error");
            }
            ApiError::Unauthorized => {
                code = StatusCode::UNAUTHORIZED;
                message = Cow::Borrowed("unauthorized");
            }
            ApiError::ProjectNotFound => {
                code = StatusCode::NOT_FOUND;
                message = Cow::Borrowed("project not found");
            }
            ApiError::RequestIdNotFound => {
                code = StatusCode::NOT_FOUND;
                message = Cow::Borrowed("request_id not found");
            }
            ApiError::InvalidationError { err } => {
                code = StatusCode::BAD_REQUEST;
                message = format!("invalidation error: {}", err).into();
            }
        }
    } else if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = Cow::Borrowed("not found");
    } else {
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = Cow::Borrowed("internal server error");
    }

    let json = rweb::reply::json(&ErrorMessage {
        code: code.as_u16(),
        message: message.into(),
    });

    Ok(rweb::reply::with_status(json, code))
}
