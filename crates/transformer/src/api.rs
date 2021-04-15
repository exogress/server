use crate::{bucket::GcsBucketClient, db::MongoDbClient, helpers::to_vec_body};
use bytes::{Buf, BufMut, BytesMut};
use exogress_server_common::{
    crypto::encrypt_stream,
    transformer::{ProcessRequest, ProcessResponse, ProcessingReady, MAX_SIZE_FOR_TRANSFORMATION},
};
use futures::{Stream, TryStreamExt};
use warp::{http::StatusCode, reject::Reject, Filter, Rejection};

#[derive(Debug)]
struct ErrorAccepting(anyhow::Error);

impl Reject for ErrorAccepting {}

#[derive(thiserror::Error, Debug)]
enum UploadError {
    #[error("save upload to bucket error: {_0}")]
    SaveUpload(anyhow::Error),

    #[error("encryption error: {_0}")]
    Encryption(anyhow::Error),

    #[error("accepting upload error: {_0}")]
    ReadBody(warp::Error),

    #[error("upload_id not found")]
    UploadIdNotFound,

    #[error("account error: {_0}")]
    Account(anyhow::Error),

    #[error("mongo error: {_0}")]
    Mongo(anyhow::Error),
}

async fn handle_upload_request(
    upload_id: &str,
    body_stream: impl Stream<Item = Result<impl Buf, warp::Error>> + Send + Sync + Unpin + 'static,
    mongodb_client: &MongoDbClient,
    gcs_bucket: &GcsBucketClient,
    webapp_client: &crate::webapp::Client,
) -> Result<(), UploadError> {
    let maybe_queued_info = mongodb_client
        .get_queued_info_by_upload_id(upload_id)
        .await
        .map_err(UploadError::Mongo)?;
    let queued_info = match maybe_queued_info {
        Some(queued_info) => queued_info,
        None => {
            return Err(UploadError::UploadIdNotFound);
        }
    };

    let secret_key = webapp_client
        .get_secret_key(&queued_info.account_unique_id)
        .await
        .map_err(UploadError::Account)?;

    let path = format!(
        "{}/uploads/{}",
        queued_info.account_unique_id, queued_info.content_hash
    );

    let (encrypted_stream, header) =
        encrypt_stream(to_vec_body(body_stream), &secret_key).map_err(UploadError::Encryption)?;

    let mut encrypted_len = 0;

    let encrypted_bytes = encrypted_stream
        .try_fold(BytesMut::new(), |mut acc, item| {
            acc.put(item.0.as_ref());
            encrypted_len += item.1;
            futures::future::ok(acc)
        })
        .await
        .map_err(UploadError::ReadBody)?;

    gcs_bucket
        .upload(
            path.clone(),
            encrypted_bytes.len() as u64,
            futures::stream::once(async { Ok(encrypted_bytes) }),
        )
        .await
        .map_err(UploadError::SaveUpload)?;

    mongodb_client
        .was_uploaded(upload_id, header)
        .await
        .map_err(UploadError::Mongo)?;

    Ok(())
}

pub fn api_handler(
    webapp_client: crate::webapp::Client,
    mongodb_client: MongoDbClient,
    gcs_bucket: GcsBucketClient,
) -> warp::filters::BoxedFilter<(impl warp::Reply,)> {
    let process_request = warp::path!("int_api" / "v1" / "transformations" / "content")
        .and(warp::post())
        .and(warp::body::json())
        .and_then({
            shadow_clone!(mongodb_client, webapp_client, gcs_bucket);

            move |body: ProcessRequest| {
                shadow_clone!(mongodb_client, webapp_client, gcs_bucket);

                async move {
                    let account_unique_id = body.account_unique_id;

                    let result: anyhow::Result<_> = async {
                        let res = mongodb_client
                            .find_processed(&account_unique_id, &body.content_hash)
                            .await?;
                        match res {
                            Some(processed) => Ok(ProcessResponse::Ready(ProcessingReady {
                                formats: processed.formats,
                                original_content_len: processed.source_size as u64,
                                transformed_at: processed.transformation_started_at,
                            })),
                            None => Ok(mongodb_client
                                .find_queued_or_create_upload(
                                    account_unique_id,
                                    &body.content_hash,
                                    &body.content_type,
                                )
                                .await?),
                        }
                    }
                    .await;

                    match result {
                        Ok(r) => Ok(warp::reply::json(&r)),
                        Err(e) => {
                            error!("error accepting object for processing: {:?}", e);
                            Err(warp::reject::custom(ErrorAccepting(e)))
                        }
                    }
                }
            }
        });

    let upload_request = warp::path!("int_api" / "v1" / "transformations" / "uploads" / String)
        .and(warp::post())
        .and(warp::filters::body::content_length_limit(
            MAX_SIZE_FOR_TRANSFORMATION,
        ))
        .and(warp::body::stream())
        .and_then(move |upload_id: String, body_stream| {
            shadow_clone!(mongodb_client, gcs_bucket, webapp_client);

            async move {
                let res = handle_upload_request(
                    &upload_id,
                    body_stream,
                    &mongodb_client,
                    &gcs_bucket,
                    &webapp_client,
                )
                .await;

                match res {
                    Ok(()) => Ok::<_, Rejection>(warp::reply::with_status("ok", StatusCode::OK)),
                    Err(UploadError::UploadIdNotFound) => Ok(warp::reply::with_status(
                        "upload_id not found",
                        StatusCode::NOT_FOUND,
                    )),
                    Err(e) => {
                        error!("Error serving upload request: {}", e);
                        Ok(warp::reply::with_status(
                            "server error",
                            StatusCode::INTERNAL_SERVER_ERROR,
                        ))
                    }
                }
            }
        });

    process_request.or(upload_request).boxed()
}
