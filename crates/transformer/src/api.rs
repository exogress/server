use crate::{bucket::GcsBucketClient, db::MongoDbClient, helpers::to_vec_body};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use exogress_server_common::{
    crypto::encrypt_stream,
    transformer::{BucketProcessedStored, ProcessRequest, ProcessResponse, ProcessingReady},
};
use futures::{Stream, StreamExt, TryFutureExt, TryStreamExt};
use itertools::Itertools;
use pin_utils::pin_mut;
use std::{
    convert::{TryFrom, TryInto},
    io::Read,
    mem,
    sync::Arc,
};
use tame_oauth::gcp::ServiceAccountAccess;
use warp::{body::json, http::StatusCode, post, reject::Reject, reply::Json, Filter, Rejection};

#[derive(Debug)]
struct ErrorAccepting(anyhow::Error);

impl Reject for ErrorAccepting {}

pub fn api_handler(
    webapp_client: crate::webapp::Client,
    mongodb_client: MongoDbClient,
    gcs_bucket: GcsBucketClient,
) -> warp::filters::BoxedFilter<(impl warp::Reply,)> {
    let client = reqwest::Client::builder().trust_dns(true).build().unwrap();

    let process_request = warp::path!("int_api" / "v1" / "transformations" / "process")
        .and(warp::post())
        .and(warp::body::json())
        .and_then({
            shadow_clone!(mongodb_client, webapp_client, gcs_bucket);

            move |body: ProcessRequest| {
                shadow_clone!(mongodb_client, webapp_client, gcs_bucket);

                async move {
                    let account_unique_id = body.account_unique_id;

                    let result = webapp_client
                        .get_secret_key(&account_unique_id)
                        .and_then(|resp| async {
                            match mongodb_client
                                .find_processed(
                                    &account_unique_id,
                                    &body.identifier,
                                    &body.content_hash,
                                )
                                .await?
                            {
                                Some(processed) => Ok(ProcessResponse::Ready {
                                    formats: processed
                                        .formats
                                        .into_iter()
                                        .map(|processed_format| {
                                            let bucket_info = gcs_bucket.bucket_info();

                                            ProcessingReady {
                                                content_type: processed_format.content_type,
                                                encryption_header: processed_format
                                                    .encryption_header,
                                                compression_ratio: processed_format
                                                    .compression_ratio,
                                                content_len: processed_format.compressed_size
                                                    as u64,
                                                buckets: vec![BucketProcessedStored {
                                                    provider: "gcs".to_string(),
                                                    name: bucket_info.name.into(),
                                                    location: bucket_info.location.to_string(),
                                                }],
                                            }
                                        })
                                        .sorted_by(|l, r| l.content_len.cmp(&r.content_len))
                                        .collect(),
                                    original_content_len: processed.source_size as u64,
                                }),
                                None => Ok(mongodb_client
                                    .find_queued(
                                        account_unique_id,
                                        body.identifier,
                                        body.content_hash,
                                    )
                                    .await?),
                            }
                        })
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
        .and(warp::header::<u64>("content-length"))
        .and(warp::body::stream())
        .and_then(move |upload_id: String, content_length, body_stream| {
            shadow_clone!(mongodb_client, gcs_bucket, webapp_client);

            async move {
                let maybe_queued_info = mongodb_client
                    .get_queued_info_by_upload_id(upload_id.as_str())
                    .await
                    .expect("FIXME");
                let queued_info = match maybe_queued_info {
                    Some(queued_info) => queued_info,
                    None => {
                        return Ok(warp::reply::with_status(
                            "upload not found",
                            StatusCode::NOT_FOUND,
                        ));
                    }
                };

                let secret_key = webapp_client
                    .get_secret_key(&queued_info.account_unique_id)
                    .await
                    .expect("FIXME");

                let path = format!(
                    "{}/uploads/{}",
                    queued_info.account_unique_id, queued_info.identifier
                );

                let (mut encrypted_stream, header) =
                    encrypt_stream(to_vec_body(body_stream), &secret_key).expect("FIXME");

                let mut encrypted_len = 0;

                let encrypted_bytes = encrypted_stream
                    .try_fold(BytesMut::new(), |mut acc, item| {
                        acc.put(item.0.as_ref());
                        encrypted_len += item.1;
                        futures::future::ok(acc)
                    })
                    .await
                    .expect("FIXME");

                gcs_bucket
                    .upload(
                        path.clone(),
                        encrypted_bytes.len() as u64,
                        futures::stream::once(async { Ok(encrypted_bytes) }),
                    )
                    .await
                    .expect("ERROR");

                mongodb_client
                    .was_uploaded(upload_id.as_str(), header)
                    .await
                    .expect("FIXME");

                info!("accept stream for upload_id: {}", upload_id);
                if true {
                    Ok(warp::reply::with_status("ok", StatusCode::OK))
                } else {
                    Err(warp::reject::reject())
                }
            }
        });

    process_request.or(upload_request).boxed()
}
