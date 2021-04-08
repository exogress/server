//! Worker pool for processing

use crate::{
    bucket::GcsBucketClient,
    db::{MongoDbClient, QueuedRequest},
    helpers::to_vec_body,
};
use bytes::{BufMut, Bytes, BytesMut};
use core::mem;
use exogress_server_common::crypto::{decrypt_stream, encrypt_stream};
use futures::TryStreamExt;
use itertools::Itertools;
use pin_utils::pin_mut;
use std::{io, sync::Arc, time::Duration};
use tokio::{sync::mpsc, task::spawn_blocking};
use tokio_stream::StreamExt;
use tokio_util::compat::FuturesAsyncReadCompatExt;

pub struct Processor {
    rx: mpsc::Receiver<QueuedRequest>,
    semaphore: tokio::sync::Semaphore,
    webapp: crate::webapp::Client,
    db: MongoDbClient,
    gcs_bucket: GcsBucketClient,
}

impl Processor {
    pub fn new(
        num_threads: usize,
        webapp: crate::webapp::Client,
        db: MongoDbClient,
        gcs_bucket: GcsBucketClient,
        rx: mpsc::Receiver<QueuedRequest>,
    ) -> Self {
        Processor {
            db,
            rx,
            semaphore: tokio::sync::Semaphore::new(num_threads),
            gcs_bucket,
            webapp,
        }
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        let db = self.db;
        let semaphore = Arc::new(self.semaphore);
        let gcs_bucket = self.gcs_bucket.clone();
        let webapp = self.webapp.clone();

        while let Some(request) = self.rx.recv().await {
            tokio::spawn({
                shadow_clone!(db, gcs_bucket, semaphore, webapp);

                async move {
                    // read upload from GCS

                    let account_unique_id = request.account_unique_id.clone();

                    let secret_key = webapp
                        .get_secret_key(&account_unique_id)
                        .await
                        .expect("FIXME");

                    let path = format!(
                        "{}/uploads/{}",
                        account_unique_id,
                        request.identifier.clone()
                    );
                    let uploaded_body = gcs_bucket.download(path.clone()).await.expect("FIXME");

                    info!("encryption heaer = {:?}", request);

                    let header = sodiumoxide::crypto::secretstream::Header::from_slice(
                        &base64::decode(request.encryption_header.clone().expect("FIXME"))
                            .expect("FIXME"),
                    )
                    .expect("FIXME");

                    let decrypted = decrypt_stream(
                        FuturesAsyncReadCompatExt::compat(
                            to_vec_body(uploaded_body)
                                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
                                .into_async_read(),
                        ),
                        &secret_key,
                        &header,
                    )
                    .expect("FIXME")
                    .try_fold(BytesMut::new(), |mut acc, b| async move {
                        acc.extend_from_slice(b.as_ref());
                        Ok(acc)
                    })
                    .await
                    .expect("FIXME")
                    .freeze();

                    info!("upload body = {:?}", decrypted.len());

                    let permit = semaphore.acquire().await.expect("FIXME");
                    let result = spawn_blocking(move || {
                        // convert the body
                        let webp = crate::magick::convert(&decrypted, "webp", "image/webp");
                        let avif = crate::magick::convert(&decrypted, "avif", "image/avif");

                        (webp, avif)
                    })
                    .await;

                    info!("conversion result = {:?}", result);
                    mem::drop(permit);
                    let identifier = request.identifier.clone();

                    let after_processed = async move {
                        let secret_key = webapp
                            .get_secret_key(&account_unique_id)
                            .await
                            .expect("FIXME");

                        gcs_bucket.delete(path).await.expect("FIXME");

                        if let Ok((webp_result, avif_result)) = result {
                            let upload_webp = {
                                shadow_clone!(identifier, gcs_bucket, secret_key);

                                async move {
                                    if let Ok(webp) = webp_result {
                                        let transformed = webp.transformed;
                                        let meta = webp.meta;
                                        let webp_path = format!(
                                            "{}/processed/{}.webp",
                                            account_unique_id,
                                            identifier.clone()
                                        );

                                        let transformed_stream = futures::stream::once(async {
                                            Ok::<_, warp::Error>(transformed)
                                        });

                                        pin_mut!(transformed_stream);

                                        let (encrypted, header) =
                                            encrypt_stream(transformed_stream, &secret_key)
                                                .expect("FIXME");

                                        let encrypted_buf = encrypted
                                            .try_fold(BytesMut::new(), |mut acc, v| {
                                                acc.put(v.0.as_ref());
                                                futures::future::ok(acc)
                                            })
                                            .await
                                            .expect("FIXME");

                                        gcs_bucket
                                            .upload(
                                                webp_path,
                                                encrypted_buf.len() as u64,
                                                futures::stream::once(async { Ok(encrypted_buf) }),
                                            )
                                            .await?;
                                        Ok::<_, anyhow::Error>(Some((meta, header)))
                                    } else {
                                        Ok(None)
                                    }
                                }
                            };

                            let upload_avif = async move {
                                if let Ok(avif) = avif_result {
                                    let transformed = avif.transformed;
                                    let meta = avif.meta;
                                    let avif_path = format!(
                                        "{}/processed/{}.avif",
                                        account_unique_id, identifier
                                    );

                                    let transformed_stream = futures::stream::once(async {
                                        Ok::<_, warp::Error>(transformed)
                                    });

                                    pin_mut!(transformed_stream);

                                    let (encrypted, header) =
                                        encrypt_stream(transformed_stream, &secret_key)
                                            .expect("FIXME");

                                    let encrypted_buf = encrypted
                                        .try_fold(BytesMut::new(), |mut acc, v| {
                                            acc.put(v.0.as_ref());
                                            futures::future::ok(acc)
                                        })
                                        .await
                                        .expect("FIXME");

                                    gcs_bucket
                                        .upload(
                                            avif_path,
                                            encrypted_buf.len() as u64,
                                            futures::stream::once(async { Ok(encrypted_buf) }),
                                        )
                                        .await?;
                                    Ok::<_, anyhow::Error>(Some((meta, header)))
                                } else {
                                    Ok(None)
                                }
                            };

                            let uploads: Vec<_> = {
                                let (a, b) = futures::future::join(upload_webp, upload_avif).await;
                                vec![a, b]
                                    .into_iter()
                                    .filter_map(|c| c.ok().flatten())
                                    .collect()
                            };

                            db.save_processed(uploads, request).await.expect("FIXME");
                        }
                    };

                    tokio::spawn(after_processed);
                }
            });
        }

        Ok(())
    }
}
