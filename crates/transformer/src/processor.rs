use crate::{
    bucket::GcsBucketClient,
    db::{listen_queue, MongoDbClient},
    helpers::to_vec_body,
};
use bytes::{BufMut, BytesMut};
use core::mem;
use exogress_server_common::crypto::{decrypt_stream, encrypt_stream};
use futures::{StreamExt, TryStreamExt};
use magick_rust::{MagickWand, ResourceType};
use pin_utils::pin_mut;
use std::{
    convert::TryInto,
    io,
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
use tokio::{task::spawn_blocking, time::sleep};
use tokio_util::compat::FuturesAsyncReadCompatExt;

pub struct Processor {
    lock: tokio::sync::Mutex<()>,
    webapp: crate::webapp::Client,
    db: MongoDbClient,
    gcs_bucket: GcsBucketClient,
    should_stop: Arc<AtomicBool>,
    conversion_threads: Option<u8>,
    conversion_memory: Option<u64>,
}

impl Processor {
    pub fn new(
        conversion_threads: Option<u8>,
        conversion_memory: Option<u64>,
        webapp: crate::webapp::Client,
        db: MongoDbClient,
        gcs_bucket: GcsBucketClient,
        should_stop: Arc<AtomicBool>,
    ) -> Self {
        Processor {
            db,
            lock: tokio::sync::Mutex::new(()),
            gcs_bucket,
            webapp,
            should_stop,
            conversion_threads,
            conversion_memory,
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let db = self.db;
        let lock = Arc::new(self.lock);
        let gcs_bucket = self.gcs_bucket.clone();
        let webapp = self.webapp.clone();

        tokio::spawn({
            shadow_clone!(db);

            async move {
                loop {
                    match db.queue_size().await {
                        Ok(queue_size) => {
                            crate::statistics::QUEUE_SIZE.set(queue_size as i64);
                        }
                        Err(e) => {
                            error!("Error counting queue size: {}", e);
                        }
                    }
                    sleep(Duration::from_secs(10)).await;
                }
            }
        });

        let queued_stream = listen_queue(db.clone(), self.should_stop);

        pin_mut!(queued_stream);

        let conversion_threads = self.conversion_threads;
        let conversion_memory = self.conversion_memory;

        while let Some(request_result) = queued_stream.next().await {
            let guard = lock.clone().lock_owned().await;

            let request = match request_result {
                Err(e) => {
                    error!("Error accepting new request: {:?}", e);
                    break;
                }
                Ok(r) => r,
            };

            tokio::spawn({
                shadow_clone!(db, gcs_bucket, webapp);

                async move {
                    // read upload from GCS

                    let account_unique_id = request.account_unique_id;

                    let secret_key = webapp.get_secret_key(&account_unique_id).await?;

                    let path = format!(
                        "{}/uploads/{}",
                        account_unique_id,
                        request.identifier.clone()
                    );
                    let uploaded_body = gcs_bucket.download(path.clone()).await?;

                    let header = sodiumoxide::crypto::secretstream::Header::from_slice(
                        &base64::decode(request.encryption_header.clone().ok_or_else(|| {
                            anyhow!("no encryption header while processing request")
                        })?)?,
                    )
                    .ok_or_else(|| anyhow!("malformed encryption header"))?;

                    let decrypted = decrypt_stream(
                        FuturesAsyncReadCompatExt::compat(
                            to_vec_body(uploaded_body)
                                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
                                .into_async_read(),
                        ),
                        &secret_key,
                        &header,
                    )?
                    .try_fold(BytesMut::new(), |mut acc, b| async move {
                        acc.extend_from_slice(b.as_ref());
                        Ok(acc)
                    })
                    .await?
                    .freeze();

                    info!("decrypted body len = {}", decrypted.len());

                    let result = spawn_blocking(move || {
                        info!("start conversion");

                        let started_at = crate::statistics::CONVERSION_TIME.start_timer();

                        // convert the body
                        let webp = crate::magick::convert(
                            conversion_threads,
                            conversion_memory,
                            &decrypted,
                            "webp",
                            "image/webp",
                        );
                        let avif = crate::magick::convert(
                            conversion_threads,
                            conversion_memory,
                            &decrypted,
                            "avif",
                            "image/avif",
                        );

                        started_at.observe_duration();

                        info!("finish conversion");
                        (webp, avif)
                    })
                    .await;

                    info!("blocking conversion finished. save result");

                    let identifier = request.identifier.clone();

                    let after_processed = async move {
                        let secret_key = webapp.get_secret_key(&account_unique_id).await?;

                        gcs_bucket.delete(path).await?;

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
                                            encrypt_stream(transformed_stream, &secret_key)?;

                                        let encrypted_buf = encrypted
                                            .try_fold(BytesMut::new(), |mut acc, v| {
                                                acc.put(v.0.as_ref());
                                                futures::future::ok(acc)
                                            })
                                            .await?;

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
                                        encrypt_stream(transformed_stream, &secret_key)?;

                                    let encrypted_buf = encrypted
                                        .try_fold(BytesMut::new(), |mut acc, v| {
                                            acc.put(v.0.as_ref());
                                            futures::future::ok(acc)
                                        })
                                        .await?;

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

                            db.save_processed(uploads, request).await?;
                        }

                        mem::drop(guard);

                        Ok::<_, anyhow::Error>(())
                    };

                    tokio::spawn(after_processed);

                    Ok::<_, anyhow::Error>(())
                }
            });
        }

        // wait until all permits are returned
        info!("Wait for all outstanding conversions to finish");
        let _ = lock.lock().await;
        info!("no more processing tasks left. Exiting");

        Ok(())
    }
}
