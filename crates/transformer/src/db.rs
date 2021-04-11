use crate::magick::ImageConversionMeta;
use bson::{doc, serde_helpers::chrono_datetime_as_bson_datetime};
use chrono::{DateTime, Utc};
use exogress_common::entities::{AccountUniqueId, Ulid};
use exogress_server_common::transformer::ProcessResponse;
use futures::Stream;
use lazy_static::lazy_static;
use mongodb::{
    options::{FindOneAndReplaceOptions, FindOneAndUpdateOptions, FindOneOptions, ReturnDocument},
    Collection,
};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::secretstream::Header;
use std::{
    convert::TryInto,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::time::sleep;

const QUEUE_COLLECTION: &str = "queue";
const PROCESSED_COLLECTION: &str = "processed";

lazy_static! {
    static ref UPLOAD_TTL: chrono::Duration = chrono::Duration::seconds(30);
    static ref PROCESSING_MAX_TIME: chrono::Duration = chrono::Duration::minutes(1);
}

#[derive(Clone)]
pub struct MongoDbClient {
    db: mongodb::Database,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueueState {
    #[serde(rename = "pending_upload")]
    PendingUpload,

    #[serde(rename = "data_received")]
    UploadReceived,
}

pub mod optionally_chrono_datetime_as_bson_datetime {
    use chrono::Utc;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::result::Result;

    /// Deserializes a chrono::DateTime from a bson::DateTime.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<chrono::DateTime<Utc>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let datetime = Option::<bson::DateTime>::deserialize(deserializer)?;
        Ok(datetime.map(|dt| dt.into()))
    }

    /// Serializes a chrono::DateTime as a bson::DateTime.
    pub fn serialize<S: Serializer>(
        val: &Option<chrono::DateTime<Utc>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let datetime = val.map(|datetime| bson::DateTime::from(datetime.to_owned()));
        datetime.serialize(serializer)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedRequest {
    pub identifier: String,
    #[serde(default)]
    pub encryption_header: Option<String>,
    pub account_unique_id: AccountUniqueId,
    pub content_hash: String,
    #[serde(with = "chrono_datetime_as_bson_datetime")]
    pub last_requested_at: chrono::DateTime<chrono::Utc>,
    pub num_requests: i64,
    #[serde(with = "chrono_datetime_as_bson_datetime")]
    pub upload_requested_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub upload_id: Option<Ulid>,

    #[serde(default, with = "optionally_chrono_datetime_as_bson_datetime")]
    pub start_processing_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl QueuedRequest {
    fn is_processing(&self) -> bool {
        self.start_processing_at.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessedFormat {
    pub content_type: String,
    pub encryption_header: String,
    pub compressed_size: i64,
    pub compression_ratio: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Processed {
    pub identifier: String,
    pub account_unique_id: AccountUniqueId,
    pub source_size: i64,
    pub content_hash: String,
    #[serde(with = "chrono_datetime_as_bson_datetime")]
    pub last_requested_at: chrono::DateTime<chrono::Utc>,
    pub num_requests: i64,
    pub formats: Vec<ProcessedFormat>,
}

pub fn listen_queue(
    client: MongoDbClient,
    should_stop: Arc<AtomicBool>,
) -> impl Stream<Item = Result<QueuedRequest, mongodb::error::Error>> {
    let collection: Collection<QueuedRequest> = client.db.collection(QUEUE_COLLECTION);
    async_stream::stream! {
        loop {
            if should_stop.load(Ordering::Relaxed) {
                info!("Processing queue will not longer accept new tasks beacuse stop request received");
                return;
            }

            let options = FindOneAndUpdateOptions::builder()
                .sort(doc! { "num_requests": -1, "last_requested_at": -1 })
                .return_document(ReturnDocument::After)
                .build();
            let found = collection
                .find_one_and_update(
                    doc! {
                        "start_processing_at": {"$exists":false},
                        "upload_id": {"$exists":false},
                    },
                    doc! {
                        "$set": {
                            "start_processing_at": Utc::now(),
                        }
                    },
                    options,
                )
                .await?;
            if let Some(request) = found {
                yield Ok(request);
            } else {
                sleep(Duration::from_millis(500)).await;
            }
        }
    }
}

impl MongoDbClient {
    pub async fn new(url: &str, db: &str) -> Result<Self, anyhow::Error> {
        let mongodb_client_options = mongodb::options::ClientOptions::parse(&url).await?;

        info!("mongodb_client_options = {:?}", mongodb_client_options);
        let mongodb_client = mongodb::Client::with_options(mongodb_client_options)?;

        let db = mongodb_client.database(db);

        db.run_command(
            doc! {
                "createIndexes": PROCESSED_COLLECTION,
                "indexes": [
                    {
                        "key": {
                            "account_unique_id": 1,
                            "content_hash": 1,
                            "identifier": 1,
                        },
                        "name": "processed_account_unique_id_content_hash_identifier_index",
                        "unique": true
                    },
                    {
                        "key": {
                            "account_unique_id": 1,
                            "content_hash": 1,
                        },
                        "name": "processed_account_unique_id_content_hash_index",
                        "unique": true
                    },
                    {
                        "key": {
                            "account_unique_id": 1,
                            "identifier": 1,
                        },
                        "name": "processed_account_unique_id_identifier_index",
                        "unique": true
                    }
                ]
            },
            None,
        )
        .await?;

        db.run_command(
            doc! {
                "createIndexes": QUEUE_COLLECTION,
                "indexes": [
                    {
                        "key": {
                            "account_unique_id": 1,
                            "content_hash": 1,
                            "identifier": 1,
                        },
                        "name": "queued_account_unique_id_content_hash_identifier_index",
                        "unique": true
                    },
                    {
                        "key": {
                            "account_unique_id": 1,
                            "content_hash": 1,
                        },
                        "name": "queued_account_unique_id_content_hash_index",
                        "unique": true
                    },
                    {
                        "key": {
                            "account_unique_id": 1,
                            "identifier": 1,
                        },
                        "name": "queued_account_unique_id_identifier_index",
                        "unique": true
                    },
                    {
                        "key": {
                            "upload_id": 1,
                        },
                        "name": "queued_upload_id_index",
                        "unique": true
                    },
                    {
                        "key": {
                            "upload_requested_at": 1,
                        },
                        "name": "queued_upload_requested_at_index",
                        "unique": true
                    },
                    {
                        "key": {
                            "num_requests": -1,
                            "last_requested_at": -1,
                        },
                        "name": "queued_ordering_index"
                    }
                ]
            },
            None,
        )
        .await?;

        let client = MongoDbClient { db };

        Ok(client)
    }

    pub async fn queue_size(&self) -> anyhow::Result<u32> {
        let collection = self.db.collection::<bson::Document>(QUEUE_COLLECTION);
        Ok(collection
            .count_documents(
                doc! {
                    "start_processing_at": {"$exists":false},
                    "upload_id": {"$exists":false},
                },
                None,
            )
            .await?
            .try_into()
            .unwrap())
    }

    async fn cleanup_outdated_uploads(&self, now: DateTime<Utc>) -> anyhow::Result<()> {
        let collection = self.db.collection::<bson::Document>(QUEUE_COLLECTION);

        // Cleanup outdated upload requests
        collection
            .delete_many(
                doc! {
                    "$or": [
                        {"upload_requested_at": { "$lt": now - *UPLOAD_TTL } },
                        {"start_processing_at": { "$lt": now - *PROCESSING_MAX_TIME } },
                    ]
                },
                None,
            )
            .await?;

        Ok(())
    }

    pub(crate) async fn get_queued_info_by_upload_id(
        &self,
        upload_id: &str,
    ) -> anyhow::Result<Option<QueuedRequest>> {
        let collection = self.db.collection::<QueuedRequest>(QUEUE_COLLECTION);
        let now = Utc::now();

        self.cleanup_outdated_uploads(now).await?;

        let filter = doc! {
            "upload_id": upload_id,
        };
        let find_one_options = FindOneOptions::builder().build();
        Ok(collection.find_one(filter, find_one_options).await?)
    }

    pub(crate) async fn was_uploaded(
        &self,
        upload_id: &str,
        header: sodiumoxide::crypto::secretstream::Header,
    ) -> anyhow::Result<()> {
        let collection = self.db.collection::<bson::Document>(QUEUE_COLLECTION);
        let filter = doc! {
            "upload_id": upload_id
        };
        let find_options = FindOneAndUpdateOptions::builder().upsert(false).build();
        collection
            .find_one_and_update(
                filter,
                doc! {
                    "$unset": {
                        "upload_id": "",
                    },
                    "$set": {
                        "encryption_header": base64::encode(header.as_ref())
                    }
                },
                Some(find_options),
            )
            .await?;

        Ok(())
    }

    pub async fn health(&self) -> bool {
        let r =
            tokio::time::timeout(Duration::from_secs(5), self.db.list_collection_names(None)).await;
        match r {
            Ok(Ok(_)) => true,
            Ok(Err(e)) => {
                error!("mongo health error: {}", e);
                false
            }
            Err(_e) => {
                error!("mongo timeout");
                false
            }
        }
    }

    pub async fn find_queued(
        &self,
        account_unique_id: AccountUniqueId,
        identifier: String,
        content_hash: String,
    ) -> anyhow::Result<ProcessResponse> {
        let now = Utc::now();
        let queue_collection = self.db.collection::<QueuedRequest>(QUEUE_COLLECTION);

        self.cleanup_outdated_uploads(now).await?;

        let filter = doc! {
            "account_unique_id": account_unique_id.to_string(),
            "$or": [
                { "identifier": identifier.clone() },
                { "content_hash": content_hash.clone() }
            ],
        };
        let find_options = FindOneAndUpdateOptions::builder().upsert(true).build();
        let upload_id = Ulid::new().to_string();
        let previous_document = queue_collection
            .find_one_and_update(
                filter,
                doc! {
                    "$inc": {"num_requests": 1},
                    "$currentDate": { "last_requested_at": true },
                    "$setOnInsert": {
                        "upload_id": upload_id.clone(),
                        "upload_requested_at": Utc::now(),
                        "content_hash": content_hash.clone(),
                        "identifier": identifier.clone(),
                    },
                },
                Some(find_options),
            )
            .await?;

        match previous_document {
            None => Ok(ProcessResponse::PendingUpload {
                upload_id,
                ttl_secs: (*UPLOAD_TTL).num_seconds() as u16,
            }),
            Some(queued) if queued.is_processing() => Ok(ProcessResponse::Processing),
            Some(_) => Ok(ProcessResponse::Accepted),
        }
    }

    pub async fn find_processed(
        &self,
        account_unique_id: &AccountUniqueId,
        identifier: &str,
        content_hash: &str,
    ) -> anyhow::Result<Option<Processed>> {
        let queue_collection = self.db.collection::<Processed>(PROCESSED_COLLECTION);

        let filter = doc! {
            "account_unique_id": account_unique_id.to_string(),
            "$or": [
                { "identifier": identifier },
                { "content_hash": content_hash }
            ],
        };
        let find_options = FindOneOptions::builder().build();

        Ok(queue_collection.find_one(filter, find_options).await?)
    }

    pub(crate) async fn save_processed(
        &self,
        processed: Vec<(ImageConversionMeta, Header)>,
        queued: QueuedRequest,
    ) -> anyhow::Result<()> {
        if processed.is_empty() {
            bail!("no processed entries specified");
        }

        let processed_collection: Collection<Processed> = self.db.collection(PROCESSED_COLLECTION);
        let queued_collection = self.db.collection::<bson::Document>(QUEUE_COLLECTION);

        let processed = Processed {
            identifier: queued.identifier.clone(),
            account_unique_id: queued.account_unique_id,
            source_size: processed[0].0.source_size as i64,
            content_hash: queued.content_hash.clone(),
            last_requested_at: queued.last_requested_at,
            num_requests: 0,
            formats: processed
                .into_iter()
                .map(|(meta, header)| ProcessedFormat {
                    content_type: meta.content_type,
                    encryption_header: base64::encode(header.as_ref()),
                    compressed_size: meta.transformed_size as i64,
                    compression_ratio: meta.compression_ratio,
                })
                .collect(),
        };

        let options = FindOneAndReplaceOptions::builder().upsert(true).build();

        processed_collection
            .find_one_and_replace(
                doc! {
                    "identifier": queued.identifier.clone(),
                    "account_unique_id": queued.account_unique_id.to_string(),
                    "content_hash": queued.content_hash.clone(),
                },
                processed,
                Some(options),
            )
            .await?;

        queued_collection
            .delete_many(
                doc! {
                    "identifier": queued.identifier,
                    "account_unique_id": queued.account_unique_id.to_string(),
                    "content_hash": queued.content_hash,
                },
                None,
            )
            .await?;

        Ok(())
    }
}
