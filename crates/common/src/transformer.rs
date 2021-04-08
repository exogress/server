use exogress_common::entities::AccountUniqueId;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessRequest {
    pub identifier: String,
    pub content_hash: String,
    pub account_unique_id: AccountUniqueId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketProcessedStored {
    pub provider: String,
    pub name: String,
    pub location: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingReady {
    pub content_type: String,
    pub encryption_header: String,
    pub compression_ratio: f32,
    pub content_len: u64,
    pub buckets: Vec<BucketProcessedStored>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ProcessResponseStatus {
    #[serde(rename = "pending_upload")]
    PendingUpload { upload_id: String, ttl_secs: u16 },

    #[serde(rename = "accepted")]
    Accepted,

    #[serde(rename = "ready")]
    Ready {
        formats: Vec<ProcessingReady>,
        original_content_len: u64,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessResponse {
    pub status: ProcessResponseStatus,
}
