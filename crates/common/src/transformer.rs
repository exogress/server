use chrono::serde::ts_milliseconds;
use exogress_common::entities::{
    AccountUniqueId, HandlerName, MountPointName, ProjectName, ProjectUniqueId,
};

pub const MAX_SIZE_FOR_TRANSFORMATION: u64 = 80 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessRequest {
    pub content_type: String,
    pub content_hash: String,
    pub account_unique_id: AccountUniqueId,
    pub project_unique_id: ProjectUniqueId,
    pub url: String,
    pub mount_point_name: MountPointName,
    pub project_name: ProjectName,
    pub handler_name: HandlerName,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketProcessedStored {
    pub provider: String,
    pub name: String,
    pub location: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessedFormat {
    pub content_type: String,
    pub profile: String,

    #[serde(flatten)]
    pub result: ProcessedFormatResult,
}

impl ProcessedFormatResult {
    pub fn transformed_content_len(&self) -> Option<i64> {
        match self {
            ProcessedFormatResult::Succeeded(ProcessedFormatSucceeded { content_len, .. }) => {
                Some(*content_len)
            }
            ProcessedFormatResult::Failed { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessedFormatSucceeded {
    pub encryption_header: String,
    pub compression_ratio: f32,
    pub content_len: i64,
    pub time_taken_ms: i64,
    pub buckets: Vec<BucketProcessedStored>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result")]
pub enum ProcessedFormatResult {
    #[serde(rename = "succeeded")]
    Succeeded(ProcessedFormatSucceeded),

    #[serde(rename = "failed")]
    Failed { reason: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum ProcessResponse {
    #[serde(rename = "pending_upload")]
    PendingUpload { upload_id: String, ttl_secs: u16 },

    #[serde(rename = "accepted")]
    Accepted,

    #[serde(rename = "processing")]
    Processing,

    #[serde(rename = "ready")]
    Ready(ProcessingReady),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessingReady {
    pub formats: Vec<ProcessedFormat>,
    pub original_content_len: u64,
    #[serde(with = "ts_milliseconds")]
    pub transformed_at: chrono::DateTime<chrono::Utc>,
}
