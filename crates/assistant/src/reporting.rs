use chrono::serde::ts_milliseconds;
use chrono::{DateTime, Utc};
use exogress_entities::Endpoint;
use smartstring::alias::*;
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    variant: UsageStatistics,
    endpoint: Endpoint,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ReportVariant {
    Statistics(Vec<Report>),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UsageStatistics {
    hits: u64,
    bytes_uploaded: u64,
    bytes_downloaded: u64,
    #[serde(with = "ts_milliseconds")]
    generated_at: DateTime<Utc>,
    period: Duration,
}
