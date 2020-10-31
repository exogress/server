use crate::health::{HealthEndpoint, HealthState};
use crate::url_prefix::UrlPrefix;
use chrono::serde::ts_milliseconds;
use exogress_entities::{AccountName, AccountUniqueId, ConfigId, ProjectName};
use sentry::types::{DateTime, Utc};
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SetValue {
    pub payload: String,
    pub ttl: Duration,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetValue {
    pub payload: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfigMessage {
    pub common_gw_hostname: String,
    pub common_gw_host_certificate: String,
    pub common_gw_host_private_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Action {
    #[serde(rename = "invalidate")]
    Invalidate {
        url_prefixes: Vec<UrlPrefix>,
        config_ids: Vec<ConfigId>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    #[serde(with = "ts_milliseconds")]
    pub generated_at: DateTime<Utc>,
    pub action: Action,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WsToGwMessage {
    #[serde(rename = "webapp_notification")]
    WebAppNotification(Notification),

    #[serde(rename = "gw_config")]
    GwConfig(GatewayConfigMessage),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
#[non_exhaustive]
pub enum WsFromGwMessage {
    #[serde(rename = "statistics")]
    Statistics { report: StatisticsReport },

    #[serde(rename = "health")]
    Health { report: HealthReport },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficRecord {
    pub account_unique_id: AccountUniqueId,
    pub tunnel_bytes_gw_tx: u64,
    pub tunnel_bytes_gw_rx: u64,
    pub https_bytes_gw_tx: u64,
    pub https_bytes_gw_rx: u64,
    #[serde(with = "ts_milliseconds")]
    pub flushed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesRecord {
    pub account_unique_id: AccountUniqueId,
    pub rules_processed: u64,
    pub requests_processed: u64,
    #[serde(with = "ts_milliseconds")]
    pub flushed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
#[non_exhaustive]
pub enum StatisticsReport {
    #[serde(rename = "traffic")]
    Traffic { records: Vec<TrafficRecord> },

    #[serde(rename = "rules")]
    Rules { records: Vec<RulesRecord> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
#[non_exhaustive]
pub enum HealthReport {
    #[serde(rename = "upstreams")]
    UpstreamsHealth { records: Vec<UpstreamReport> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamReport {
    pub account_name: AccountName,
    pub project_name: ProjectName,
    pub health_endpoint: HealthEndpoint,
    pub health: Option<HealthState>, // None == no longer exist
    #[serde(with = "ts_milliseconds")]
    pub datetime: DateTime<Utc>,
}
