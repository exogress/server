use crate::logging::LogMessage;
use chrono::serde::ts_milliseconds;
use exogress_common::entities::{AccountUniqueId, ConfigId, ProjectUniqueId};
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
        fqdns: Vec<String>,
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

    #[serde(rename = "logs")]
    Logs { report: Vec<LogMessage> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficRecord {
    pub account_unique_id: AccountUniqueId,
    pub project_unique_id: ProjectUniqueId,

    pub public_bytes_gw_tx: u64,
    pub public_bytes_gw_rx: u64,

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
    pub project_unique_id: ProjectUniqueId,
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
