use crate::url_prefix::UrlPrefix;
use chrono::serde::ts_milliseconds;
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
pub struct GatewayCommonTlsConfigMessage {
    pub hostname: String,
    pub certificate: String,
    pub private_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Action {
    #[serde(rename = "invalidate_url_prefixes")]
    InvalidateUrlPrefixes { url_prefixes: Vec<UrlPrefix> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    #[serde(with = "ts_milliseconds")]
    pub generated_at: DateTime<Utc>,
    pub action: Action,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WsMessage {
    #[serde(rename = "webapp_notification")]
    WebAppNotification(Notification),

    #[serde(rename = "gw_tls")]
    GwTls(GatewayCommonTlsConfigMessage),
}
