use chrono::{serde::ts_milliseconds, DateTime, Utc};
use exogress_common::entities::{
    AccountUniqueId, ConfigName, Exception, InstanceId, LabelName, LabelValue, MountPointName,
    ProjectName, ProjectUniqueId, SmolStr, Upstream,
};
use hashbrown::HashMap;
use langtag::LanguageTagBuf;
use parking_lot::Mutex;
use serde_with::{serde_as, DurationMilliSecondsWithFrac};
use std::{net::IpAddr, sync::Arc, time::Duration};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct HttpBodyLog(pub Arc<parking_lot::Mutex<Option<BodyLog>>>);

impl HttpBodyLog {
    pub fn is_none(&self) -> bool {
        self.0.lock().is_none()
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LogMessage {
    pub gw_location: SmolStr,

    // Date is a system fields. This format should be kept
    #[serde(with = "ts_milliseconds")]
    pub date: chrono::DateTime<chrono::Utc>,

    pub remote_addr: IpAddr,

    pub account_unique_id: AccountUniqueId,
    pub project: ProjectName,
    pub project_unique_id: ProjectUniqueId,
    pub mount_point: MountPointName,
    pub url: SmolStr,
    pub method: SmolStr,

    pub protocol: SmolStr,

    pub user_agent: Option<SmolStr>,

    pub status_code: Option<u16>,

    pub content_len: Option<u64>,

    pub steps: Vec<ProcessingStep>,

    pub facts: Arc<Mutex<serde_json::Value>>,

    pub str: Option<String>,

    #[serde(skip_serializing_if = "HttpBodyLog::is_none")]
    pub request_body: HttpBodyLog,

    #[serde(skip_serializing_if = "HttpBodyLog::is_none")]
    pub response_body: HttpBodyLog,

    pub started_at: chrono::DateTime<chrono::Utc>,
    pub ended_at: Option<chrono::DateTime<chrono::Utc>>,

    #[serde_as(as = "Option<DurationMilliSecondsWithFrac>")]
    pub time_taken_ms: Option<Duration>,
}

impl LogMessage {
    pub fn set_message_string(&mut self) {
        self.str = Some(format!(
            "[{}] {} {} {} \"{} {} {}\" {} \"{}\"",
            self.date.format("%d/%b/%Y:%H:%M:%S %z"),
            self.mount_point,
            self.gw_location,
            self.remote_addr,
            self.method,
            self.url,
            self.protocol,
            self.status_code
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".to_string()),
            self.user_agent
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".to_string()),
        ));
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "kind")]
pub enum ProcessingStep {
    #[serde(rename = "invoked")]
    Invoked(HandlerProcessingStep),

    #[serde(rename = "exception")]
    Exception(ExceptionProcessingStep),

    #[serde(rename = "static_response")]
    StaticResponse(StaticResponseProcessingStep),

    #[serde(rename = "served_from_cache")]
    ServedFromCache,

    #[serde(rename = "optimize")]
    Optimize(OptimizeProcessingStep),

    #[serde(rename = "compress")]
    Compress(CompressProcessingStep),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OptimizeProcessingStep {
    pub from_content_type: SmolStr,
    pub to_content_type: SmolStr,
    pub compression_ratio: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CompressProcessingStep {
    pub encoding: SmolStr,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StaticResponseProcessingStep {
    // pub static_response: StaticResponseName,
    pub data: HashMap<SmolStr, SmolStr>,
    pub config_name: Option<ConfigName>,
    pub language: Option<LanguageTagBuf>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ExceptionProcessingStep {
    pub exception: Exception,
    pub data: HashMap<SmolStr, SmolStr>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "handler")]
pub enum HandlerProcessingStep {
    #[serde(rename = "auth")]
    Auth(AuthHandlerLogMessage),
    #[serde(rename = "proxy")]
    Proxy(ProxyHandlerLogMessage),
    #[serde(rename = "s3_bucket")]
    S3Bucket(S3BucketHandlerLogMessage),
    #[serde(rename = "gcs_bucket")]
    GcsBucket(GcsBucketHandlerLogMessage),
    #[serde(rename = "static_dir")]
    StaticDir(StaticDirHandlerLogMessage),
    // #[serde(rename = "application_firewall")]
    // ApplicationFirewall(ApplicationFirewallLogMessage),
}

// #[derive(Serialize, Deserialize, Clone, Debug)]
// pub enum ApplicationFirewallAction {
//     #[serde(rename = "permitted")]
//     Permitted,
//
//     #[serde(rename = "prohibited")]
//     Prohibited,
// }
//
// #[derive(Serialize, Deserialize, Clone, Debug)]
// pub struct ApplicationFirewallLogMessage {
//     pub detected: Vec<String>,
//     pub action: ApplicationFirewallAction,
//     pub language: Option<LanguageTagBuf>,
// }

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StaticDirHandlerLogMessage {
    pub config_name: ConfigName,
    pub language: Option<LanguageTagBuf>,

    pub attempts: Vec<ProxyAttemptLogMessage>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InstanceLog {
    pub instance_id: InstanceId,
    pub labels: HashMap<LabelName, LabelValue>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProxyAttemptLogMessage {
    pub attempt: u8,

    pub attempted_at: DateTime<Utc>,

    pub instance: InstanceLog,

    #[serde(skip_serializing_if = "HttpBodyLog::is_none")]
    pub proxy_request_body: HttpBodyLog,

    #[serde(skip_serializing_if = "HttpBodyLog::is_none")]
    pub proxy_response_body: HttpBodyLog,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ProtocolUpgrade {
    #[serde(rename = "websocket")]
    WebSocket,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProxyHandlerLogMessage {
    pub upstream: Upstream,
    pub config_name: ConfigName,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub upgrade: Option<ProtocolUpgrade>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<LanguageTagBuf>,

    pub attempts: Vec<ProxyAttemptLogMessage>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(tag = "status")]
pub enum BodyStatusLog {
    #[serde(rename = "transferred")]
    Transferred,
    #[serde(rename = "cancelled")]
    Cancelled { error: String },
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BodyLog {
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,

    #[serde_as(as = "DurationMilliSecondsWithFrac")]
    pub time_taken_ms: Duration,
    pub transferred_bytes: u32,

    pub bytes_per_sec: f32,

    #[serde(flatten)]
    pub status: BodyStatusLog,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct S3BucketHandlerLogMessage {
    pub region: SmolStr,
    pub language: Option<LanguageTagBuf>,

    #[serde(skip_serializing_if = "HttpBodyLog::is_none")]
    pub proxy_response_body: HttpBodyLog,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GcsBucketHandlerLogMessage {
    pub bucket: SmolStr,
    pub language: Option<LanguageTagBuf>,

    #[serde(skip_serializing_if = "HttpBodyLog::is_none")]
    pub proxy_response_body: HttpBodyLog,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum AclAction {
    #[serde(rename = "allowed")]
    Allowed,

    #[serde(rename = "denied")]
    Denied,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuthHandlerLogMessage {
    pub provider: Option<SmolStr>,
    pub identity: Option<SmolStr>,
    pub acl_entry: Option<SmolStr>,
    pub acl_action: AclAction,
    pub language: Option<LanguageTagBuf>,
}
