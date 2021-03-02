use chrono::serde::ts_milliseconds;
use exogress_common::entities::{
    AccountUniqueId, ConfigName, Exception, InstanceId, MountPointName, ProjectName, SmolStr,
    Upstream,
};
use hashbrown::HashMap;
use langtag::LanguageTagBuf;
use parking_lot::Mutex;
use serde_with::{serde_as, DurationSecondsWithFrac};
use std::{net::IpAddr, sync::Arc, time::Duration};

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LogMessage {
    pub gw_location: SmolStr,
    #[serde(with = "ts_milliseconds")]
    pub date: chrono::DateTime<chrono::Utc>,
    pub client_addr: IpAddr,

    pub account_unique_id: AccountUniqueId,
    pub project: ProjectName,
    pub mount_point: MountPointName,
    pub url: SmolStr,
    pub method: SmolStr,

    pub status_code: Option<u16>,

    #[serde_as(as = "Option<DurationSecondsWithFrac>")]
    pub time_taken: Option<Duration>,

    pub content_len: Option<u64>,

    pub steps: Vec<ProcessingStep>,

    pub facts: Arc<Mutex<HashMap<SmolStr, SmolStr>>>,
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
    pub instance_id: InstanceId,
    pub config_name: ConfigName,
    pub language: Option<LanguageTagBuf>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProxyHandlerLogMessage {
    pub upstream: Upstream,
    pub instance_id: InstanceId,
    pub config_name: ConfigName,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<LanguageTagBuf>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct S3BucketHandlerLogMessage {
    pub region: SmolStr,
    pub language: Option<LanguageTagBuf>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GcsBucketHandlerLogMessage {
    pub bucket: SmolStr,
    pub language: Option<LanguageTagBuf>,
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
