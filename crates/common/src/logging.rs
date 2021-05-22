use chrono::{DateTime, Utc};
use exogress_common::{
    config_core::ClientConfigRevision,
    entities::{
        AccountUniqueId, ConfigName, Exception, HandlerName, InstanceId, LabelName, LabelValue,
        MountPointName, ParameterName, ProjectName, ProjectUniqueId, SmolStr, Ulid, Upstream,
    },
};
use hashbrown::HashMap;
use http::{
    header::{ACCEPT, USER_AGENT},
    HeaderMap,
};
use langtag::LanguageTagBuf;
use parking_lot::Mutex;
use serde_with::{serde_as, DurationMilliSecondsWithFrac, DurationSeconds};
use std::{net::IpAddr, sync::Arc, time::Duration};
use typed_headers::HeaderMapExt;

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
    pub request_id: Ulid,
    pub gw_location: SmolStr,

    pub remote_addr: IpAddr,

    pub account_unique_id: AccountUniqueId,
    pub project: ProjectName,
    pub project_unique_id: ProjectUniqueId,
    pub mount_point: MountPointName,

    pub protocol: SmolStr,

    pub request: RequestMetaInfo,
    pub response: ResponseMetaInfo,

    pub steps: Vec<ProcessingStep>,

    pub facts: Arc<Mutex<serde_json::Value>>,

    pub str: Option<String>,

    #[serde(rename = "@timestamp")]
    pub timestamp: chrono::DateTime<chrono::Utc>,

    pub started_at: chrono::DateTime<chrono::Utc>,
    pub ended_at: Option<chrono::DateTime<chrono::Utc>>,

    #[serde_as(as = "Option<DurationMilliSecondsWithFrac>")]
    pub time_taken_ms: Option<Duration>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct WellKnownHeaders {
    #[serde(rename = "content_length")]
    pub content_length: Option<u64>,

    #[serde(rename = "content_type")]
    pub content_type: Option<SmolStr>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct WellKnownRequestHeaders {
    #[serde(flatten)]
    pub common: WellKnownHeaders,

    #[serde(rename = "user_agent")]
    pub user_agent: Option<SmolStr>,

    pub accept: Option<SmolStr>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct WellKnownResponseHeaders {
    #[serde(flatten)]
    pub common: WellKnownHeaders,
}

impl WellKnownHeaders {
    pub fn fill_from_headers(&mut self, headers: &HeaderMap) {
        if let Ok(Some(len)) = headers.typed_get::<typed_headers::ContentLength>() {
            self.content_length = Some(len.0);
        }

        if let Ok(Some(content_type)) = headers.typed_get::<typed_headers::ContentType>() {
            self.content_type = Some(content_type.0.as_ref().into());
        }
    }
}

impl WellKnownResponseHeaders {
    pub fn fill_from_headers(&mut self, headers: &HeaderMap) {
        self.common.fill_from_headers(headers);
    }
}

impl WellKnownRequestHeaders {
    pub fn fill_from_headers(&mut self, headers: &HeaderMap) {
        self.common.fill_from_headers(headers);

        if let Some(user_agent) = headers.get(USER_AGENT) {
            if let Ok(ua) = user_agent.to_str() {
                self.user_agent = Some(ua.into());
            }
        }

        if let Some(accept) = headers.get(ACCEPT) {
            if let Ok(s) = accept.to_str() {
                self.accept = Some(s.into());
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RequestMetaInfo {
    pub headers: WellKnownRequestHeaders,

    #[serde(skip_serializing_if = "HttpBodyLog::is_none")]
    pub body: HttpBodyLog,

    pub url: SmolStr,
    pub method: SmolStr,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ResponseMetaInfo {
    pub headers: WellKnownResponseHeaders,

    #[serde(skip_serializing_if = "HttpBodyLog::is_none")]
    pub body: HttpBodyLog,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub compression: Option<SmolStr>,

    pub status_code: Option<u16>,
}

impl LogMessage {
    pub fn set_message_string(&mut self) {
        self.str = Some(format!(
            "{} {} {} {} {} {} {} {} \"{}\"",
            self.started_at.to_rfc3339(),
            self.gw_location,
            self.mount_point,
            self.remote_addr,
            self.protocol,
            self.request.method,
            self.request.url,
            self.response
                .status_code
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".to_string()),
            self.request
                .headers
                .user_agent
                .as_ref()
                .map(|s| s.as_str())
                .unwrap_or_else(|| "-"),
        ));
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "action")]
pub enum ProcessingStep {
    #[serde(rename = "invoke")]
    Invoke(Arc<parking_lot::Mutex<CacheableInvocationProcessingStep>>),

    #[serde(rename = "throw_exception")]
    ThrowException(ExceptionProcessingStep),

    #[serde(rename = "catch_exception")]
    CatchException(CatchProcessingStep),

    #[serde(rename = "static_response")]
    StaticResponse(StaticResponseProcessingStep),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StaticResponseProcessingStep {
    // pub static_response: StaticResponseName,
    pub data: HashMap<SmolStr, SmolStr>,
    pub config_name: Option<ConfigName>,

    pub scope: ScopeLog,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<LanguageTagBuf>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ExceptionProcessingStep {
    pub exception: Exception,
    pub handler_name: Option<SmolStr>,
    pub data: HashMap<SmolStr, SmolStr>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "rescuable")]
pub enum CatchProcessingVariantStep {
    #[serde(rename = "exception")]
    Exception { exception: String },

    #[serde(rename = "status_code")]
    StatusCode {
        #[serde(with = "http_serde::status_code")]
        status_code: http::StatusCode,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CatchProcessingStep {
    #[serde(flatten)]
    pub variant: CatchProcessingVariantStep,

    pub catch_matcher: String,

    pub scope: ScopeLog,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "level")]
pub enum ScopeLog {
    #[serde(rename = "project_config")]
    ProjectConfig,

    #[serde(rename = "client_config")]
    ClientConfig {
        config_name: ConfigName,
        revision: ClientConfigRevision,
    },

    #[serde(rename = "project_mount")]
    ProjectMount { mount_point: MountPointName },

    #[serde(rename = "client_mount")]
    ClientMount {
        config_name: ConfigName,
        revision: ClientConfigRevision,
        mount_point: MountPointName,
    },

    #[serde(rename = "project_handler")]
    ProjectHandler {
        mount_point: MountPointName,
        handler_name: HandlerName,
    },

    #[serde(rename = "client_handler")]
    ClientHandler {
        config_name: ConfigName,
        revision: ClientConfigRevision,
        mount_point: MountPointName,
        handler_name: HandlerName,
    },

    #[serde(rename = "project_rule")]
    ProjectRule {
        mount_point: MountPointName,
        handler_name: HandlerName,
        rule_num: usize,
    },

    #[serde(rename = "client_rule")]
    ClientRule {
        config_name: ConfigName,
        revision: ClientConfigRevision,
        mount_point: MountPointName,
        handler_name: HandlerName,
        rule_num: usize,
    },

    #[serde(rename = "parameter")]
    Parameter { parameter_name: ParameterName },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "source")]
pub enum CacheableInvocationProcessingStep {
    #[serde(rename = "cache")]
    Cached {
        #[serde(skip_serializing_if = "Option::is_none")]
        config_name: Option<ConfigName>,

        handler_name: HandlerName,

        transformation: Option<TransformationStatus>,
    },

    #[serde(rename = "origin")]
    Invoked(HandlerProcessingStep),

    #[serde(rename = "empty")]
    Empty {
        transformation: Option<TransformationStatus>,
    },
}

impl CacheableInvocationProcessingStep {
    pub fn is_not_empty(&self) -> bool {
        if let CacheableInvocationProcessingStep::Empty { .. } = *self {
            return false;
        }

        true
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "handler_kind")]
pub enum HandlerProcessingStepVariant {
    #[serde(rename = "auth")]
    Auth(AuthHandlerLogMessage),
    #[serde(rename = "proxy")]
    Proxy(ProxyHandlerLogMessage),
    #[serde(rename = "proxy-public")]
    ProxyPublic(ProxyPublicHandlerLogMessage),
    #[serde(rename = "s3_bucket")]
    S3Bucket(S3BucketHandlerLogMessage),
    #[serde(rename = "gcs_bucket")]
    GcsBucket(GcsBucketHandlerLogMessage),
    #[serde(rename = "static_dir")]
    StaticDir(StaticDirHandlerLogMessage),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HandlerProcessingStep {
    #[serde(flatten)]
    pub variant: HandlerProcessingStepVariant,

    pub path: SmolStr,

    #[serde(rename = "save_to_cache")]
    pub save_to_cache: Option<CacheSavingStatus>,

    pub transformation: Option<TransformationStatus>,
}

impl CacheableInvocationProcessingStep {
    pub fn transformation_mut(&mut self) -> &mut Option<TransformationStatus> {
        match self {
            CacheableInvocationProcessingStep::Cached { transformation, .. } => transformation,
            CacheableInvocationProcessingStep::Invoked(HandlerProcessingStep {
                transformation,
                ..
            }) => transformation,
            CacheableInvocationProcessingStep::Empty { transformation } => transformation,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CacheSaveStep {
    pub enabled: bool,
    pub eligible: bool,
    pub status: bool,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "status")]
pub enum CacheSavingStatus {
    #[serde(rename = "disabled")]
    Disabled,

    #[serde(rename = "not_eligible")]
    NotEligible,

    #[serde(rename = "save_error")]
    SaveError,

    #[serde(rename = "skipped")]
    Skipped,

    #[serde(rename = "saved")]
    Saved {
        #[serde_as(as = "DurationSeconds")]
        max_age: Duration,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "status")]
pub enum TransformationStatus {
    #[serde(rename = "disabled")]
    Disabled,

    #[serde(rename = "cache_disabled")]
    CacheDisabled,

    #[serde(rename = "limited")]
    Limited,

    #[serde(rename = "not_eligible")]
    NotEligible,

    #[serde(rename = "transformed")]
    Transformed,

    #[serde(rename = "triggered")]
    Triggered,

    #[serde(rename = "saved_to_cache")]
    SavedToCache,

    #[serde(rename = "error")]
    Error,

    #[serde(rename = "skipped")]
    Skipped,
}

impl From<HandlerProcessingStep> for CacheableInvocationProcessingStep {
    fn from(s: HandlerProcessingStep) -> Self {
        CacheableInvocationProcessingStep::Invoked(s)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StaticDirHandlerLogMessage {
    pub config_name: ConfigName,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<LanguageTagBuf>,
    pub handler_name: HandlerName,

    pub attempts: Vec<ProxyAttemptLogMessage>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InstanceLog {
    pub instance_id: InstanceId,
    pub labels: HashMap<LabelName, LabelValue>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProxyPublicAttemptLogMessage {
    pub attempt: u8,

    pub attempted_at: DateTime<Utc>,

    pub request: ProxyRequestToOriginInfo,

    pub response: ProxyOriginResponseInfo,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProxyAttemptLogMessage {
    pub attempt: u8,

    pub attempted_at: DateTime<Utc>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<InstanceLog>,

    pub request: ProxyRequestToOriginInfo,

    pub response: ProxyOriginResponseInfo,
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
    pub handler_name: HandlerName,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub upgrade: Option<ProtocolUpgrade>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<LanguageTagBuf>,

    pub attempts: Vec<ProxyAttemptLogMessage>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(tag = "status")]
pub enum BodyStatusLog {
    #[serde(rename = "finished")]
    Finished,

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<LanguageTagBuf>,
    pub handler_name: HandlerName,

    pub attempts: Vec<ProxyAttemptLogMessage>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProxyRequestToOriginInfo {
    #[serde(skip_serializing_if = "HttpBodyLog::is_none")]
    pub body: HttpBodyLog,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProxyOriginResponseInfo {
    #[serde(skip_serializing_if = "HttpBodyLog::is_none")]
    pub body: HttpBodyLog,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProxyPublicHandlerLogMessage {
    pub base_url: SmolStr,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub upgrade: Option<ProtocolUpgrade>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<LanguageTagBuf>,
    pub handler_name: HandlerName,

    pub attempts: Vec<ProxyPublicAttemptLogMessage>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GcsBucketHandlerLogMessage {
    pub bucket: SmolStr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<LanguageTagBuf>,
    pub handler_name: HandlerName,

    pub attempts: Vec<ProxyAttemptLogMessage>,
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
    pub handler_name: HandlerName,
    pub provider: Option<SmolStr>,
    pub identity: Option<SmolStr>,
    pub acl_entry: Option<SmolStr>,
    pub acl_action: AclAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<LanguageTagBuf>,
}
