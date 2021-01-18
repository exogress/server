use chrono::serde::ts_milliseconds;
use exogress_common::entities::{AccountUniqueId, MountPointName, ProjectName, SmolStr};
use serde_with::serde_as;
use std::net::IpAddr;

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LogMessage {
    pub gw_location: SmolStr,
    #[serde(with = "ts_milliseconds")]
    pub time: chrono::DateTime<chrono::Utc>,
    pub client_addr: IpAddr,

    pub account_unique_id: AccountUniqueId,
    pub project: ProjectName,
    pub mount_point: MountPointName,
    // handler_name: Option<HandlerName>,
    pub url: SmolStr,
    pub method: SmolStr,
    // status: Option<u16>,

    // #[serde_as(as = "Option<DurationSeconds>")]
    // process_time_ms: Option<Duration>,
    // steps: Vec<ProcessingStep>,
}
//
// pub enum ProcessingStep {
//     Handler(HandlerLogMessage),
//     Exception(ExceptionName),
//     StaticResponse(StaticResponse),
//     Optimize,
//     Cache,
// }
//
// pub enum HandlerLogMessage {
//     Auth(AuthHandlerLogMessage),
//     Proxy(ProxyHandlerLogMessage),
//     S3Bucket(S3BucketHandlerLogMessage),
//     GcsBucket(GcsBucketHandlerLogMessage),
//     StaticDir(StaticDirHandlerLogMessage),
// }
//
// pub struct UpstreamLogMessage {
//     upstream: UpstreamName,
//     instance_id: InstanceId,
//     upstream_addr: IpAddr,
// }
//
// pub struct StaticDirHandlerLogMessage {
//     upstream: UpstreamLogMessage,
//     dir: SmolStr,
// }
//
// pub struct ProxyHandlerLogMessage {
//     upstream: UpstreamLogMessage,
// }
//
// pub struct S3BucketHandlerLogMessage {
//     region: S3Region,
// }
//
// pub struct GcsBucketHandlerLogMessage {
//     bucket: SmolStr,
// }
//
// pub struct AuthHandlerLogMessage {
//     provider: AuthProvider,
//     identity: Option<SmolStr>,
//     acl_entry: Option<SmolStr>,
//     is_passed: bool,
// }
