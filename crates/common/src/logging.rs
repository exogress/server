use chrono::serde::ts_milliseconds;
use exogress_common::config_core::parametrized::aws::bucket::S3Region;
use exogress_common::config_core::{AuthProvider, StaticResponse};
use exogress_common::entities::{HandlerName, InstanceId, MountPointName, ProjectName, SmolStr};
use http::Method;
use serde_with::{serde_as, DurationSeconds};
use std::net::IpAddr;
use std::time::Duration;

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LogMessage {
    gw_location: SmolStr,
    #[serde(with = "ts_milliseconds")]
    time: chrono::DateTime<chrono::Utc>,
    client_addr: IpAddr,

    project: ProjectName,
    mount_point: MountPointName,
    handler_name: Option<HandlerName>,

    hostname: SmolStr,
    path: SmolStr,
    method: Option<SmolStr>,

    status: Option<u16>,

    #[serde_as(as = "Option<DurationSeconds>")]
    process_time_ms: Option<Duration>,
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
