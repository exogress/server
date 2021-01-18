use exogress_common::config_core::parametrized::aws::bucket::S3Region;
use exogress_common::config_core::{AuthProvider, StaticResponse};
use exogress_common::entities::{HandlerName, InstanceId, MountPointName, ProjectName, SmolStr};
use http::{Method, StatusCode};
use std::net::IpAddr;

#[derive(OptionalStruct, Serialize, Deserialize, Debug, Clone)]
#[optional_derive(Serialize, Copy, Display)]
pub struct LogMessage {
    gw_location: SmolStr,
    time: chrono::DateTime<chrono::Utc>,
    client_addr: IpAddr,

    project: ProjectName,
    mount_point: MountPointName,
    handler_name: HandlerName,

    path: String,
    method: Method,
    status: StatusCode,
    hostname: String,

    process_time: chrono::Duration,
    // steps: Vec<ProcessingStep>,
    // client_geo: SmolStr,
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
