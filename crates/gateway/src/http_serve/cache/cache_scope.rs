use exogress_common::config_core::ClientConfigRevision;
use exogress_common::entities::InstanceId;

#[derive(Debug, Clone, Hash, PartialEq, Copy)]
pub struct ResolvedCacheScope {
    pub config_revision: Option<ClientConfigRevision>,
    pub instance_id: Option<InstanceId>,
}
