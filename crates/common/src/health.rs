use exogress_config_core::Probe;
use exogress_entities::{InstanceId, Upstream};
use http::StatusCode;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "kind")]
pub enum UnhealthyReason {
    #[serde(rename = "timeout")]
    Timeout,
    #[serde(rename = "unreachable")]
    Unreachable,
    #[serde(rename = "bad_status")]
    BadStatus(#[serde(with = "http_serde::status_code")] StatusCode),
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "state")]
pub enum HealthState {
    #[serde(rename = "healthy")]
    Healthy,
    #[serde(rename = "unhealthy")]
    Unhealthy {
        probe: Probe,
        reason: UnhealthyReason,
    },
    #[serde(rename = "not_yet_known")]
    NotYetKnown,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct HealthEndpoint {
    pub instance_id: InstanceId,
    pub upstream: Upstream,
}
