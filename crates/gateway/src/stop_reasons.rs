use std::fmt;

use exogress_common_utils::termination::StopSignal;
use rdkafka::error::KafkaError;
use stop_handle::{StopHandle, StopWait};

pub type AppStopHandle = StopHandle<StopReason>;
pub type AppStopWait = StopWait<StopReason>;

#[derive(Debug, Clone)]
pub enum StopReason {
    SignalReceived,
    KafkaConsumeError(KafkaError),
}

impl StopSignal for StopReason {
    fn signal_received() -> Self {
        StopReason::SignalReceived
    }
}

impl fmt::Display for StopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StopReason::SignalReceived => write!(f, "signal received"),
            StopReason::KafkaConsumeError(e) => write!(f, "registrar consume error: {}", e),
        }
    }
}
