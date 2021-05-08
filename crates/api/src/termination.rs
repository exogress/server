use exogress_common::common_utils::termination::StopSignal;
use std::fmt;

#[derive(Debug, Clone)]
pub enum StopReason {
    SignalReceived,
}

impl fmt::Display for StopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StopReason::SignalReceived => write!(f, "signal received"),
        }
    }
}

impl StopSignal for StopReason {
    fn signal_received() -> Self {
        StopReason::SignalReceived
    }
}
