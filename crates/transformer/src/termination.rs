use exogress_common::common_utils::termination::StopSignal;
use std::{fmt, panic::UnwindSafe};

#[derive(Debug, Clone)]
pub enum StopReason {
    ProcessorStopped,
    WebServerStopped,
    SignalReceived,
}

impl UnwindSafe for StopReason {}

impl fmt::Display for StopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StopReason::ProcessorStopped => write!(f, "processor stopped"),
            StopReason::WebServerStopped => write!(f, "web server stopped"),
            StopReason::SignalReceived => write!(f, "signal received"),
        }
    }
}

impl StopSignal for StopReason {
    fn signal_received() -> Self {
        StopReason::SignalReceived
    }
}
