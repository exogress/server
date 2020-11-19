use exogress_common_utils::termination::StopSignal;
use std::fmt;
use std::panic::UnwindSafe;

#[derive(Debug, Clone)]
pub enum StopReason {
    SignalReceived,
    SetOfflineError,
    HealthReportError,
}

impl UnwindSafe for StopReason {}

impl fmt::Display for StopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StopReason::SignalReceived => write!(f, "signal received"),
            StopReason::SetOfflineError => write!(f, "set offline error"),
            StopReason::HealthReportError => write!(f, "health report error"),
        }
    }
}

impl StopSignal for StopReason {
    fn signal_received() -> Self {
        StopReason::SignalReceived
    }
}
