use exogress_common_utils::termination::StopSignal;
use std::fmt;
use std::panic::UnwindSafe;

#[derive(Debug, Clone)]
pub enum StopReason {
    SignalReceived,
    PeriodicSenderTerminated,
    SetOfflineError,
}

impl UnwindSafe for StopReason {}

impl fmt::Display for StopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StopReason::SignalReceived => write!(f, "signal received"),
            StopReason::SetOfflineError => write!(f, "set offline error"),
            StopReason::PeriodicSenderTerminated => write!(f, "periodic sender terminated"),
        }
    }
}

impl StopSignal for StopReason {
    fn signal_received() -> Self {
        StopReason::SignalReceived
    }
}
