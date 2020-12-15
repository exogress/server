use std::fmt;

use exogress::common_utils::termination::StopSignal;
use stop_handle::{StopHandle, StopWait};

pub type AppStopHandle = StopHandle<StopReason>;
pub type AppStopWait = StopWait<StopReason>;

#[derive(Debug, Clone)]
pub enum StopReason {
    SignalReceived,
    NotificationChannelError,
    NotificationChannelClosed,
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
            StopReason::NotificationChannelError => write!(f, "notification channel error"),
            StopReason::NotificationChannelClosed => write!(f, "notification channel closed"),
        }
    }
}
