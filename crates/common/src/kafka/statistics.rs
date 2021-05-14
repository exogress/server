use crate::assistant::StatisticsReport;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct GwStatisticsReport {
    pub report: StatisticsReport,
    pub gw_hostname: String,
    pub gw_location: String,
}
