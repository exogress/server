use exogress_server_common::prometheus::DEFAULT_TIME_BUCKETS;
use lazy_static::lazy_static;
use prometheus::{
    register_histogram, register_int_counter_vec, Encoder, Histogram, IntCounterVec, TextEncoder,
};

lazy_static! {
    pub static ref STATISTICS_REPORT_SAVE_TIME: Histogram = register_histogram!(
        "commiter_statistics_report_save_time",
        "Time taken to save statistics reports to mongodb",
        DEFAULT_TIME_BUCKETS.clone()
    )
    .unwrap();
    pub static ref ACCOUNT_LOGS_SAVE_TIME: Histogram = register_histogram!(
        "commiter_accounts_logs_batch_save_time",
        "Time taken to save log message batch to account",
        DEFAULT_TIME_BUCKETS.clone()
    )
    .unwrap();
    pub static ref ACCOUNT_LOGS_SAVE: IntCounterVec = register_int_counter_vec!(
        "commiter_account_logs_saved",
        "Number of account logs saved",
        &["error"]
    )
    .unwrap();
}

pub fn dump_prometheus() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();

    String::from_utf8(buffer).expect("bad prometheus data")
}
