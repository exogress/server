use lazy_static::lazy_static;
use prometheus::{Encoder, Gauge, Histogram, IntCounter, TextEncoder};

lazy_static! {
    pub static ref API_REQUEST_TIME_HISTOGRAM: Vec<f64> = vec![
        10.0, 20.0, 30.0, 40.0, 50.0, 70.0, 100.0, 150.0, 200.0, 500.0, 1000.0, 2000.0, 5000.0,
        10000.0, 20000.0
    ];
    pub static ref CHANNEL_ESTABLISHMENT_ERRORS: IntCounter = register_int_counter!(
        "signaler_channels_establishment_errors",
        "Number of errors trying to establish channel"
    )
    .unwrap();
    pub static ref ACTIVE_CHANNELS: Gauge = register_gauge!(
        "signaler_active_channels",
        "Number of active channels with clients"
    )
    .unwrap();
    pub static ref CHANELS_ESTABLISHMENT_TIME_MS: Histogram = register_histogram!(
        "signaler_channels_establishment_time_ms",
        "Time taken to establish signaling channel (in milliseconds)",
        API_REQUEST_TIME_HISTOGRAM.clone()
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
