use lazy_static::lazy_static;
use prometheus::{
    register_histogram_vec, register_int_gauge, Encoder, HistogramVec, IntGauge, TextEncoder,
};

lazy_static! {
    pub static ref CONVERSION_TIME: HistogramVec = register_histogram_vec!(
        "transformer_conversion_time",
        "Time taken for conversions",
        &["format"],
        vec![
            0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 15.0, 20.0, 25.0, 30.0, 35.0, 40.0, 45.0,
            50.0, 55.0, 60.0, 65.0, 70.0, 75.0, 80.0, 85.0, 90.0, 95.0, 100.0, 120.0, 140.0, 160.0,
            180.0, 200.0, 300.0, 400.0
        ]
    )
    .unwrap();
    pub static ref QUEUE_SIZE: IntGauge =
        register_int_gauge!("transformer_queue_size", "Size of the queue").unwrap();
}

pub fn dump_prometheus() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();

    String::from_utf8(buffer).expect("bad prometheus data")
}
