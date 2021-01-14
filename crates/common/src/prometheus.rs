use lazy_static::lazy_static;

lazy_static! {
    pub static ref DEFAULT_TIME_BUCKETS: Vec<f64> =
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0];
}
