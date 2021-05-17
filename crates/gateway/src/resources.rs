use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use sysinfo::{ProcessorExt, System, SystemExt};
use tokio::time::sleep;
use typed_builder::TypedBuilder;

#[derive(Default)]
struct State {
    cpu_usage_triggered: AtomicBool,
    la_triggered: AtomicBool,
    memory_triggered: AtomicBool,
}

impl State {
    pub fn is_limited(&self) -> bool {
        self.cpu_usage_triggered.load(Ordering::Relaxed)
            || self.la_triggered.load(Ordering::Relaxed)
            || self.memory_triggered.load(Ordering::Relaxed)
    }
}

#[derive(TypedBuilder)]
#[allow(dead_code)]
pub struct ResourcesManager {
    #[builder(default = 90.0)]
    cpu_usage_high_watermark_percent: f32,
    #[builder(default = 80.0)]
    cpu_usage_low_watermark_percent: f32,

    #[builder(default = 90.0)]
    la_high_watermark_percent: f32,
    #[builder(default = 80.0)]
    la_low_watermark_percent: f32,

    #[builder(default = 90.0)]
    memory_high_watermark_percent: f32,
    #[builder(default = 80.0)]
    memory_low_watermark_percent: f32,

    stop_trigger: Arc<AtomicBool>,
}

impl ResourcesManager {
    pub async fn run(self) {
        let mut s = System::new_all();

        let state = State::default();
        let mut filtered_cpu_usage = median::Filter::new(6);

        loop {
            sleep(Duration::from_secs(1)).await;

            s.refresh_all();

            let cpus_info = s.get_global_processor_info();
            let num_cpus = s.get_processors().len();

            let cpu_usage_percent = filtered_cpu_usage.consume(cpus_info.get_cpu_usage()) as u8;

            // let free_memory = s.get_free_memory();
            // let total_memory = s.get_total_memory();

            let load_average = s.get_load_average().one;

            // let consumed_mem_percent = (1.0 - (free_memory as f64 / total_memory as f64)) * 100.0;

            let load_average_percent = load_average / num_cpus as f64;

            if load_average_percent > self.la_high_watermark_percent as f64 {
                if !state.la_triggered.swap(true, Ordering::Relaxed) {
                    warn!(
                        "LA % is higher than high watermark {}. LA = {}; num cores = {}",
                        self.la_high_watermark_percent, load_average, num_cpus
                    );
                }
            } else if load_average_percent < self.la_low_watermark_percent as f64 {
                if state.la_triggered.swap(false, Ordering::Relaxed) {
                    info!(
                        "LA % now less than low watermark {}. LA = {}; num cores = {}",
                        self.la_low_watermark_percent, load_average, num_cpus
                    );
                }
            }

            if cpu_usage_percent > self.cpu_usage_high_watermark_percent as u8 {
                if !state.cpu_usage_triggered.swap(true, Ordering::Relaxed) {
                    warn!(
                        "CPU Usage % is higher than high watermark {}. CPU usage = {}",
                        self.cpu_usage_high_watermark_percent, cpu_usage_percent
                    );
                }
            } else if cpu_usage_percent < self.cpu_usage_low_watermark_percent as u8 {
                if state.cpu_usage_triggered.swap(false, Ordering::Relaxed) {
                    info!(
                        "CPU usage % is now less than low watermark {}. CPU usage = {}",
                        self.cpu_usage_low_watermark_percent, cpu_usage_percent
                    );
                }
            }

            // disable for now. need to clearly understand if memory doesn't longer grow
            // if consumed_mem_percent > self.memory_high_watermark_percent as f64 {
            //     if !state.memory_triggered.swap(true, Ordering::Relaxed) {
            //         warn!(
            //             "Memory usage % is higher than high watermark {}. Free = {}, Total = {}",
            //             self.memory_high_watermark_percent, free_memory, total_memory
            //         );
            //     }
            // } else if consumed_mem_percent < self.memory_low_watermark_percent as f64 {
            //     if state.memory_triggered.swap(false, Ordering::Relaxed) {
            //         info!(
            //             "Memory usage % now less than low watermark {}. Free = {}, Total = {}",
            //             self.memory_low_watermark_percent, free_memory, total_memory
            //         );
            //     }
            // }

            if state.is_limited() {
                if !self.stop_trigger.swap(true, Ordering::Relaxed) {
                    crate::statistics::RESOURCES_HIGH.set(1.0);
                    warn!("Stop accepting new connections due to resource limitations");
                }
            } else {
                if self.stop_trigger.swap(false, Ordering::Relaxed) {
                    crate::statistics::RESOURCES_HIGH.set(0.0);
                    info!("Start accepting new connections due to free resources");
                }
            }
        }
    }
}
