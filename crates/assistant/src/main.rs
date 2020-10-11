#![warn(rust_2018_idioms)]

#[macro_use]
extern crate shadow_clone;
#[macro_use]
extern crate tracing;
#[macro_use]
extern crate serde;

use crate::clickhouse::Clickhouse;
use crate::http::GatewayCommonTlsConfig;
use crate::termination::StopReason;
use clap::{crate_version, App, Arg};
use exogress_common_utils::termination::stop_signal_listener;
use futures::FutureExt;
use redis::Client;
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use stop_handle::stop_handle;
use tokio::runtime::Builder;

mod http;
// pub mod reporting;
mod clickhouse;
mod termination;

fn main() {
    let spawn_args = App::new("spawn")
        .arg(
            Arg::with_name("gw_hostname")
                .long("gw-hostname")
                .value_name("HOST")
                .required(true)
                .help("Set common GW hostname")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("gw_tls_cert_path")
                .long("gw-tls-cert-path")
                .value_name("PATH")
                .required(true)
                .help("Set GW common TLS cert path")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("gw_tls_key_path")
                .long("gw-tls-key-path")
                .value_name("PATH")
                .required(true)
                .help("Set GW common TLS key path")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("listen_http")
                .long("listen-http")
                .value_name("SOCKET_ADDR")
                .default_value("0.0.0.0:3214")
                .required(true)
                .help("Set websocket listen address")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("clickhouse_url")
                .long("clickhouse-url")
                .value_name("URL")
                .default_value("tcp://127.0.0.1:9000/exogress_counters")
                .required(true)
                .help("Set clickhouse URL")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("redis_addr")
                .long("redis-addr")
                .value_name("URL")
                .default_value("redis://127.0.0.1/12")
                .required(true)
                .help("Set redis addr")
                .takes_value(true),
        );

    let spawn_args = exogress_common_utils::clap::threads::add_args(
        exogress_server_common::clap::sentry::add_args(exogress_common_utils::clap::log::add_args(
            spawn_args,
        )),
    );

    let args = App::new("Exogress Assistant Server")
        .version(crate_version!())
        .author("Exogress Team <team@exogress.com>")
        .subcommand(spawn_args);

    let mut args = exogress_common_utils::clap::autocompletion::add_args(args);

    let matches = args.clone().get_matches().clone();
    exogress_common_utils::clap::autocompletion::handle_autocompletion(
        &mut args,
        &matches,
        "exogress-assistant",
    );

    let (app_stop_handle, app_stop_wait) = stop_handle::<StopReason>();

    let matches = matches
        .subcommand_matches("spawn")
        .expect("Unknown subcommand");

    let _maybe_sentry = exogress_server_common::clap::sentry::extract_matches(&matches);
    exogress_common_utils::clap::log::handle(&matches, "assistant");
    let num_threads = exogress_common_utils::clap::threads::extract_matches(&matches);

    let clickhouse_url = matches
        .value_of("clickhouse_url")
        .expect("no --clickhouse-url provided")
        .to_string();

    let gw_tls_key_path: String = matches
        .value_of("gw_tls_key_path")
        .expect("no --gw-tls-key-path provided")
        .into();
    let gw_tls_cert_path: String = matches
        .value_of("gw_tls_cert_path")
        .expect("no --gw-tls-cert-path provided")
        .into();
    let gw_hostname: String = matches
        .value_of("gw_hostname")
        .expect("no --gw-hostname provided")
        .into();

    let redis_addr: String = matches
        .value_of("redis_addr")
        .expect("no redis addr provided")
        .into();

    let listen_http_addr = matches
        .value_of("listen_http")
        .map(|r| {
            r.parse::<SocketAddr>()
                .expect("Failed to parse listen  HTTP address (ip:port)")
        })
        .unwrap();

    let mut rt = Builder::new()
        .threaded_scheduler()
        .enable_all()
        .core_threads(num_threads)
        .thread_name("assistant-reactor")
        .build()
        .unwrap();

    let maybe_panic = rt.block_on({
        AssertUnwindSafe(async move {
            tokio::spawn(stop_signal_listener(app_stop_handle.clone()));

            let redis_client = Client::open(redis_addr.as_str()).unwrap();
            let clickhouse_client = Clickhouse::new(&clickhouse_url)
                .await
                .expect("clickhouse init error");

            info!("Listening  HTTP on {}", listen_http_addr);

            http::server(
                listen_http_addr,
                GatewayCommonTlsConfig {
                    hostname: gw_hostname,
                    tls_cert_path: gw_tls_cert_path.parse().unwrap(),
                    tls_key_path: gw_tls_key_path.parse().unwrap(),
                },
                redis_client,
                clickhouse_client,
                app_stop_wait,
            )
            .await;

            info!("Stop");
        })
        .catch_unwind()
    });

    if let Err(_e) = maybe_panic {
        error!("stop on panic");
    }
}
