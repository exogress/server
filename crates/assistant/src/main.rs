#![warn(rust_2018_idioms)]

#[macro_use]
extern crate shadow_clone;
#[macro_use]
extern crate tracing;
#[macro_use]
extern crate serde;

use crate::termination::StopReason;
use clap::{crate_version, App, Arg};
use exogress_common_utils::termination::stop_signal_listener;
use futures::FutureExt;
use mimalloc::MiMalloc;
use redis::Client;
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use stop_handle::stop_handle;
use tokio::runtime::Builder;

mod http;
mod termination;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn main() {
    let spawn_args = App::new("spawn")
        .arg(
            Arg::with_name("listen_http")
                .long("listen-http")
                .value_name("SOCKET_ADDR")
                .default_value("0.0.0.0:3214")
                .required(true)
                .about("Set websocket listen address")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("redis_addr")
                .long("redis-addr")
                .value_name("URL")
                .default_value("redis://127.0.0.1")
                .required(true)
                .about("Set redis addr")
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

            info!("Listening  HTTP on {}", listen_http_addr);

            http::server(listen_http_addr, redis_client, app_stop_wait).await;

            info!("Stop");
        })
        .catch_unwind()
    });

    if let Err(_e) = maybe_panic {
        error!("stop on panic");
    }
}
