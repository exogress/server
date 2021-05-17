#[macro_use]
extern crate clap;
#[macro_use]
extern crate derive_builder;
#[macro_use]
extern crate tracing;
#[macro_use]
extern crate shadow_clone;
#[macro_use]
extern crate anyhow;

#[cfg(test)]
extern crate quickcheck;
#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

mod balancer;
mod forwarder;
mod statistics;
mod termination;
mod tls;

use crate::{balancer::ShardedGateways, termination::StopReason};
use clap::{App, Arg};
use exogress_common::common_utils::termination::stop_signal_listener;
use exogress_server_common::clap::int_api::IntApiBaseUrls;
use forwarder::ForwarderBuilder;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use stop_handle::stop_handle;
use tokio::runtime::Builder;
use trust_dns_resolver::{TokioAsyncResolver, TokioHandle};

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

fn main() {
    let spawn_args = App::new("spawn")
        .arg(
            Arg::with_name("gw_http_port")
                .long("gw-http-port")
                .value_name("PORT")
                .default_value("2080")
                .required(true)
                .help("Gateways HTTP port")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("gw_https_port")
                .long("gw-https-port")
                .value_name("PORT")
                .default_value("2443")
                .required(true)
                .help("Gateways HTTPS port")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("listen_http")
                .long("listen-http")
                .value_name("SOCKET_ADDR")
                .default_value("0.0.0.0:4080")
                .required(true)
                .help("Set websocket listen address")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("listen_https")
                .long("listen-https")
                .value_name("SOCKET_ADDR")
                .default_value("0.0.0.0:4443")
                .required(true)
                .help("Set websocket listen address")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("listen_int_http")
                .long("listen-int-http")
                .value_name("SOCKET_ADDR")
                .default_value("127.0.0.1:22710")
                .required(true)
                .help("Set int HTTP listen address")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("gateway")
                .long("gateway")
                .value_name("WEIGHT:IP")
                .required(true)
                .multiple(true)
                .help("Gateway address in form weight:ip")
                .takes_value(true),
        );

    let spawn_args = exogress_server_common::clap::int_api::add_args(
        exogress_common::common_utils::clap::threads::add_args(
            exogress_server_common::clap::sentry::add_args(
                exogress_server_common::clap::log::add_args(spawn_args),
            ),
        ),
        true,
        false,
        false,
        false,
    );

    let args = App::new("Exogress Directory Balancer")
        .version(crate_version!())
        .author("Exogress Team <team@exogress.com>")
        .subcommand(spawn_args);

    let mut args = exogress_common::common_utils::clap::autocompletion::add_args(args);

    let matches = args.clone().get_matches().clone();
    exogress_common::common_utils::clap::autocompletion::handle_autocompletion(
        &mut args,
        &matches,
        "exogress-director",
    );

    let (app_stop_handle, app_stop_wait) = stop_handle::<StopReason>();

    let matches = matches
        .subcommand_matches("spawn")
        .expect("Unknown subcommand");

    let _maybe_sentry = exogress_server_common::clap::sentry::extract_matches(&matches);
    let num_threads = exogress_common::common_utils::clap::threads::extract_matches(&matches);
    let IntApiBaseUrls {
        int_client_cert, ..
    } = exogress_server_common::clap::int_api::extract_matches(&matches, true, false, false, false);

    let listen_int_http_addr = matches
        .value_of("listen_int_http")
        .map(|r| {
            r.parse::<SocketAddr>()
                .expect("Failed to parse listen int HTTP address (ip:port)")
        })
        .unwrap();

    let rt = Builder::new_multi_thread()
        .enable_all()
        .worker_threads(num_threads)
        .thread_name("director-reactor")
        .build()
        .unwrap();

    let resolver = TokioAsyncResolver::from_system_conf(TokioHandle).unwrap();

    let logger_bg = rt
        .block_on({
            exogress_server_common::clap::log::handle(
                matches.clone(),
                "director",
                resolver,
                int_client_cert,
            )
        })
        .expect("could not initialize logger");

    rt.spawn(logger_bg);

    rt.spawn(crate::statistics::spawn(listen_int_http_addr));

    let mut gateways = Vec::new();

    for item in matches.values_of("gateway").expect("no gateways defined") {
        let mut items = item.split(':');
        let weight: u8 = items
            .next()
            .expect("bad gw format")
            .parse()
            .expect("bad weight");
        let ip: IpAddr = items
            .next()
            .expect("bad gw format")
            .parse()
            .expect("bad ip address");
        gateways.push((ip, weight));
    }

    let sharded_gateways = ShardedGateways::new(gateways, 4096).expect("Gateways error");

    let listen_http = matches
        .value_of("listen_http")
        .expect("no --listen-http provided")
        .parse()
        .expect("bad listen-http");

    let listen_https = matches
        .value_of("listen_https")
        .expect("no --listen-https provided")
        .parse()
        .expect("bad listen-https");

    let gw_https_port = matches
        .value_of("gw_https_port")
        .expect("no --gw-https-port provided")
        .parse()
        .expect("bad gw_https_port");

    let gw_http_port = matches
        .value_of("gw_http_port")
        .expect("no --gw-http-port provided")
        .parse()
        .expect("bad gw_http_port");

    info!("listen HTTP: {}", listen_http);
    info!("listen HTTPS = {}", listen_https);

    rt.block_on(async move {
        tokio::spawn(stop_signal_listener(app_stop_handle.clone()));

        let forwarder = ForwarderBuilder::default()
            .listen_http(listen_http)
            .listen_https(listen_https)
            .forward_to_http_port(gw_http_port)
            .forward_to_https_port(gw_https_port)
            .sharded_gateways(Arc::new(sharded_gateways))
            .build()
            .unwrap()
            .spawn();

        tokio::select! {
            r = forwarder => {
                info!("stop: {:?}", r);
            }
            reason = app_stop_wait => {
                info!("stop by request with reason: `{}`", reason);
            }
        }
    });
}
