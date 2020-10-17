#[macro_use]
extern crate clap;
#[macro_use]
extern crate derive_builder;
#[macro_use]
extern crate tracing;
#[macro_use]
extern crate shadow_clone;

mod forwarder;
mod termination;

use crate::termination::StopReason;
use clap::{App, Arg};
use exogress_common_utils::termination::stop_signal_listener;
use forwarder::{ForwarderBuilder, ForwardingRules};
use std::net::IpAddr;
use stop_handle::stop_handle;
use tokio::runtime::Builder;

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
            Arg::with_name("gateway")
                .long("gateway")
                .value_name("WEIGHT:IP")
                .required(true)
                .multiple(true)
                .help("Gateway address in form weigth:ip")
                .takes_value(true),
        );

    let spawn_args = exogress_common_utils::clap::threads::add_args(
        exogress_server_common::clap::sentry::add_args(exogress_common_utils::clap::log::add_args(
            spawn_args,
        )),
    );

    let args = App::new("Exogress Directory Balancer")
        .version(crate_version!())
        .author("Exogress Team <team@exogress.com>")
        .subcommand(spawn_args);

    let mut args = exogress_common_utils::clap::autocompletion::add_args(args);

    let matches = args.clone().get_matches().clone();
    exogress_common_utils::clap::autocompletion::handle_autocompletion(
        &mut args,
        &matches,
        "exogress-director",
    );

    let (app_stop_handle, app_stop_wait) = stop_handle::<StopReason>();

    let matches = matches
        .subcommand_matches("spawn")
        .expect("Unknown subcommand");

    let _maybe_sentry = exogress_server_common::clap::sentry::extract_matches(&matches);
    exogress_common_utils::clap::log::handle(&matches, "director");
    let num_threads = exogress_common_utils::clap::threads::extract_matches(&matches);

    let mut rt = Builder::new()
        .threaded_scheduler()
        .enable_all()
        .core_threads(num_threads)
        .thread_name("director-reactor")
        .build()
        .unwrap();

    let rules = ForwardingRules::default();

    for item in matches.values_of("gateway").expect("no gateways defined") {
        let mut items = item.split(':');
        let weight: isize = items
            .next()
            .expect("bad gw format")
            .parse()
            .expect("bad weight");
        let ip: IpAddr = items
            .next()
            .expect("bad gw format")
            .parse()
            .expect("bad ip address");
        rules.add(ip, weight);
    }

    info!("gateways: {:?}", rules);

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

    info!("listen_http = {}", listen_http);
    info!("listen_https = {}", listen_https);

    rt.block_on(async move {
        tokio::spawn(stop_signal_listener(app_stop_handle.clone()));

        let forwarder = ForwarderBuilder::default()
            .listen_http(listen_http)
            .listen_https(listen_https)
            .forward_to_http_port(gw_http_port)
            .forward_to_https_port(gw_https_port)
            .rules(rules)
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
