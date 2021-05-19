#[macro_use]
extern crate clap;
#[macro_use]
extern crate tracing;
#[macro_use]
extern crate shadow_clone;
#[macro_use]
extern crate anyhow;

use crate::{
    assistant::AssistantClient, int_api_client::IntApiClient, rules_processor::BestPopFinder,
    server::DnsServer, termination::StopReason,
};
use clap::{App, Arg};
use exogress_common::common_utils::termination::stop_signal_listener;
use exogress_server_common::clap::int_api::IntApiBaseUrls;
use seahash::SeaHasher;
use std::{
    hash::{Hash, Hasher},
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use stop_handle::stop_handle;
use tokio::{runtime::Builder, time::sleep};
use trust_dns_resolver::{TokioAsyncResolver, TokioHandle};

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

mod assistant;
mod authority;
mod catalog;
mod cdn_zone;
mod ecs;
mod int_api_client;
mod rules;
mod rules_processor;
mod server;
mod short_zone;
mod statistics;
mod termination;

fn main() {
    let spawn_args = App::new("spawn")
        .arg(
            Arg::with_name("listen_int_http")
                .long("listen-int-http")
                .value_name("SOCKET_ADDR")
                .default_value("127.0.0.1:27174")
                .required(true)
                .help("Set int HTTP listen address")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("ns_port")
                .long("ns-port")
                .required(true)
                .help("DNS server port")
                .takes_value(true)
                .default_value("10053"),
        )
        .arg(
            Arg::with_name("ns_bind_addr")
                .long("ns-bind-addr")
                .required(true)
                .help("DNS server addr to bind to")
                .takes_value(true)
                .multiple(true),
        )
        .arg(
            Arg::with_name("ns")
                .long("ns")
                .required(true)
                .help("DNS short zone name server")
                .takes_value(true)
                .multiple(true),
        )
        .arg(
            Arg::with_name("short_hosts_cname")
                .long("short-hosts-cname")
                .required(true)
                .help("DNS CNAME for all records")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("short_zone")
                .long("short-zone")
                .required(true)
                .help("DNS short zone name")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("cdn_zone")
                .long("cdn-zone")
                .required(true)
                .help("DNS CDN zone name")
                .takes_value(true),
        );

    let spawn_args = exogress_server_common::geoip::clap::add_args(
        exogress_server_common::clap::int_api::add_args(
            exogress_common::common_utils::clap::threads::add_args(
                exogress_server_common::clap::sentry::add_args(
                    exogress_server_common::clap::log::add_args(spawn_args),
                ),
            ),
            true,
            true,
            false,
            false,
        ),
    );

    let args = App::new("Exogress DNS Server")
        .version(crate_version!())
        .author("Exogress Team <team@exogress.com>")
        .subcommand(spawn_args);

    let mut args = exogress_common::common_utils::clap::autocompletion::add_args(args);

    let matches = args.clone().get_matches().clone();
    exogress_common::common_utils::clap::autocompletion::handle_autocompletion(
        &mut args,
        &matches,
        "exogress-dns",
    );

    let (app_stop_handle, app_stop_wait) = stop_handle::<StopReason>();

    let matches = matches
        .subcommand_matches("spawn")
        .expect("Unknown subcommand");

    let _maybe_sentry = exogress_server_common::clap::sentry::extract_matches(&matches);
    let num_threads = exogress_common::common_utils::clap::threads::extract_matches(&matches);
    let IntApiBaseUrls {
        int_client_cert,
        webapp_url,
        assistant_url,
        ..
    } = exogress_server_common::clap::int_api::extract_matches(&matches, true, true, false, false);
    let dbip = exogress_server_common::geoip::clap::extract_matches(&matches);

    let int_api_client = IntApiClient::new(
        webapp_url.expect("INT api url is not provided"),
        int_client_cert.clone(),
    );

    let rt = Builder::new_multi_thread()
        .enable_all()
        .worker_threads(num_threads)
        .thread_name("reactor")
        .build()
        .unwrap();

    let resolver = TokioAsyncResolver::from_system_conf(TokioHandle).unwrap();

    let logger_bg = rt
        .block_on({
            exogress_server_common::clap::log::handle(
                matches.clone(),
                "dns",
                resolver,
                int_client_cert.clone(),
            )
        })
        .expect("could not initialize logger");

    rt.spawn(logger_bg);

    let listen_int_http_addr = matches
        .value_of("listen_int_http")
        .map(|r| {
            r.parse::<SocketAddr>()
                .expect("Failed to parse listen int HTTP address (ip:port)")
        })
        .unwrap();

    rt.spawn(crate::statistics::spawn(listen_int_http_addr));

    let short_hosts_cname = matches
        .value_of("short_hosts_cname")
        .expect("no --short-hosts-cname provided")
        .to_string();

    let short_zone = matches
        .value_of("short_zone")
        .expect("no --short-zone provided")
        .to_string();

    let cdn_zone = matches
        .value_of("cdn_zone")
        .expect("no --net-zone provided")
        .to_string();

    let ns_servers = matches
        .values_of("ns")
        .expect("no --ns provided")
        .map(|ns| ns.to_string())
        .collect::<Vec<String>>();

    let ns_bind_addr = matches
        .values_of("ns_bind_addr")
        .expect("no --ns-bind-addr")
        .map(|ns| ns.parse().expect("bad ns-bind-addr provided"))
        .collect::<Vec<IpAddr>>();

    let ns_port: u16 = matches
        .value_of("ns_port")
        .expect("no --ns-port provided")
        .parse()
        .expect("bad ns-port");

    rt.block_on(async move {
        tokio::spawn(stop_signal_listener(app_stop_handle.clone()));

        let rules_processor = BestPopFinder::new(dbip);

        let assistant_client = AssistantClient::new(
            assistant_url.expect("assistant URL is not provided"),
            int_client_cert.clone(),
        )
        .await
        .expect("error building assistant client");

        tokio::spawn({
            shadow_clone!(rules_processor);

            async move {
                let mut last_hash = None;
                loop {
                    match assistant_client.get_dns_rules().await {
                        Ok(dns_records) => {
                            let mut hasher = SeaHasher::new();
                            dns_records.hash(&mut hasher);
                            let hash_sum = hasher.finish();

                            if Some(hash_sum) != last_hash {
                                last_hash = Some(hash_sum);
                                rules_processor.update_rules(dns_records);
                            }
                            sleep(Duration::from_secs(10)).await;
                        }
                        Err(e) => {
                            error!("error retrieving DNS config: {}", e);
                            sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
            }
        });

        let _dns_server = DnsServer::new(
            &short_zone,
            &cdn_zone,
            &ns_servers,
            "team.exogress.com.",
            &short_hosts_cname,
            int_api_client,
            &ns_bind_addr,
            ns_port,
            rules_processor,
        )
        .await
        .expect("Failed to initialize DNS server");

        let reason = app_stop_wait.await;
        info!("stop by request with reason: `{}`", reason);
    });
}
