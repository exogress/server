#![warn(rust_2018_idioms)]

#[macro_use]
extern crate shadow_clone;
#[macro_use]
extern crate tracing;
#[macro_use]
extern crate serde;

use crate::{http::GatewayCommonTlsConfig, kafka::KafkaProducer, termination::StopReason};
use clap::{crate_version, App, Arg};
use exogress_common::{common_utils::termination::stop_signal_listener, entities::Ulid};
use exogress_server_common::clap::int_api::IntApiBaseUrls;
use futures::FutureExt;
use redis::Client;
use std::{net::SocketAddr, panic::AssertUnwindSafe, time::Duration};
use stop_handle::stop_handle;
use tokio::runtime::Builder;
use trust_dns_resolver::{TokioAsyncResolver, TokioHandle};

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

mod http;
mod kafka;
mod presence;
mod statistics;
mod termination;

pub struct HttpsConfig {
    int_tls_cert: Vec<u8>,
    int_tls_key: Vec<u8>,
    int_tls_auth_ca: Vec<u8>,
}

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
            Arg::with_name("int_tls_cert_path")
                .long("int-tls-cert-path")
                .value_name("PATH")
                .required(false)
                .requires_all(&["int_tls_auth_ca_path", "int_tls_key_path"])
                .help("Set int TLS cert path for protecting gateways access (will switch to HTTPS mode)")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("int_tls_key_path")
                .long("int-tls-key-path")
                .value_name("PATH")
                .required(false)
                .requires_all(&["int_tls_auth_ca_path", "int_tls_cert_path"])
                .help("Set int TLS key path for protecting gateways access (will switch to HTTPS mode)")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("int_tls_auth_ca_path")
                .long("int-tls-auth-ca-path")
                .requires_all(&["int_tls_cert_path", "int_tls_key_path"])
                .value_name("PATH")
                .help("Set int TLS authentication CA ")
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
            Arg::with_name("redis_addr")
                .long("redis-addr")
                .value_name("URL")
                .default_value("redis://127.0.0.1/12")
                .required(true)
                .help("Set redis addr")
                .takes_value(true),
        );

    let spawn_args = exogress_server_common::clap::dns_rules::add_args(
        exogress_server_common::kafka::clap::add_args(
            exogress_server_common::clap::int_api::add_args(
                exogress_common::common_utils::clap::threads::add_args(
                    exogress_server_common::clap::sentry::add_args(
                        exogress_server_common::clap::log::add_args(spawn_args),
                    ),
                ),
                true,
                false,
                false,
                false,
            ),
        ),
    );

    let args = App::new("Exogress Assistant Server")
        .version(crate_version!())
        .author("Exogress Team <team@exogress.com>")
        .subcommand(spawn_args);

    let mut args = exogress_common::common_utils::clap::autocompletion::add_args(args);

    let matches = args.clone().get_matches().clone();
    exogress_common::common_utils::clap::autocompletion::handle_autocompletion(
        &mut args,
        &matches,
        "exogress-assistant",
    );

    let (app_stop_handle, app_stop_wait) = stop_handle::<StopReason>();

    let matches = matches
        .subcommand_matches("spawn")
        .expect("Unknown subcommand");

    let IntApiBaseUrls {
        webapp_url: webapp_base_url,
        int_client_cert,
        ..
    } = exogress_server_common::clap::int_api::extract_matches(&matches, true, false, false, false);

    let webapp_base_url = webapp_base_url.expect("no webapp_base_url");

    let _maybe_sentry = exogress_server_common::clap::sentry::extract_matches(&matches);
    let num_threads = exogress_common::common_utils::clap::threads::extract_matches(&matches);
    let kafka_brokers = exogress_server_common::kafka::clap::extract_matches(&matches);
    let dns_rules_path =
        exogress_server_common::clap::dns_rules::handle(&matches).expect("bad dns-rules arg");

    let rt = Builder::new_multi_thread()
        .enable_all()
        .worker_threads(num_threads)
        .thread_name("reactor")
        .build()
        .unwrap();

    let resolver = TokioAsyncResolver::from_system_conf(TokioHandle).unwrap();

    let logger_bg = rt
        .block_on({
            exogress_server_common::clap::log::handle(matches.clone(), "assistant", resolver, None)
        })
        .expect("error initializing logger");

    rt.spawn(logger_bg);

    let tls_config =
        if let (Some(int_tls_cert_path), Some(int_tls_key_path), Some(int_tls_auth_ca_path)) = (
            matches.value_of("int_tls_cert_path"),
            matches.value_of("int_tls_key_path"),
            matches.value_of("int_tls_auth_ca_path"),
        ) {
            Some(HttpsConfig {
                int_tls_cert: std::fs::read(int_tls_cert_path).expect("int TLS cert not found"),
                int_tls_key: std::fs::read(int_tls_key_path).expect("int TLS key not found"),
                int_tls_auth_ca: std::fs::read(int_tls_auth_ca_path)
                    .expect("int TLS CA for authentication not found"),
            })
        } else {
            None
        };

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

    let assistant_id: String = Ulid::new().to_string();

    let maybe_panic = rt.block_on({
        shadow_clone!(webapp_base_url, assistant_id, int_client_cert);

        AssertUnwindSafe(async move {
            let kafka_producer = KafkaProducer::new(kafka_brokers.as_str())
                .expect("Failed to initialize kafka producer");

            info!("Register assistant");
            let presence_client = presence::Client::new(
                webapp_base_url.clone(),
                assistant_id.clone(),
                int_client_cert.clone(),
            );

            presence_client
                .register_assistant()
                .await
                .expect("Could not register assistant");
            info!("Done");

            let periodic_send_alive = {
                let presence_client = presence_client.clone();

                #[allow(unreachable_code)]
                async move {
                    let mut interval = tokio::time::interval(Duration::from_secs(60));

                    loop {
                        interval.tick().await;
                        presence_client.assistant_alive().await?;
                    }

                    Ok::<(), anyhow::Error>(())
                }
            }
            .fuse();

            tokio::spawn(stop_signal_listener(app_stop_handle.clone()));

            let redis_client = Client::open(redis_addr.as_str()).unwrap();

            info!("Listening  HTTP on {}", listen_http_addr);

            let http = http::server(
                listen_http_addr,
                GatewayCommonTlsConfig {
                    hostname: gw_hostname,
                    tls_cert_path: gw_tls_cert_path.parse().unwrap(),
                    tls_key_path: gw_tls_key_path.parse().unwrap(),
                },
                tls_config,
                dns_rules_path,
                redis_client,
                presence_client,
                kafka_producer,
                app_stop_handle,
                app_stop_wait,
            );

            tokio::select! {
                r = http => {
                    warn!("http server stopped: {:?}", r);
                },
                r = periodic_send_alive => {
                    warn!("assistant alive sender stopped: {:?}", r);
                },
            }

            info!("Stop");
        })
        .catch_unwind()
    });

    if let Err(_e) = maybe_panic {
        error!("stop on panic");
    }

    info!("unregistering assistant");
    rt.block_on(async move {
        presence::Client::new(webapp_base_url, assistant_id, int_client_cert)
            .unregister_assistant()
            .await
    })
    .expect("Could not unregister signaler");
    info!("done");
}
