#![warn(rust_2018_idioms)]

#[macro_use]
extern crate shadow_clone;
#[macro_use]
extern crate tracing;
#[macro_use]
extern crate serde;

use crate::http::GatewayCommonTlsConfig;
use crate::reporting::MongoDbClient;
use crate::termination::StopReason;
use clap::{crate_version, App, Arg};
use exogress_common_utils::termination::stop_signal_listener;
use exogress_entities::Ulid;
use exogress_server_common::clap::int_api::IntApiBaseUrls;
use futures::FutureExt;
use redis::Client;
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::time::Duration;
use stop_handle::stop_handle;
use tokio::runtime::Builder;
use trust_dns_resolver::TokioAsyncResolver;

mod http;
mod presence;
mod reporting;
mod termination;
mod webapp;

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
            Arg::with_name("mongodb_url")
                .long("mongodb-url")
                .value_name("URL")
                .default_value("mongodb://localhost:27017")
                .required(true)
                .help("Set mongodb URL")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("mongodb_database")
                .long("mongodb-database")
                .value_name("STRING")
                .default_value("webapp_development")
                .required(true)
                .help("Set mongodb database name")
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

    let spawn_args = exogress_server_common::clap::int_api::add_args(
        exogress_common_utils::clap::threads::add_args(
            exogress_server_common::clap::sentry::add_args(
                exogress_server_common::clap::log::add_args(spawn_args),
            ),
        ),
        true,
        false,
        false,
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

    let IntApiBaseUrls {
        webapp_url: webapp_base_url,
        int_client_cert,
        ..
    } = exogress_server_common::clap::int_api::extract_matches(&matches, true, false, false);

    let webapp_base_url = webapp_base_url.expect("no webapp_base_url");

    let _maybe_sentry = exogress_server_common::clap::sentry::extract_matches(&matches);
    let num_threads = exogress_common_utils::clap::threads::extract_matches(&matches);

    let mut rt = Builder::new()
        .threaded_scheduler()
        .enable_all()
        .core_threads(num_threads)
        .thread_name("assistant-reactor")
        .build()
        .unwrap();

    let resolver = rt
        .block_on(TokioAsyncResolver::from_system_conf(rt.handle().clone()))
        .unwrap();

    let logger_bg = rt
        .block_on({
            shadow_clone!(int_client_cert);

            exogress_server_common::clap::log::handle(
                matches.clone(),
                "assistant",
                resolver.clone(),
                None,
            )
        })
        .expect("error initializing logger");

    rt.spawn(logger_bg);

    info!("Use Webapp url at {}", webapp_base_url);
    let webapp_client =
        crate::webapp::Client::new(webapp_base_url.clone(), int_client_cert.clone());

    let mongodb_url = matches
        .value_of("mongodb_url")
        .expect("no --mongodb-url provided")
        .to_string();
    let mongodb_db = matches
        .value_of("mongodb_database")
        .expect("no --mongodb-database provided")
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

    let assistant_id: String = Ulid::new().to_string().into();

    let maybe_panic = rt.block_on({
        shadow_clone!(webapp_base_url);
        shadow_clone!(assistant_id);
        shadow_clone!(int_client_cert);

        AssertUnwindSafe(async move {
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

            let mongodb_client = MongoDbClient::new(mongodb_url.as_ref(), mongodb_db.as_ref())
                .await
                .expect("mongo db connection error");

            info!("Listening  HTTP on {}", listen_http_addr);

            let http = http::server(
                listen_http_addr,
                GatewayCommonTlsConfig {
                    hostname: gw_hostname,
                    tls_cert_path: gw_tls_cert_path.parse().unwrap(),
                    tls_key_path: gw_tls_key_path.parse().unwrap(),
                },
                redis_client,
                webapp_client,
                presence_client,
                mongodb_client,
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
