#![warn(rust_2018_idioms)]

#[macro_use]
extern crate shadow_clone;
#[macro_use]
extern crate tracing;
#[macro_use]
extern crate serde;
#[macro_use]
extern crate prometheus;

use std::net::SocketAddr;

use clap::{crate_version, App, Arg};
use futures::FutureExt;
use lazy_static::lazy_static;
use redis::Client;
use stop_handle::stop_handle;

use crate::termination::StopReason;
use exogress_common::common_utils::termination::stop_signal_listener;
use exogress_common::entities::Ulid;
use exogress_server_common::clap::int_api::IntApiBaseUrls;
use exogress_server_common::presence;
use std::panic::AssertUnwindSafe;
use std::time::Duration;
use tokio::runtime::Builder;
use trust_dns_resolver::{TokioAsyncResolver, TokioHandle};

mod http;
mod statistics;
mod termination;

lazy_static! {
    static ref DEFAULT_HOSTNAME: std::string::String = hostname::get()
        .ok()
        .unwrap_or_else(|| "unknown".into())
        .into_string()
        .expect("error in ");
}

fn main() {
    let spawn_args = App::new("spawn")
        .arg(
            Arg::with_name("listen_public_http")
                .long("listen-public-http")
                .value_name("SOCKET_ADDR")
                .default_value("0.0.0.0:2998")
                .required(true)
                .help("Set websocket listen address")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("listen_private_http")
                .long("listen-private-http")
                .value_name("SOCKET_ADDR")
                .default_value("0.0.0.0:2999")
                .required(true)
                .help("Set private HTTP listen address")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("redis_addr")
                .long("redis-addr")
                .value_name("URL")
                .default_value("redis://127.0.0.1")
                .required(true)
                .help("Set redis addr")
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
    );

    let args = App::new("Exogress Signaler Server")
        .version(crate_version!())
        .author("Exogress Team <team@exogress.com>")
        .subcommand(spawn_args);

    let mut args = exogress_common::common_utils::clap::autocompletion::add_args(args);

    let matches = args.clone().get_matches().clone();
    exogress_common::common_utils::clap::autocompletion::handle_autocompletion(
        &mut args,
        &matches,
        "exogress-signaler",
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
    let _maybe_sentry = exogress_server_common::clap::sentry::extract_matches(&matches);

    let num_threads = exogress_common::common_utils::clap::threads::extract_matches(&matches);
    let rt = Builder::new_multi_thread()
        .enable_all()
        .worker_threads(num_threads)
        .thread_name("signaler-reactor")
        .build()
        .unwrap();

    let resolver = TokioAsyncResolver::from_system_conf(TokioHandle).unwrap();

    let logger_bg = rt
        .block_on({
            shadow_clone!(int_client_cert);

            exogress_server_common::clap::log::handle(
                matches.clone(),
                "signaker",
                resolver.clone(),
                None,
            )
        })
        .expect("error initializing logger");

    rt.spawn(logger_bg);

    let webapp_base_url = webapp_base_url.expect("no webapp_base_url");

    let redis_addr: String = matches
        .value_of("redis_addr")
        .expect("no redis addr provided")
        .into();

    let listen_public_http_addr = matches
        .value_of("listen_public_http")
        .map(|r| {
            r.parse::<SocketAddr>()
                .expect("Failed to parse listen public HTTP address (ip:port)")
        })
        .unwrap();

    let listen_private_http_addr = matches
        .value_of("listen_private_http")
        .map(|r| {
            r.parse::<SocketAddr>()
                .expect("Failed to parse listen private HTTP address (ip:port)")
        })
        .unwrap();

    let signaler_id: String = Ulid::new().to_string().into();

    let maybe_panic = rt.block_on({
        shadow_clone!(webapp_base_url);
        shadow_clone!(int_client_cert);
        shadow_clone!(signaler_id);

        AssertUnwindSafe(async move {
            println!("spawn presence client");

            let presence_client =
                presence::Client::new(webapp_base_url, signaler_id, int_client_cert);

            tokio::spawn(stop_signal_listener(app_stop_handle.clone()));

            println!("Spawning signaler");

            presence_client
                .register_signaler()
                .await
                .expect("Could not register signaler");
            println!("Signaler registered");

            let periodic_send_alive = {
                let presence_client = presence_client.clone();

                #[allow(unreachable_code)]
                async move {
                    let mut interval = tokio::time::interval(Duration::from_secs(60));

                    loop {
                        interval.tick().await;
                        presence_client.signaler_alive().await?;
                    }

                    Ok::<(), anyhow::Error>(())
                }
            }
            .fuse();

            println!("Listening public HTTP on {}", listen_public_http_addr);
            println!("Use redis at {} for notification", redis_addr);

            let redis_client = Client::open(redis_addr.as_str()).unwrap();

            let (public_server_graceful_stop_handle, public_server_graceful_stop_wait) =
                stop_handle();
            let (private_server_graceful_stop_handle, private_server_graceful_stop_wait) =
                stop_handle();

            tokio::spawn(http::public::server(
                listen_public_http_addr,
                presence_client.clone(),
                redis_client.clone(),
                app_stop_handle.clone(),
                public_server_graceful_stop_wait,
            ));

            info!("Listening private HTTP on {}", listen_private_http_addr);

            tokio::spawn(http::private::server(
                listen_private_http_addr,
                redis_client,
                private_server_graceful_stop_wait,
            ));

            let http_termination_reason = tokio::select! {
                r = periodic_send_alive => {
                    match r {
                        Err(e) => {
                            error!("Could not send signaler alive: {}", e);
                        }
                        Ok(()) => {
                            error!("Signaler alive unexpectedly stopped");
                        }
                    };
                    stop_handle::StopReason::Requested(StopReason::PeriodicSenderTerminated)
                },
                r = app_stop_wait => {
                    info!("Stop {}", r);
                    r
                },
            };

            public_server_graceful_stop_handle.stop(http_termination_reason.clone());
            private_server_graceful_stop_handle.stop(http_termination_reason);

            info!("Signaler server stopped. Unregistering");
        })
        .catch_unwind()
    });

    if let Err(_e) = maybe_panic {
        error!("stop on panic");
    }

    rt.block_on(async move {
        presence::Client::new(webapp_base_url, signaler_id, int_client_cert)
            .unregister_signaler()
            .await
    })
    .expect("Could not unregister signaler");
}
