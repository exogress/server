#![warn(rust_2018_idioms)]

#[macro_use]
extern crate shadow_clone;
#[macro_use]
extern crate slog;

use std::net::SocketAddr;
use std::panic;

use clap::{crate_version, App, Arg};
use futures::{pin_mut, select};
use futures::{FutureExt, SinkExt};
use lazy_static::lazy_static;
use mimalloc::MiMalloc;
use redis::Client;
use smartstring::alias::String;
use stop_handle::stop_handle;

use exogress_server_common::clap as clap_helpers;
use exogress_server_common::termination::stop_signal_listener;

use crate::termination::StopReason;
use std::panic::AssertUnwindSafe;
use std::time::Duration;
use tokio::runtime::Builder;

mod http;
mod presence;
mod termination;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

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
                .about("Set websocket listen address")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("listen_private_http")
                .long("listen-private-http")
                .value_name("SOCKET_ADDR")
                .default_value("0.0.0.0:2999")
                .required(true)
                .about("Set private HTTP listen address")
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
        )
        .arg(
            Arg::with_name("webapp_base_url")
                .long("webapp-base-url")
                .value_name("URL")
                .default_value("http://localhost:3000")
                .required(true)
                .about("Set webapp base URL")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("signaler_id")
                .long("signaler-id")
                .value_name("STRING")
                .about("Use this signaler-id as an identifier for presence API")
                .required(true)
                .takes_value(true),
        );

    let spawn_args = clap_helpers::threads::add_args(clap_helpers::sentry::add_args(
        clap_helpers::log::add_args(spawn_args),
    ));

    let args = App::new("Exogress Signaler Server")
        .version(crate_version!())
        .author("Exogress Team <team@exogress.com>")
        .subcommand(spawn_args);

    let mut args = clap_helpers::autocompletion::add_args(args);

    let matches = args.clone().get_matches().clone();
    clap_helpers::autocompletion::handle_autocompletion(&mut args, &matches, "exogress-signaler");

    let (app_stop_handle, mut app_stop_wait) = stop_handle::<StopReason>();

    let matches = matches
        .subcommand_matches("spawn")
        .expect("Unknown subcommand");

    let maybe_sentry = clap_helpers::sentry::extract_matches(&matches);
    let log = clap_helpers::log::extract_matches(
        &matches,
        "signaler",
        maybe_sentry.map(|(_, _, drain)| drain),
    );
    let num_threads = clap_helpers::threads::extract_matches(&matches, &log);

    let signaler_id: String = matches
        .value_of("signaler_id")
        .expect("no signaler_id provided")
        .into();

    let redis_addr: String = matches
        .value_of("redis_addr")
        .expect("no redis addr provided")
        .into();

    let webapp_base_url: String = matches
        .value_of("webapp_base_url")
        .expect("no webapp base url provided")
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

    let mut rt = Builder::new()
        .threaded_scheduler()
        .enable_all()
        .core_threads(num_threads)
        .thread_name("signaler-reactor")
        .build()
        .unwrap();

    let maybe_panic = rt.block_on({
        shadow_clone!(log);
        let webapp_base_url = webapp_base_url.clone();
        let signaler_id = signaler_id.clone();

        AssertUnwindSafe(async move {
            let presence_client = presence::Client::new(webapp_base_url, signaler_id);

            tokio::spawn(stop_signal_listener(app_stop_handle.clone(), log.clone()));

            presence_client
                .register_signaler()
                .await
                .expect("Could not register signaler");

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

            info!(log, "Listening public HTTP on {}", listen_public_http_addr);

            let redis_client = Client::open(redis_addr.as_str()).unwrap();

            let (public_server_graceful_stop_handle, public_server_graceful_stop_wait) =
                stop_handle();
            let (private_server_graceful_stop_handle, private_server_graceful_stop_wait) =
                stop_handle();

            tokio::spawn(http::public::server(
                listen_public_http_addr,
                presence_client.clone(),
                redis_client.clone(),
                public_server_graceful_stop_wait,
                log.clone(),
            ));

            info!(
                log,
                "Listening private HTTP on {}", listen_private_http_addr
            );

            tokio::spawn(http::private::server(
                listen_private_http_addr,
                redis_client,
                private_server_graceful_stop_wait,
                log.clone(),
            ));

            pin_mut!(periodic_send_alive);

            let http_termination_reason = select! {
                r = periodic_send_alive => {
                    match r {
                        Err(e) => {
                            error!(log, "Could not send signaler alive: {}", e);
                        }
                        Ok(()) => {
                            crit!(log, "Signaler alive unexpectedly stopped");
                        }
                    };
                    stop_handle::StopReason::Requested(StopReason::PeriodicSenderTerminated)
                },
                r = app_stop_wait => {
                    info!(log, "Stop {}", r);
                    r
                },
            };

            public_server_graceful_stop_handle.stop(http_termination_reason.clone());
            private_server_graceful_stop_handle.stop(http_termination_reason);

            info!(log, "Signaler server stopped. Unregistering");
        })
        .catch_unwind()
    });

    if let Err(_e) = maybe_panic {
        error!(log, "stop on panic");
    }

    rt.block_on(async move {
        presence::Client::new(webapp_base_url, signaler_id)
            .unregister_signaler()
            .await
    })
    .expect("Could not unregister signaler");
}
