#![warn(rust_2018_idioms)]

#[macro_use]
extern crate shadow_clone;
#[macro_use]
extern crate tracing;

use crate::{
    elasticsearch::ElasticsearchClient, reporting::MongoDbClient, termination::StopReason,
};
use clap::{crate_version, App, Arg};
use exogress_common::common_utils::termination::stop_signal_listener;
use futures::FutureExt;
use std::{net::SocketAddr, panic::AssertUnwindSafe};
use stop_handle::stop_handle;
use tokio::runtime::Builder;
use trust_dns_resolver::{TokioAsyncResolver, TokioHandle};

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

mod elasticsearch;
mod http;
mod kafka;
mod reporting;
mod statistics;
mod termination;

fn main() {
    let spawn_args = App::new("spawn")
        .arg(
            Arg::with_name("listen_int_http")
                .long("listen-int-http")
                .value_name("SOCKET_ADDR")
                .default_value("0.0.0.0:12924")
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
            Arg::with_name("elasticsearch_url")
                .long("elasticsearch-url")
                .value_name("URL")
                .default_value("http://localhost:9200")
                .required(true)
                .help("Set elasticsearch URL")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("elasticsearch_ca")
                .long("elasticsearch-ca")
                .value_name("PATH")
                .required(false)
                .help("Set elasticsearch TLS CA")
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
        );

    let spawn_args = exogress_common::common_utils::clap::threads::add_args(
        exogress_server_common::clap::sentry::add_args(
            exogress_server_common::kafka::clap::add_args(
                exogress_server_common::clap::log::add_args(spawn_args),
            ),
        ),
    );

    let args = App::new("Exogress Commiter Server")
        .version(crate_version!())
        .author("Exogress Team <team@exogress.com>")
        .subcommand(spawn_args);

    let mut args = exogress_common::common_utils::clap::autocompletion::add_args(args);

    let matches = args.clone().get_matches().clone();
    exogress_common::common_utils::clap::autocompletion::handle_autocompletion(
        &mut args,
        &matches,
        "exogress-commiter",
    );

    let (app_stop_handle, app_stop_wait) = stop_handle::<StopReason>();

    let matches = matches
        .subcommand_matches("spawn")
        .expect("Unknown subcommand");

    let _maybe_sentry = exogress_server_common::clap::sentry::extract_matches(&matches);
    let kafka_brokers = exogress_server_common::kafka::clap::extract_matches(&matches);
    let num_threads = exogress_common::common_utils::clap::threads::extract_matches(&matches);

    let rt = Builder::new_multi_thread()
        .enable_all()
        .worker_threads(num_threads)
        .thread_name("reactor")
        .build()
        .unwrap();

    let resolver = TokioAsyncResolver::from_system_conf(TokioHandle).unwrap();

    let logger_bg = rt
        .block_on({
            exogress_server_common::clap::log::handle(matches.clone(), "commiter", resolver, None)
        })
        .expect("error initializing logger");

    rt.spawn(logger_bg);

    let elasticsearch_url = matches
        .value_of("elasticsearch_url")
        .expect("no --elasticsearch-url provided")
        .to_string();
    let elasticsearch_ca = matches.value_of("elasticsearch_ca").map(|s| s.to_string());
    let mongodb_url = matches
        .value_of("mongodb_url")
        .expect("no --mongodb-url provided")
        .to_string();
    let mongodb_db = matches
        .value_of("mongodb_database")
        .expect("no --mongodb-database provided")
        .to_string();
    let listen_int_http_addr = matches
        .value_of("listen_int_http")
        .map(|r| {
            r.parse::<SocketAddr>()
                .expect("Failed to parse listen  HTTP address (ip:port)")
        })
        .unwrap();

    let maybe_panic = rt.block_on({
        AssertUnwindSafe(async move {
            tokio::spawn(stop_signal_listener(app_stop_handle.clone()));

            let mongodb_client = MongoDbClient::new(mongodb_url.as_ref(), mongodb_db.as_ref())
                .await
                .expect("mongo db connection error");

            let elastic_client =
                ElasticsearchClient::new(elasticsearch_url.as_ref(), elasticsearch_ca)
                    .await
                    .expect("elasticsearch db connection error");

            info!("Listening  HTTP on {}", listen_int_http_addr);

            let http = http::server(
                listen_int_http_addr,
                mongodb_client.clone(),
                elastic_client.clone(),
                app_stop_handle,
                app_stop_wait,
            );

            let kafka_consumer_future = crate::kafka::spawn(
                kafka_brokers.as_str(),
                "commiter",
                num_threads * 8,
                mongodb_client,
                elastic_client,
            );

            tokio::select! {
                r = http => {
                    warn!("http server stopped: {:?}", r);
                },
                r = kafka_consumer_future => {
                    warn!("kafka_consumer_future stopped: {:?}", r);
                },
            }

            info!("Stop");
        })
        .catch_unwind()
    });

    if let Err(_e) = maybe_panic {
        error!("stop on panic");
    }

    info!("done");
}
