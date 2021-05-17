#![warn(rust_2018_idioms)]

#[macro_use]
extern crate shadow_clone;
#[macro_use]
extern crate tracing;
#[macro_use]
extern crate serde;

mod elasticsearch;
mod http;
mod mongodb;
mod redis_client;
mod service;
mod statistics;
mod termination;

use crate::{
    elasticsearch::ElasticsearchClient, http::run_http_server, mongodb::MongoDbClient,
    redis_client::RedisClient, service::Service, termination::StopReason,
};
use clap::{crate_version, App, Arg};
use exogress_common::common_utils::termination::stop_signal_listener;
use exogress_server_common::clap::int_api::IntApiBaseUrls;
use std::net::SocketAddr;
use stop_handle::stop_handle;
use tokio::runtime::Builder;
use trust_dns_resolver::{TokioAsyncResolver, TokioHandle};

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

fn main() {
    let spawn_args = App::new("spawn")
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
        )
        .arg(
            Arg::with_name("redis_addr")
                .long("redis-addr")
                .value_name("URL")
                .default_value("redis://127.0.0.1/7")
                .required(true)
                .help("Set redis addr")
                .takes_value(true),
        );

    let spawn_args = exogress_common::common_utils::clap::threads::add_args(
        exogress_server_common::clap::sentry::add_args(
            exogress_server_common::clap::log::add_args(spawn_args),
        ),
    );

    let args = App::new("Exogress Public API Server")
        .version(crate_version!())
        .author("Exogress Team <team@exogress.com>")
        .subcommand(spawn_args);

    let mut args = exogress_common::common_utils::clap::autocompletion::add_args(args);

    let matches = args.clone().get_matches().clone();
    exogress_common::common_utils::clap::autocompletion::handle_autocompletion(
        &mut args,
        &matches,
        "exogress-api",
    );

    let (app_stop_handle, app_stop_wait) = stop_handle::<StopReason>();

    let matches = matches
        .subcommand_matches("spawn")
        .expect("Unknown subcommand");

    let _maybe_sentry = exogress_server_common::clap::sentry::extract_matches(&matches);
    let num_threads = exogress_common::common_utils::clap::threads::extract_matches(&matches);
    let IntApiBaseUrls {
        int_client_cert,
        assistant_url,
        ..
    } = exogress_server_common::clap::int_api::extract_matches(&matches, false, true, false, false);

    let rt = Builder::new_multi_thread()
        .enable_all()
        .worker_threads(num_threads)
        .thread_name("assistant-reactor")
        .build()
        .unwrap();

    let resolver = TokioAsyncResolver::from_system_conf(TokioHandle).unwrap();

    let logger_bg = rt
        .block_on({
            exogress_server_common::clap::log::handle(matches.clone(), "api", resolver, None)
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

    rt.block_on(async move {
        tokio::spawn(stop_signal_listener(app_stop_handle.clone()));

        let redis_client = RedisClient::new(redis_addr.as_str())
            .await
            .expect("Error connecting to redis");

        let mongodb_client = MongoDbClient::new(mongodb_url.as_ref(), mongodb_db.as_ref())
            .await
            .expect("mongo db connection error");

        let elastic_client = ElasticsearchClient::new(elasticsearch_url.as_ref(), elasticsearch_ca)
            .await
            .expect("elasticsearch db connection error");

        info!("Listening  HTTP on {}", listen_http_addr);

        let service: Service = Service::builder()
            .redis(redis_client)
            .elasticsearch(elastic_client)
            .mongodb(mongodb_client)
            .build();

        run_http_server(service, listen_http_addr, app_stop_wait).await;

        info!("Stop");
    });

    info!("done");
}
