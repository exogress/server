#[macro_use]
extern crate clap;
#[macro_use]
extern crate tracing;
#[macro_use]
extern crate shadow_clone;
#[macro_use]
extern crate anyhow;

mod api;
mod bucket;
mod db;
mod helpers;
mod magick;
mod processor;
mod statistics;
mod termination;
mod webapp;

use crate::{
    api::api_handler,
    bucket::{GcsBucketClient, ALL_LOCATIONS},
    db::{listen_queue, MongoDbClient},
    processor::Processor,
    statistics::dump_prometheus,
    termination::StopReason,
};
use clap::{App, Arg};
use exogress_common::common_utils::termination::stop_signal_listener;
use exogress_server_common::clap::int_api::IntApiBaseUrls;
use futures_util::future::FutureExt;
use mimalloc::MiMalloc;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use stop_handle::stop_handle;
use tokio::{runtime::Builder, sync::mpsc};
use trust_dns_resolver::{TokioAsyncResolver, TokioHandle};
use warp::Filter;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn main() {
    let all_gcs_locations_strings: Vec<_> =
        ALL_LOCATIONS.iter().map(|loc| loc.to_string()).collect();
    let spawn_args = App::new("spawn")
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
                .default_value("transformer_develop")
                .required(true)
                .help("Set mongodb database name")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("gcs_bucket_location")
                .long("gcs-bucket-location")
                .value_name("STRING")
                .possible_values(
                    &all_gcs_locations_strings
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>(),
                )
                .required(true)
                .help("Set GCS bucket location of the provided bucket")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("gcs_bucket")
                .long("gcs-bucket")
                .value_name("STRING")
                .required(true)
                .help("Set GCS bucket to store the data")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("gcs_credentials_file")
                .long("gcs-credentials-file")
                .value_name("STRING")
                .required(true)
                .help("The path to GCS credentials file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("listen_http")
                .long("listen-http")
                .value_name("SOCKET_ADDR")
                .default_value("0.0.0.0:3976")
                .required(true)
                .help("Set HTTP listen address")
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

    let args = App::new("Exogress Transformer")
        .about("Performs conversion to modern formats, like WebP")
        .version(crate_version!())
        .author("Exogress Team <team@exogress.com>")
        .subcommand(spawn_args);

    let mut args = exogress_common::common_utils::clap::autocompletion::add_args(args);

    let matches = args.clone().get_matches().clone();
    exogress_common::common_utils::clap::autocompletion::handle_autocompletion(
        &mut args,
        &matches,
        "exogress-transformer",
    );

    let (app_stop_handle, app_stop_wait) = stop_handle::<StopReason>();

    let matches = matches
        .subcommand_matches("spawn")
        .expect("Unknown subcommand");

    let mongodb_url = matches
        .value_of("mongodb_url")
        .expect("no --mongodb-url provided")
        .to_string();

    let mongodb_db = matches
        .value_of("mongodb_database")
        .expect("no --mongodb-database provided")
        .to_string();

    let gcs_credentials_file = matches
        .value_of("gcs_credentials_file")
        .expect("no --gcs-credentials-file provided")
        .to_string();

    let gcs_bucket = matches
        .value_of("gcs_bucket")
        .expect("no --gcs-bucket provided")
        .to_string();

    let gcs_bucket_location = matches
        .value_of("gcs_bucket_location")
        .expect("no --gcs-bucket-location provided")
        .parse()
        .expect("bad gcs-bucket-location");

    let _maybe_sentry = exogress_server_common::clap::sentry::extract_matches(&matches);
    let num_threads = exogress_common::common_utils::clap::threads::extract_matches(&matches);
    let IntApiBaseUrls {
        webapp_url: webapp_base_url,
        int_client_cert,
        ..
    } = exogress_server_common::clap::int_api::extract_matches(&matches, true, false, false);

    let listen_http = matches
        .value_of("listen_http")
        .map(|r| {
            r.parse::<SocketAddr>()
                .expect("Failed to parse listen HTTP address (ip:port)")
        })
        .unwrap();

    let rt = Builder::new_multi_thread()
        .enable_all()
        .worker_threads(num_threads)
        .thread_name("transformer-reactor")
        .build()
        .unwrap();

    let resolver = TokioAsyncResolver::from_system_conf(TokioHandle).unwrap();

    let logger_bg = rt
        .block_on({
            exogress_server_common::clap::log::handle(
                matches.clone(),
                "transformer",
                resolver,
                int_client_cert.clone(),
            )
        })
        .expect("could not initialize logger");

    rt.spawn(logger_bg);

    info!("listen HTTP: {}", listen_http);

    let webapp_base_url = webapp_base_url.unwrap();

    rt.block_on(async move {
        tokio::spawn(stop_signal_listener(app_stop_handle.clone()));

        info!("Use MongoDB at {}. DB: {}", mongodb_url, mongodb_db);

        let (for_processing_tx, for_processing_rx) = mpsc::channel(1);

        let mongodb_client = MongoDbClient::new(mongodb_url.as_ref(), mongodb_db.as_ref())
            .await
            .expect("mongo db connection error");

        let queue_reader = tokio::spawn({
            shadow_clone!(mongodb_client);

            async move {
                let r = listen_queue(mongodb_client, for_processing_tx).await;
                error!("queue res = {:?}", r);
            }
        });

        info!("Use Webapp url at {}", webapp_base_url);
        let webapp_client =
            crate::webapp::Client::new(webapp_base_url.clone(), int_client_cert.clone());

        let prometheus = warp::path!("metrics").map(|| dump_prometheus());
        let gcs_bucket =
            GcsBucketClient::new(gcs_bucket, gcs_bucket_location, gcs_credentials_file)
                .expect("GCS bucket config error");

        let (_, server) = warp::serve(
            api_handler(
                webapp_client.clone(),
                mongodb_client.clone(),
                gcs_bucket.clone(),
            )
            .or(prometheus),
        )
        .bind_with_graceful_shutdown(
            listen_http,
            app_stop_wait.map(move |r| info!("HTTP server stop request received: {}", r)),
        );

        let processor = tokio::spawn(
            Processor::new(
                4,
                webapp_client,
                mongodb_client,
                gcs_bucket,
                for_processing_rx,
            )
            .run(),
        );

        tokio::select! {
            _ = processor => {
                info!("Processor exited");
            },
            _ = queue_reader => {
                info!("Queue Reader exited");
            },
            _ = server => {},
        }
    });
}
