#![warn(rust_2018_idioms)]

#[macro_use]
extern crate shadow_clone;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate tracing;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate prometheus;
#[macro_use]
extern crate maplit;

use async_compression::futures::write::GzipDecoder;
use clap::{crate_version, App, Arg};
use futures::io::BufWriter;
use futures_util::io::AsyncWriteExt;
use rules_counter::AccountRulesCounters;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use progress_bar::progress_bar::ProgressBar;
use reqwest::header;
use stop_handle::stop_handle;
use tempfile::NamedTempFile;
use url::Url;

use crate::clients::{tunnels_acceptor, ClientTunnels};

use crate::http_serve::auth::github::GithubOauth2Client;
use crate::http_serve::auth::google::GoogleOauth2Client;
use crate::stop_reasons::StopReason;
use crate::url_mapping::notification_listener::AssistantClient;
use crate::webapp::Client;
use exogress_common_utils::termination::stop_signal_listener;
use exogress_server_common::assistant::{
    HealthReport, RulesRecord, StatisticsReport, TrafficRecord, WsFromGwMessage,
};
use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};
use parking_lot::RwLock;
use tokio::runtime::{Builder, Handle};
use tokio::time::delay_for;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

mod clients;
mod dbip;
// mod environments;
mod config;
mod http_serve;
mod int_server;
mod mime_helpers;
mod rules_counter;
mod statistics;
mod stop_reasons;
mod url_mapping;
mod webapp;

fn main() {
    let spawn_args = App::new("spawn")
        .arg(
            Arg::with_name("assistant_base_url")
                .long("assistant-base-url")
                .value_name("URL")
                .required(true)
                .help("Assistant base URL")
                .default_value("ws://localhost:3214")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("public_base_url")
                .long("public-base-url")
                .value_name("URL")
                .required(true)
                .help("Public base URL")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("google_oauth2_client_id")
                .long("google-oauth2-client-id")
                .value_name("STRING")
                .required(true)
                .help("Google oAuth2 client ID")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("google_oauth2_client_secret")
                .long("google-oauth2-client-secret")
                .value_name("STRING")
                .required(true)
                .help("Google oAuth2 client Secret")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("github_oauth2_client_id")
                .long("github-oauth2-client-id")
                .value_name("STRING")
                .required(true)
                .help("Github oAuth2 client ID")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("github_oauth2_client_secret")
                .long("github-oauth2-client-secret")
                .value_name("STRING")
                .required(true)
                .help("Github oAuth2 client Secret")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("listen_http")
                .long("listen-http")
                .value_name("SOCKET_ADDR")
                .default_value("0.0.0.0:1337")
                .required(true)
                .help("Set HTTP listen address")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("listen_https")
                .long("listen-https")
                .value_name("SOCKET_ADDR")
                .default_value("0.0.0.0:2443")
                .required(true)
                .help("Set HTTPS listen address")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("listen_tunnel")
                .long("listen-tunnel")
                .value_name("SOCKET_ADDR")
                .default_value("0.0.0.0:10714")
                .required(true)
                .help("Tunnels listener")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("listen_int_https")
                .long("listen-int-https")
                .value_name("SOCKET_ADDR")
                .default_value("0.0.0.0:3443")
                .required(true)
                .help("Set HTTPS listen address")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("individual_tls_cert_path")
                .long("individual-tls-cert-path")
                .value_name("PATH")
                .help("Certificate to use")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("individual_tls_key_path")
                .long("individual-tls-key-path")
                .value_name("PATH")
                .help("Key file to use")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("individual_hostname")
                .long("individual-hostname")
                .value_name("HOSTNAME")
                .help("Own hostname to use for client tunnel connections")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("location")
                .long("location")
                .value_name("STRING")
                .help("Gateway location")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("external_https_port")
                .long("external-https-port")
                .value_name("PORT")
                .help("Redefine external HTTPS port to use")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("webroot")
                .long("webroot")
                .value_name("PATH")
                .help("Set webroot path for certbot interaction")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("int_api_base_url")
                .long("int-api-base-url")
                .value_name("URL")
                .default_value("http://localhost:2999")
                .help("Set private signaler base URL")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("cache_ttl_secs")
                .long("cache-ttl")
                .value_name("SECONDS")
                .default_value("600") // 10 minutes
                .help("Keep data upto the number of seconds")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("download_dbip")
                .long("download-dbip")
                .help("Perform DBIP download")
                .requires("isp_location_dbip_url"),
        )
        .arg(
            Arg::with_name("isp_location_dbip_url")
                .long("isp-location-dbip-url")
                .env("ISP_LOCATION_DBIP_URL")
                .value_name("URL")
                .help("ISP DBIP Download URL")
                .takes_value(true)
                .default_value("https://repos.lancastr.net/dbip-mirror/stable/files/dbip-location-isp/latest/dbip-location-isp.gz"),
        )
        .arg(
            Arg::with_name("dbip_download_dir")
                .long("dbip-download-dir")
                .env("DBIP_DOWNLOAD_DIR")
                .value_name("PATH")
                .help("ISP DBIP Download into this dir. If not set temporary directory will be created")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("dbip_path")
                .long("dbip-path")
                .conflicts_with("download_dbip")
                .value_name("PATH")
                .env("DBIP_PATH")
                .help("Path to MMDB database")
                .takes_value(true),
        );

    let spawn_args = exogress_server_common::clap::webapp::add_args(
        exogress_common_utils::clap::threads::add_args(
            exogress_server_common::clap::sentry::add_args(
                exogress_common_utils::clap::log::add_args(spawn_args),
            ),
        ),
    );

    let args = App::new("Exogress Gateway")
        .version(crate_version!())
        .author("Exogress Team <team@exogress.com>")
        .about("Load-balancing cloud gateway")
        .subcommand(spawn_args);

    let mut args = exogress_common_utils::clap::autocompletion::add_args(args);

    let matches = args.clone().get_matches().clone();
    exogress_common_utils::clap::autocompletion::handle_autocompletion(
        &mut args,
        &matches,
        "exogress-gateway",
    );

    let matches = matches
        .subcommand_matches("spawn")
        .expect("Unknown subcommand");

    let webapp_base_url = exogress_server_common::clap::webapp::extract_matches(&matches);
    let _maybe_sentry = exogress_server_common::clap::sentry::extract_matches(&matches);
    exogress_common_utils::clap::log::handle(&matches, "gw");
    let num_threads = exogress_common_utils::clap::threads::extract_matches(&matches);

    let mut rt = Builder::new()
        .threaded_scheduler()
        .enable_all()
        .core_threads(num_threads)
        .thread_name("gateway-reactor")
        .build()
        .unwrap();

    let (app_stop_handle, app_stop_wait) = stop_handle();

    let public_base_url: Url = matches
        .value_of("public_base_url")
        .unwrap()
        .parse()
        .expect("bad URL format");

    let assistant_base_url: Url = matches
        .value_of("assistant_base_url")
        .unwrap()
        .parse()
        .expect("bad assistant URL format");

    let google_oauth2_client_id = matches.value_of("google_oauth2_client_id").unwrap().into();
    let google_oauth2_client_secret = matches
        .value_of("google_oauth2_client_secret")
        .unwrap()
        .into();

    let github_oauth2_client_id = matches.value_of("github_oauth2_client_id").unwrap().into();
    let github_oauth2_client_secret = matches
        .value_of("github_oauth2_client_secret")
        .unwrap()
        .into();

    let cache_ttl: Duration = Duration::from_secs(
        matches
            .value_of("cache_ttl_secs")
            .unwrap()
            .parse()
            .expect("bad TTL value"),
    );

    let individual_tls_cert_path = matches.value_of("individual_tls_cert_path").unwrap();
    let individual_tls_key_path = matches.value_of("individual_tls_key_path").unwrap();

    info!("Use Webapp url at {}", webapp_base_url);

    let webroot: PathBuf = fs::canonicalize(
        matches
            .value_of("webroot")
            .expect("no webroot defined")
            .to_string(),
    )
    .expect("error in webroot");
    info!("Use certbot webroot at {}", webroot.display());

    let int_api_base_url: Url = matches
        .value_of("int_api_base_url")
        .expect("no int_api_base_url")
        .parse()
        .expect("bad int_api_base_url");

    let listen_http_addr = matches
        .value_of("listen_http")
        .map(|r| {
            r.parse::<SocketAddr>()
                .expect("Failed to parse listen HTTP address (ip:port)")
        })
        .unwrap();

    let listen_int_https_addr = matches
        .value_of("listen_int_https")
        .map(|r| {
            r.parse::<SocketAddr>()
                .expect("Failed to parse listen int HTTPS address (ip:port)")
        })
        .unwrap();

    let listen_https_addr = matches
        .value_of("listen_https")
        .map(|r| {
            r.parse::<SocketAddr>()
                .expect("Failed to parse listen HTTPS address (ip:port)")
        })
        .unwrap();

    let listen_tunnel_addr = matches
        .value_of("listen_tunnel")
        .map(|r| {
            r.parse::<SocketAddr>()
                .expect("Failed to parse tunnel listen addr (ip:port)")
        })
        .unwrap();

    rt.block_on(async move {
        let temp_db_file = NamedTempFile::new().expect("could not create named temp file");

        let db_path = if matches.is_present("download_dbip") {
            use tokio_util::compat::Tokio02AsyncReadCompatExt;

            let (db_file, db_path) = match matches.value_of("dbip_download_dir") {
                Some(download_dir) => {
                    let db_path = PathBuf::from(download_dir.to_string()).join("dbip.mmdb");

                    if db_path.exists() {
                        fs::remove_file(&db_path).expect("Could not delete DB");
                    };

                    (
                        tokio::fs::File::create(&db_path)
                            .await
                            .expect("Could not create dbip path"),
                        db_path,
                    )
                }
                None => (
                    tokio::fs::File::from(
                        temp_db_file.reopen().expect("could not reopen temp file"),
                    ),
                    temp_db_file.path().to_path_buf(),
                ),
            };

            let dbip_url = matches
                .value_of("isp_location_dbip_url")
                .unwrap()
                .to_string();

            let client = reqwest::Client::new();

            let total_size = {
                let resp = client
                    .head(dbip_url.as_str())
                    .send()
                    .await
                    .expect("could not get DB size");
                if resp.status().is_success() {
                    resp.headers()
                        .get(header::CONTENT_LENGTH)
                        .and_then(|ct_len| ct_len.to_str().ok())
                        .and_then(|ct_len| ct_len.parse().ok())
                        .unwrap_or(0)
                } else {
                    error!("error getting geo DB size: {:?}", resp.status());
                    panic!("could not get DB size");
                }
            };

            let mut pb = ProgressBar::new(total_size);

            let mut compressed_csv_db = reqwest::get(&dbip_url)
                .await
                .expect("Could not download dbip DB");

            let mut decoder = GzipDecoder::new(BufWriter::new(db_file.compat()));

            println!(
                "Downloading dbip mmdb file from {:?} to {:?}...",
                dbip_url, db_path
            );

            let mut read_bytes: usize = 0;

            while let Some(chunk) = compressed_csv_db.chunk().await? {
                read_bytes += chunk.len();
                pb.set_progression(read_bytes);
                decoder.write_all(&chunk).await.expect("Error writing DB");
            }

            decoder.close().await.expect("Error writing DB");

            println!("Download complete!");

            Some(db_path)
        } else {
            matches
                .value_of("dbip_path")
                .map(|path| PathBuf::from(path.to_string()))
        };

        let dbip = db_path.map(|path| {
            info!("Opening maxminddb...");
            let dbip = Arc::new(maxminddb::Reader::open_mmap(&path).expect("Failed to open dbip"));
            info!("maxminddb successfully opened");

            let loc = dbip
                .lookup::<dbip::LocationAndIsp>("123.33.22.123".parse().unwrap())
                .unwrap();

            info!(
                "{}/{}",
                loc.country
                    .clone()
                    .and_then(|c| c.iso_code)
                    .unwrap_or_default(),
                loc.city
                    .clone()
                    .and_then(|c| c.names.and_then(|n| n.en))
                    .unwrap_or_default()
            );

            dbip
        });

        tokio::spawn(stop_signal_listener(app_stop_handle.clone()));

        info!("Listening int HTTPS on https://{}", listen_int_https_addr);
        tokio::spawn(int_server::spawn(
            listen_int_https_addr,
            individual_tls_cert_path.into(),
            individual_tls_key_path.into(),
        ));

        let external_https_port = matches
            .value_of("external_https_port")
            .map(|r| r.parse().expect("Could not parse external_https_port"))
            .unwrap_or_else(|| listen_https_addr.port());

        info!("Listening HTTP on {}", listen_http_addr);
        info!(
            "Listening HTTPS on {}, external_port is {}",
            listen_https_addr, external_https_port
        );

        let client_tunnels = ClientTunnels::new(int_api_base_url);

        let (tunnel_counters_tx, tunnel_counters_rx) = mpsc::channel(16536);

        tokio::spawn(tunnels_acceptor(
            listen_tunnel_addr,
            individual_tls_cert_path.into(),
            individual_tls_key_path.into(),
            client_tunnels.clone(),
            tunnel_counters_tx,
        ));

        let (mut statistics_tx, statistics_rx) = mpsc::channel::<WsFromGwMessage>(16);

        let individual_hostname = matches
            .value_of("individual_hostname")
            .expect("Please provide --individual-hostname")
            .to_string();

        let gw_location = matches
            .value_of("location")
            .expect("Please provide --location")
            .to_string();

        let account_rules_counters = AccountRulesCounters::new();
        let (health_state_change_tx, health_state_change_rx) = mpsc::channel(256);

        let dump_health_changes = {
            shadow_clone!(individual_hostname);
            shadow_clone!(mut statistics_tx);

            const CHUNK: usize = 2048;
            let mut ready_chunks = health_state_change_rx.ready_chunks(CHUNK);
            async move {
                while let Some(ready_chunks) = ready_chunks.next().await {
                    let should_wait = ready_chunks.len() != CHUNK;

                    info!("health report: {:?}", ready_chunks);

                    let batch = WsFromGwMessage::Health {
                        report: HealthReport::UpstreamsHealth {
                            records: ready_chunks,
                        },
                    };

                    statistics_tx.send(batch).await?;
                    if should_wait {
                        delay_for(Duration::from_secs(5)).await;
                    }
                }

                Ok::<_, anyhow::Error>(())
            }
        };

        let dump_traffic_statistics = {
            shadow_clone!(individual_hostname);
            shadow_clone!(mut statistics_tx);

            const CHUNK: usize = 2048;
            let mut ready_chunks = tunnel_counters_rx.ready_chunks(CHUNK);
            async move {
                while let Some(ready_chunks) = ready_chunks.next().await {
                    let should_wait = ready_chunks.len() != CHUNK;

                    let batch = WsFromGwMessage::Statistics {
                        report: StatisticsReport::Traffic {
                            records: ready_chunks
                                .into_iter()
                                .map(|statistics| TrafficRecord {
                                    account_name: statistics.account_name,
                                    tunnel_bytes_gw_tx: statistics.bytes_written,
                                    tunnel_bytes_gw_rx: statistics.bytes_read,
                                    from: statistics.from,
                                    to: statistics.to,
                                })
                                .collect(),
                        },
                    };

                    statistics_tx.send(batch).await?;

                    if should_wait {
                        delay_for(Duration::from_secs(20)).await;
                    }
                }

                Ok::<_, anyhow::Error>(())
            }
        };

        let dump_rules_statistics = {
            shadow_clone!(account_rules_counters);

            #[allow(unreachable_code)]
            async move {
                loop {
                    if let Some(recs) = account_rules_counters.flush() {
                        let report = WsFromGwMessage::Statistics {
                            report: StatisticsReport::Rules {
                                records: recs
                                    .into_iter()
                                    .map(|r| RulesRecord {
                                        account_name: r.account_name,
                                        rules_processed: r.rules_processed,
                                        from: r.from,
                                        to: r.to,
                                    })
                                    .collect(),
                            },
                        };

                        statistics_tx.send(report).await?;

                        delay_for(Duration::from_secs(60)).await;
                    }
                }

                Ok::<_, anyhow::Error>(())
            }
        };

        let api_client = Client::new(cache_ttl, health_state_change_tx, webapp_base_url);

        let resolver = TokioAsyncResolver::new(
            ResolverConfig::default(),
            ResolverOpts::default(),
            Handle::current(),
        )
        .await
        .unwrap();

        let tls_gw_common = Arc::new(RwLock::new(None));

        let consumer = AssistantClient::new(
            assistant_base_url.clone(),
            &individual_hostname,
            &gw_location,
            &api_client.mappings(),
            &client_tunnels,
            tls_gw_common.clone(),
            statistics_rx,
            &api_client,
            resolver.clone(),
            &app_stop_handle,
        )
        .await
        .expect("notification listener error");

        tokio::spawn(async move {
            consumer.spawn().await;

            error!("assistant consumer unexpectedly closed");
            app_stop_handle.stop(StopReason::NotificationChannelClosed);
        });

        let google_oauth2_client = GoogleOauth2Client::new(
            Duration::from_secs(60),
            google_oauth2_client_id,
            google_oauth2_client_secret,
            public_base_url.clone(),
            assistant_base_url.clone(),
        );

        let github_oauth2_client = GithubOauth2Client::new(
            Duration::from_secs(60),
            github_oauth2_client_id,
            github_oauth2_client_secret,
            public_base_url.clone(),
            assistant_base_url.clone(),
        );

        // std::thread::spawn(move || loop {
        //     std::thread::sleep(Duration::from_secs(10));
        //     let deadlocks = parking_lot::deadlock::check_deadlock();
        //     if deadlocks.is_empty() {
        //         continue;
        //     }
        //
        //     println!("{} deadlocks detected", deadlocks.len());
        //     for (i, threads) in deadlocks.iter().enumerate() {
        //         println!("Deadlock #{}", i);
        //         for t in threads {
        //             println!("Thread Id {:#?}", t.thread_id());
        //             println!("{:#?}", t.backtrace());
        //         }
        //     }
        // });

        let server = http_serve::handle::server(
            client_tunnels,
            listen_http_addr,
            listen_https_addr,
            external_https_port,
            api_client,
            app_stop_wait,
            tls_gw_common,
            public_base_url,
            individual_hostname,
            webroot,
            google_oauth2_client,
            github_oauth2_client,
            assistant_base_url,
            &account_rules_counters,
            dbip,
            resolver,
        );

        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::spawn(dump_traffic_statistics) => {},
                _ = tokio::spawn(dump_rules_statistics) => {},
                _ = tokio::spawn(dump_health_changes) => {},
            }
        });

        server.await;

        Ok::<(), anyhow::Error>(())
    })
    .expect("error running server");

    rt.shutdown_timeout(Duration::from_secs(5));

    info!("Web server stopped");
}
