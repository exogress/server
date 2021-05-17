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
extern crate anyhow;

use byte_unit::Byte;
use clap::{crate_version, App, Arg};
use rules_counter::AccountCounters;
use smol_str::SmolStr;
use std::{fs, io, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use stop_handle::stop_handle;
use url::Url;

use crate::clients::{tunnels_acceptor, ClientTunnels};

use crate::{
    clients::traffic_counter::OneOfTrafficStatistics,
    http_serve::{
        acme::acme_server,
        auth::{github::GithubOauth2Client, google::GoogleOauth2Client},
        cache::Cache,
    },
    notification_listener::AssistantClient,
    resources::ResourcesManager,
    stop_reasons::StopReason,
    webapp::Client,
};
use core::mem;
use exogress_common::{common_utils::termination::stop_signal_listener, entities::Ulid};
use exogress_server_common::{
    assistant::{RulesRecord, StatisticsReport, TrafficRecord, WsFromGwMessage},
    clap::int_api::IntApiBaseUrls,
};
use futures::{channel::oneshot, StreamExt};
use parking_lot::RwLock;
use std::sync::atomic::AtomicBool;
use tempfile::NamedTempFile;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    runtime::Builder,
    sync::mpsc::error::TrySendError,
    time::sleep,
};
use tokio_stream::wrappers::ReceiverStream;
use trust_dns_resolver::{TokioAsyncResolver, TokioHandle};

pub(crate) mod clients;
mod http_serve;
mod int_server;
mod mime_helpers;
mod notification_listener;
mod public_hyper_client;
mod registry;
mod resources;
mod rules_counter;
mod statistics;
mod stop_reasons;
mod transformer;
mod urls;
mod webapp;

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

fn main() {
    let spawn_args = App::new("spawn")
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
            Arg::with_name("listen_http_acme_challenge")
                .long("listen-http-acme-challenge")
                .value_name("SOCKET_ADDR")
                .default_value("0.0.0.0:80")
                .required(true)
                .help("Set HTTP listen address for ACME challenge")
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
            Arg::with_name("assistants_connections")
                .long("assistants-connections")
                .value_name("NUMERIC")
                .help("Number of connections to assistant servers")
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
            Arg::with_name("gcs_credentials_file")
                .long("gcs-credentials-file")
                .value_name("STRING")
                .required(true)
                .help("The path to GCS credentials file")
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
            Arg::with_name("disk_cache_max_size")
                .long("disk-cache-max-size")
                .value_name("BYTES")
                .required(true)
                .default_value("1 GB") // 10 minutes
                .help("Maximum size of all cached files")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("cache_dir")
                .long("cache-dir")
                .value_name("PATH")
                .required(true)
                .help("Set cache dir")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("statistics_local_storage_dir")
                .long("statistics-local-storage-dir")
                .value_name("PATH")
                .required(true)
                .help(
                    "Set directory to store files with logs which were unable to send in real-time",
                )
                .takes_value(true),
        );

    let init_individual_certs_args = App::new("init-individual-certs")
        .arg(
            Arg::with_name("listen_http_acme_challenge")
                .long("listen-http-acme-challenge")
                .value_name("SOCKET_ADDR")
                .default_value("0.0.0.0:80")
                .required(true)
                .help("Set HTTP listen address for ACME challenge")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("webroot")
                .long("webroot")
                .value_name("PATH")
                .help("Set webroot path for certbot interaction")
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
            true,
            true,
        ),
    );

    let args = App::new("Exogress Gateway")
        .version(crate_version!())
        .author("Exogress Team <team@exogress.com>")
        .about("Load-balancing cloud gateway")
        .subcommand(spawn_args)
        .subcommand(init_individual_certs_args);

    let mut args = exogress_common::common_utils::clap::autocompletion::add_args(args);

    let matches = args.clone().get_matches().clone();
    exogress_common::common_utils::clap::autocompletion::handle_autocompletion(
        &mut args,
        &matches,
        "exogress-gateway",
    );

    if let Some(matches) = matches.subcommand_matches("init-individual-certs") {
        let listen_http_acme_challenge_addr = matches
            .value_of("listen_http_acme_challenge")
            .map(|r| {
                r.parse::<SocketAddr>()
                    .expect("Failed to parse listen HTTP address (ip:port) for ACME challenge")
            })
            .unwrap();

        let webroot: PathBuf = fs::canonicalize(
            matches
                .value_of("webroot")
                .expect("no webroot defined")
                .to_string(),
        )
        .expect("error in webroot");

        info!("Use certbot webroot at {}", webroot.display());

        let rt = Builder::new_multi_thread().enable_all().build().unwrap();

        rt.block_on(acme_server(webroot, listen_http_acme_challenge_addr))
            .expect("acme server error");

        // exit
        return;
    }

    let matches = matches
        .subcommand_matches("spawn")
        .expect("Unknown subcommand");

    let IntApiBaseUrls {
        assistant_url: assistant_base_url,
        signaler_url: signaler_base_url,
        webapp_url: webapp_base_url,
        transformer_url: transformer_base_url,
        int_client_cert,
    } = exogress_server_common::clap::int_api::extract_matches(&matches, true, true, true, true);
    let _maybe_sentry = exogress_server_common::clap::sentry::extract_matches(&matches);
    let num_threads = exogress_common::common_utils::clap::threads::extract_matches(&matches);

    let gcs_credentials_file = matches
        .value_of("gcs_credentials_file")
        .expect("no --gcs-credentials-file provided")
        .to_string();

    let assistant_base_url = assistant_base_url.expect("no assistant_base_url");
    let signaler_base_url = signaler_base_url.expect("no signaler_base_url");
    let webapp_base_url = webapp_base_url.expect("no webapp_base_url");
    let transformer_base_url = transformer_base_url.expect("no transformer_base_url");

    let cache_dir: PathBuf = matches
        .value_of("cache_dir")
        .expect("no cache dir provided")
        .parse()
        .unwrap();

    let statistics_local_storage_dir: PathBuf = matches
        .value_of("statistics_local_storage_dir")
        .expect("no logs local storage supplied")
        .parse()
        .unwrap();

    {
        let mut chunks_dir = statistics_local_storage_dir.clone();
        chunks_dir.push("chunks");
        std::fs::create_dir_all(chunks_dir).expect("failed to create dir for statistics chunks");

        let mut tmp_dir = statistics_local_storage_dir.clone();
        tmp_dir.push("tmp");
        std::fs::create_dir_all(tmp_dir).expect("failed to create dir for tmp chunks");
    }

    let rt = Builder::new_multi_thread()
        .enable_all()
        .worker_threads(num_threads)
        .thread_name("gateway-reactor")
        .build()
        .unwrap();

    let resolver = TokioAsyncResolver::from_system_conf(TokioHandle).unwrap();

    let logger_bg = rt
        .block_on({
            shadow_clone!(int_client_cert);

            exogress_server_common::clap::log::handle(
                matches.clone(),
                "gw",
                resolver.clone(),
                int_client_cert,
            )
        })
        .expect("error initializing logger");

    rt.spawn(logger_bg);

    let (app_stop_handle, app_stop_wait) = stop_handle();

    let public_base_url: Url = matches
        .value_of("public_base_url")
        .unwrap()
        .parse()
        .expect("bad URL format");

    let google_oauth2_client_id: SmolStr =
        matches.value_of("google_oauth2_client_id").unwrap().into();
    let google_oauth2_client_secret: SmolStr = matches
        .value_of("google_oauth2_client_secret")
        .unwrap()
        .into();

    let github_oauth2_client_id: SmolStr =
        matches.value_of("github_oauth2_client_id").unwrap().into();
    let github_oauth2_client_secret: SmolStr = matches
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

    let disk_cache_max_size: Byte = matches
        .value_of("disk_cache_max_size")
        .unwrap()
        .parse()
        .expect("bad bytes value value");

    crate::statistics::EDGE_CACHE_MAX_SIZE.set(disk_cache_max_size.get_bytes() as f64);

    let individual_tls_cert_path = matches.value_of("individual_tls_cert_path").unwrap();
    let individual_tls_key_path = matches.value_of("individual_tls_key_path").unwrap();

    info!("Use Transformer url at {}", transformer_base_url);
    info!("Use Webapp url at {}", webapp_base_url);

    let webroot: PathBuf = fs::canonicalize(
        matches
            .value_of("webroot")
            .expect("no webroot defined")
            .to_string(),
    )
    .expect("error in webroot");
    info!("Use certbot webroot at {}", webroot.display());

    let listen_http_acme_challenge_addr = matches
        .value_of("listen_http_acme_challenge")
        .map(|r| {
            r.parse::<SocketAddr>()
                .expect("Failed to parse listen HTTP address (ip:port) for ACME challenge")
        })
        .unwrap();

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
        let dbip = exogress_server_common::geoip::clap::extract_matches(&matches);

        let gw_location: SmolStr = matches
            .value_of("location")
            .expect("Please provide --location")
            .to_string()
            .into();

        let cache = Cache::new(cache_dir, disk_cache_max_size, gw_location.clone())
            .await
            .expect("Failed to initialize cache");

        tokio::spawn(stop_signal_listener(app_stop_handle.clone()));

        let spawned_at = chrono::Utc::now();

        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(1)).await;
                let passed_secs = (chrono::Utc::now() - spawned_at).num_seconds();

                crate::statistics::UPTIME_SECS.set(passed_secs as f64);
            }
        });

        info!("Listening int HTTPS on https://{}", listen_int_https_addr);
        tokio::spawn(int_server::spawn(
            listen_int_https_addr,
            individual_tls_cert_path.into(),
            individual_tls_key_path.into(),
        ));

        let external_https_port = matches
            .value_of("external_https_port")
            .map(|r| r.parse().expect("Could not parse external-https-port"))
            .unwrap_or_else(|| listen_https_addr.port());
        let assistants_connections: u8 = matches
            .value_of("assistants_connections")
            .map(|r| r.parse().expect("Could not parse assistants-connections"))
            .expect("assistants_connections not set");

        info!("Listening ACME HTTP on {}", listen_http_acme_challenge_addr);
        info!("Listening HTTP on {}", listen_http_addr);
        info!(
            "Listening HTTPS on {}, external_port is {}",
            listen_https_addr, external_https_port
        );

        let client_tunnels = ClientTunnels::new(signaler_base_url, int_client_cert.clone());

        // log messages are "safe" to make unbounded, because tokio mpsc is implemented as a linked list,
        // and all log messages already exist in the mem. When they get send no more memory will be allocated
        // and there is no risk of not "shrinking" the ubounded buffer, after they get sent.
        let (log_messages_tx, log_messages_rx) = tokio::sync::mpsc::unbounded_channel();
        let (tunnel_counters_tx, tunnel_counters_rx) = tokio::sync::mpsc::channel(256);
        let (public_counters_tx, public_counters_rx) = tokio::sync::mpsc::channel(256);
        let (https_counters_tx, https_counters_rx) = tokio::sync::mpsc::channel(256);

        let google_oauth2_client = GoogleOauth2Client::new(
            Duration::from_secs(60),
            google_oauth2_client_id.into(),
            google_oauth2_client_secret.into(),
            public_base_url.clone(),
            assistant_base_url.clone(),
            int_client_cert.clone(),
        );

        let github_oauth2_client = GithubOauth2Client::new(
            Duration::from_secs(60),
            github_oauth2_client_id.into(),
            github_oauth2_client_secret.into(),
            public_base_url.clone(),
            assistant_base_url.clone(),
            int_client_cert.clone(),
        );

        let account_rules_counters = AccountCounters::new();

        let api_client = Client::new(
            cache_ttl,
            account_rules_counters.clone(),
            tunnel_counters_tx.clone(),
            public_counters_tx.clone(),
            webapp_base_url,
            google_oauth2_client.clone(),
            github_oauth2_client.clone(),
            assistant_base_url.clone(),
            transformer_base_url.clone(),
            &public_base_url,
            gw_location.clone(),
            gcs_credentials_file,
            log_messages_tx,
            int_client_cert.clone(),
            cache,
            dbip.clone(),
            resolver.clone(),
        );

        let high_resource_consumption = Arc::new(AtomicBool::new(false));

        tokio::spawn(
            ResourcesManager::builder()
                .stop_trigger(high_resource_consumption.clone())
                .build()
                .run(),
        );

        let acceptor = tunnels_acceptor(
            listen_tunnel_addr,
            individual_tls_cert_path.into(),
            individual_tls_key_path.into(),
            client_tunnels.clone(),
            api_client.clone(),
            high_resource_consumption.clone(),
            tunnel_counters_tx,
        );

        tokio::spawn(async {
            let res = acceptor.await;
            warn!("tunnels acceptor stopped: {:?}", res);
        });

        let (gw_to_assistant_messages_tx, gw_to_assistant_messages_rx) =
            tokio::sync::mpsc::channel::<WsFromGwMessage>(32);

        let individual_hostname = matches
            .value_of("individual_hostname")
            .expect("Please provide --individual-hostname")
            .to_string();

        let dump_log_messages = {
            shadow_clone!(
                mut gw_to_assistant_messages_tx,
                statistics_local_storage_dir
            );

            const CHUNK: usize = 16536;
            let mut ready_chunks =
                tokio_stream::wrappers::UnboundedReceiverStream::new(log_messages_rx)
                    .ready_chunks(CHUNK);

            let saving_semaphore = Arc::new(tokio::sync::Semaphore::new(16));

            async move {
                while let Some(ready_chunks) = ready_chunks.next().await {
                    let batch = WsFromGwMessage::Logs {
                        report: ready_chunks,
                    };

                    if let Err(TrySendError::Full(batch)) =
                        gw_to_assistant_messages_tx.try_send(batch)
                    {
                        let permit = saving_semaphore.clone().acquire_owned().await;
                        tokio::spawn({
                            shadow_clone!(statistics_local_storage_dir);

                            async move {
                                if let Err(e) = save_statistics_message_for_future_sending(
                                    batch,
                                    &statistics_local_storage_dir,
                                )
                                .await
                                {
                                    error!("Failed to save logs batch for future sending: {}", e);
                                };

                                mem::drop(permit);
                            }
                        });
                    }
                }

                Ok::<_, anyhow::Error>(())
            }
        };

        let dump_traffic_statistics = {
            shadow_clone!(
                mut gw_to_assistant_messages_tx,
                statistics_local_storage_dir
            );

            const CHUNK: usize = 4096;
            let mut ready_chunks = futures::stream::select(
                futures::stream::select(
                    ReceiverStream::new(tunnel_counters_rx).map(OneOfTrafficStatistics::Tunnel),
                    ReceiverStream::new(https_counters_rx).map(OneOfTrafficStatistics::Https),
                ),
                ReceiverStream::new(public_counters_rx).map(OneOfTrafficStatistics::Public),
            )
            .ready_chunks(CHUNK);
            async move {
                while let Some(ready_chunks) = ready_chunks.next().await {
                    let batch = WsFromGwMessage::Statistics {
                        report: StatisticsReport::Traffic {
                            records: ready_chunks
                                .into_iter()
                                .map(|statistics| TrafficRecord {
                                    account_unique_id: *statistics.account_unique_id(),
                                    project_unique_id: *statistics.project_unique_id(),

                                    tunnel_bytes_gw_tx: if statistics.is_tunnel() {
                                        *statistics.bytes_written()
                                    } else {
                                        0
                                    },
                                    tunnel_bytes_gw_rx: if statistics.is_tunnel() {
                                        *statistics.bytes_read()
                                    } else {
                                        0
                                    },

                                    public_bytes_gw_tx: if statistics.is_public() {
                                        *statistics.bytes_written()
                                    } else {
                                        0
                                    },
                                    public_bytes_gw_rx: if statistics.is_public() {
                                        *statistics.bytes_read()
                                    } else {
                                        0
                                    },

                                    https_bytes_gw_tx: if statistics.is_https() {
                                        *statistics.bytes_written()
                                    } else {
                                        0
                                    },
                                    https_bytes_gw_rx: if statistics.is_https() {
                                        *statistics.bytes_read()
                                    } else {
                                        0
                                    },

                                    flushed_at: *statistics.to(),
                                })
                                .collect(),
                        },
                    };

                    if let Err(TrySendError::Full(batch)) =
                        gw_to_assistant_messages_tx.try_send(batch)
                    {
                        if let Err(e) = save_statistics_message_for_future_sending(
                            batch,
                            &statistics_local_storage_dir,
                        )
                        .await
                        {
                            error!("Failed to save statistics batch for future sending: {}", e);
                        }
                    }
                }

                Ok::<_, anyhow::Error>(())
            }
        };

        let send_outstanding_statistics_reports = {
            shadow_clone!(
                mut gw_to_assistant_messages_tx,
                statistics_local_storage_dir
            );

            #[allow(unreachable_code)]
            async move {
                let mut chunks_dir = statistics_local_storage_dir.clone();
                chunks_dir.push("chunks");

                loop {
                    let mut dir = tokio::fs::read_dir(&chunks_dir).await?;

                    if let Some(dir_entry) = dir.next_entry().await? {
                        let permit = gw_to_assistant_messages_tx.reserve().await?;
                        let res = async {
                            let mut file = tokio::fs::File::open(dir_entry.path()).await?;
                            tokio::fs::remove_file(dir_entry.path()).await?;
                            let mut content = Vec::new();
                            file.read_to_end(&mut content).await?;
                            let msg = serde_json::from_slice(&content)?;
                            permit.send(msg);

                            crate::statistics::OUTSTANDING_REPORTS_SENT.inc();

                            Ok::<_, anyhow::Error>(())
                        }
                        .await;

                        if let Err(e) = res {
                            error!("error sending outstanding data: {}", e);
                            // } else {
                            // info!("sent outstanding chunk {:?}", dir_entry.path().file_name());
                        };
                    } else {
                        sleep(Duration::from_secs(1)).await;
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
                                        account_unique_id: r.account_unique_id,
                                        project_unique_id: r.project_unique_id,
                                        rules_processed: r.rules_processed,
                                        requests_processed: r.requests_processed,
                                        flushed_at: r.to,
                                    })
                                    .collect(),
                            },
                        };

                        gw_to_assistant_messages_tx.send(report).await?;
                        sleep(Duration::from_secs(60)).await;
                    } else {
                        sleep(Duration::from_secs(10)).await;
                    }
                }

                Ok::<_, anyhow::Error>(())
            }
        };

        let tls_gw_common = Arc::new(RwLock::new(None));

        let (first_connection_established_tx, first_connection_established_rx) = oneshot::channel();

        let consumer = AssistantClient::new(
            assistant_base_url.clone(),
            assistants_connections,
            &individual_hostname,
            gw_location.clone(),
            &api_client.mappings(),
            &client_tunnels,
            tls_gw_common.clone(),
            gw_to_assistant_messages_rx,
            int_client_cert.clone(),
            &api_client,
            first_connection_established_tx,
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

        let acme_server = acme_server(webroot, listen_http_acme_challenge_addr);
        tokio::spawn(async move {
            let res = acme_server.await;
            error!("ACME server stopped with result: {:?}", res);
            sentry::capture_message(
                format!("ACME server stopped with result: {:?}", res).as_str(),
                sentry::Level::Fatal,
            );
        });

        info!("Waiting for the first assistant connection...");
        first_connection_established_rx
            .await
            .expect("Error waiting for the first assistant connection");
        info!("Assistant connection established. Starting the server");

        let server = http_serve::handle::server(
            client_tunnels,
            listen_http_addr,
            listen_https_addr,
            external_https_port,
            api_client,
            high_resource_consumption.clone(),
            app_stop_wait,
            tls_gw_common,
            public_base_url,
            gw_location.clone(),
            individual_hostname.into(),
            google_oauth2_client,
            github_oauth2_client,
            assistant_base_url,
            int_client_cert,
            https_counters_tx,
        );

        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::spawn(dump_log_messages) => {},
                _ = tokio::spawn(dump_traffic_statistics) => {},
                _ = tokio::spawn(dump_rules_statistics) => {},
                _ = tokio::spawn(send_outstanding_statistics_reports) => {},
            }
        });

        server.await;

        Ok::<(), anyhow::Error>(())
    })
    .expect("error running server");
    rt.shutdown_timeout(Duration::from_secs(5));

    info!("Web server stopped");
}

async fn save_statistics_message_for_future_sending(
    batch: WsFromGwMessage,
    dir: &PathBuf,
) -> anyhow::Result<()> {
    crate::statistics::REPORTS_SAVED_TO_DISK.inc();

    let mut tmp_path = dir.clone();
    tmp_path.push("tmp");

    let tempfile = tokio::task::spawn_blocking(|| NamedTempFile::new_in(tmp_path)).await??;
    let (reopened, tempfile) = tokio::task::spawn_blocking(|| {
        let reopened = tempfile.reopen()?;
        Ok::<_, io::Error>((reopened, tempfile))
    })
    .await??;
    let mut file = tokio::fs::File::from_std(reopened);
    let serialized = serde_json::to_vec(&batch).unwrap();
    file.write_all(&serialized).await?;
    let chunk_id = Ulid::new();

    let mut out_path = dir.clone();
    out_path.push("chunks");
    out_path.push(chunk_id.to_string());

    tokio::task::spawn_blocking(|| tempfile.persist(out_path)).await??;

    Ok(())
}
