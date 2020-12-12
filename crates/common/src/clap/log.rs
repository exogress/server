use anyhow::anyhow;
use clap::{Arg, ArgMatches};
use std::future::Future;
use std::io::{Cursor, Seek, SeekFrom};
use std::net::IpAddr;
use std::sync::Arc;
use tokio_rustls::rustls::internal::pemfile::{certs, pkcs8_private_keys};
use tracing::Level;
use tracing_gelf::Logger;
use trust_dns_resolver::TokioAsyncResolver;

pub fn add_args<'a>(app: clap::App<'a, 'a>) -> clap::App<'a, 'a> {
    app.arg(
        Arg::with_name("gelf_host")
            .long("gelf-host")
            .value_name("HOSTNAME")
            .help("Log to GELF server")
            .takes_value(true)
            .required(false),
    )
    .arg(
        Arg::with_name("gelf_port")
            .long("gelf-port")
            .value_name("PORT")
            .help("GELF server port")
            .default_value("12201")
            .takes_value(true)
            .required(false),
    )
    .arg(
        Arg::with_name("gelf_is_tls")
            .long("gelf-tls")
            .help("Use gelf through TLS")
            .takes_value(false)
            .required(false)
            .requires("gelf_host"),
    )
    .arg(
        Arg::with_name("log_level")
            .long("log-level")
            .env("LOG_LEVEL")
            .value_name("LOG_LEVEL")
            .help("Log level")
            .default_value("INFO")
            .case_insensitive(true)
            .possible_values(&["trace", "debug", "info", "warn", "error"])
            .required(true)
            .takes_value(true),
    )
}

pub async fn handle<'a>(
    matches: ArgMatches<'a>,
    service_name: &'static str,
    resolver: TokioAsyncResolver,
    maybe_int_client_cert: Option<Vec<u8>>,
) -> Result<impl Future<Output = ()>, anyhow::Error> {
    let log_level = match &matches
        .value_of("log_level")
        .expect("Please provide --log-level")
        .to_lowercase()[..]
    {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => panic!("Bad log level"),
    };

    let subscriber = tracing_subscriber::fmt().with_max_level(log_level).finish();

    let bg_task = if let Some(gelf_host) = matches.value_of("gelf_host") {
        println!("using GELF host: {}", gelf_host);
        let gelf_host = gelf_host.to_string();

        let gelf_port = matches
            .value_of("gelf_port")
            .ok_or_else(|| anyhow!("GELF port not set"))?
            .parse::<u16>()?;

        let address = match gelf_host.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => resolver
                .lookup_ip(gelf_host.clone())
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("could not resolve gelf addr"))?,
        };

        if !matches.is_present("gelf_is_tls") {
            Logger::builder()
                .additional_field("service", service_name)
                .init_tcp_with_subscriber((address, gelf_port).into(), subscriber)
                .map_err(|e| anyhow!("TCP subscriber init error: {:?}", e))?
        } else {
            let mut config = tokio_rustls::rustls::ClientConfig::new();
            config.root_store =
                rustls_native_certs::load_native_certs().expect("native certs error");
            if let Some(cert) = maybe_int_client_cert {
                println!("Use int access certificate for GELF logging");
                let mut c = Cursor::new(&cert);
                let pkey = pkcs8_private_keys(&mut c)
                    .expect("bad int access certificate")
                    .pop()
                    .unwrap();
                c.seek(SeekFrom::Start(0)).unwrap();
                let certs = certs(&mut c).expect("bad int access certificate");
                config
                    .set_single_client_cert(certs, pkey)
                    .expect("set GELF client cert error");
            }

            Logger::builder()
                .additional_field("service", service_name)
                .init_tls_with_subscriber(
                    (address, gelf_port).into(),
                    gelf_host.clone(),
                    Arc::new(config),
                    subscriber,
                )
                .map_err(|e| anyhow!("TLS subscriber init error{:?}", e))?
        }
    } else {
        tracing::subscriber::set_global_default(subscriber)
            .map_err(|_err| anyhow!("Unable to set global default subscriber"))?;
        Box::pin(futures::future::pending())
    };

    Ok(bg_task)
}
