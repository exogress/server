use clap::{Arg, ArgMatches};
use lazy_static::lazy_static;
use slog::{Drain, Duplicate, LevelFilter};
use sloggers::terminal::TerminalLoggerBuilder;
use sloggers::types::Severity;
use sloggers::{Build, LoggerBuilder};

lazy_static! {
    static ref DEFAULT_HOSTNAME: String =
        hostname::get_hostname().unwrap_or_else(|| "unknown".into());
}

pub fn add_args(app: clap::App) -> clap::App {
    app.arg(
        Arg::with_name("gelf_own_hostname")
            .long("gelf-individual-hostname")
            .value_name("HOSTNAME")
            .about("Use provided hostname as a gelf hostname")
            .takes_value(true)
            .required(false)
            .default_value(&DEFAULT_HOSTNAME),
    )
    .arg(
        Arg::with_name("gelf_server")
            .long("gelf-server")
            .value_name("SOCKET_ADDR")
            .about("Log to GELF server")
            .takes_value(true)
            .required(false),
    )
    .arg(
        Arg::with_name("log_level")
            .long("log-level")
            .env("LOG_LEVEL")
            .value_name("LOG_LEVEL")
            .about("Log level")
            .default_value("INFO")
            .case_insensitive(true)
            .possible_values(&["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"])
            .required(true)
            .takes_value(true),
    )
}

pub fn extract_matches<D: Drain<Ok = (), Err = slog::Never>>(
    matches: &ArgMatches,
    service_name: &'static str,
    duplicate_drain: Option<D>,
) -> slog::Logger
where
    <D as slog::Drain>::Err: std::fmt::Debug,
    D: Send + Sync + std::panic::UnwindSafe + std::panic::RefUnwindSafe + 'static,
{
    let gelf_own_hostname = matches.value_of("gelf_own_hostname").unwrap().to_string();
    let log_level = match &matches
        .value_of("log_level")
        .expect("Please provide --log-level")
        .to_lowercase()[..]
    {
        "trace" => Severity::Trace,
        "debug" => Severity::Debug,
        "info" => Severity::Info,
        "warn" => Severity::Warning,
        "error" => Severity::Error,
        "critical" => Severity::Critical,
        _ => panic!("Bad log level"),
    };

    if let Some(gelf_server) = matches.value_of("gelf_server") {
        println!("Logging to gelf server {}", gelf_server);
        let gelf_drain = slog_gelf::Gelf::new(&gelf_own_hostname, gelf_server)
            .unwrap()
            .fuse();
        let async_drain = slog_async::Async::new(gelf_drain).build().fuse();
        let level_filter = LevelFilter::new(async_drain, log_level.as_level()).fuse();

        match duplicate_drain {
            Some(drain) => {
                let d = Duplicate::new(level_filter, drain.fuse()).fuse();
                slog::Logger::root(d, o!("service" => service_name))
            }
            None => slog::Logger::root(level_filter, o!("service" => service_name)),
        }
    } else {
        let mut terminal_logger_builder = TerminalLoggerBuilder::new();
        terminal_logger_builder.level(log_level);

        let terminal = LoggerBuilder::Terminal(terminal_logger_builder)
            .build()
            .unwrap()
            .fuse();

        match duplicate_drain {
            Some(drain) => {
                let d = Duplicate::new(terminal, drain.fuse()).fuse();
                slog::Logger::root(d, o!())
            }
            None => slog::Logger::root(terminal, o!()),
        }
    }
}
