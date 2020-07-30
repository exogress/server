use clap::{Arg, ArgMatches};
use sentry::integrations::panic::PanicIntegration;
use sentry::{ClientInitGuard, ScopeGuard};

pub fn add_args(app: clap::App) -> clap::App {
    app.arg(
        Arg::with_name("sentry_dsn")
            .long("sentry-dsn")
            .value_name("DSN")
            .about("sentry dsn")
            .required(false)
            .takes_value(true),
    )
}

pub fn extract_matches(matches: &ArgMatches) -> Option<(ScopeGuard, ClientInitGuard)> {
    let maybe_sentry_dsn = matches.value_of("sentry_dsn");

    if let Some(sentry_dsn) = maybe_sentry_dsn {
        let panic_integration = PanicIntegration::default();

        let options = sentry::ClientOptions {
            release: sentry::release_name!(),
            ..Default::default()
        }
        .add_integration(panic_integration);

        println!("Enabling sentry...");
        let sentry = sentry::init((&sentry_dsn[..], options));

        let sentry_guard = sentry::Hub::current().push_scope();

        Some((sentry_guard, sentry))
    } else {
        None
    }
}
