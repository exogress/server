use clap::{Arg, ArgMatches};
use sentry::integrations::panic::PanicIntegration;
use sentry::{ClientInitGuard, ScopeGuard};
use url::Url;

pub fn add_args(app: clap::App) -> clap::App {
    app.arg(
        Arg::with_name("webapp_base_url")
            .long("webapp-base-url")
            .value_name("URL")
            .required(true)
            .about("Set Webapp Base URL")
            .takes_value(true),
    )
}

pub fn extract_matches(matches: &ArgMatches) -> Url {
    matches
        .value_of("webapp_base_url")
        .expect("webapp base URL should be set")
        .parse()
        .expect("bad webapp base url")
}
