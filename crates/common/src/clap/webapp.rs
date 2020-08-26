use clap::{Arg, ArgMatches};
use url::Url;

pub fn add_args<'a>(app: clap::App<'a, 'a>) -> clap::App<'a, 'a> {
    app.arg(
        Arg::with_name("webapp_base_url")
            .long("webapp-base-url")
            .value_name("URL")
            .required(true)
            .help("Set Webapp Base URL")
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
