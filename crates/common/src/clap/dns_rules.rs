use anyhow::anyhow;
use clap::{Arg, ArgMatches};
use std::path::PathBuf;

pub fn add_args<'a>(app: clap::App<'a, 'a>) -> clap::App<'a, 'a> {
    app.arg(
        Arg::with_name("dns_rules_path")
            .long("dns-rules-path")
            .value_name("PATH")
            .required(true)
            .help("Set DNS rules path")
            .takes_value(true),
    )
}

pub fn handle<'a>(matches: &ArgMatches<'a>) -> Result<PathBuf, anyhow::Error> {
    Ok(matches
        .value_of("dns_rules_path")
        .ok_or_else(|| anyhow!("dns_rules_path not provided"))?
        .parse()?)
}
