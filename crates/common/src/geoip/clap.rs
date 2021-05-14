use crate::geoip::{model::LocationAndIsp, GeoipReader};
use clap::{Arg, ArgMatches};
use std::{path::PathBuf, sync::Arc};
use tracing::info;

pub fn add_args<'a>(app: clap::App<'a, 'a>) -> clap::App<'a, 'a> {
    app.arg(
        Arg::with_name("dbip_path")
            .long("dbip-path")
            .value_name("PATH")
            .env("DBIP_PATH")
            .help("Path to MMDB database")
            .takes_value(true),
    )
}

pub fn extract_matches(matches: &ArgMatches) -> Option<GeoipReader> {
    let db_path = matches
        .value_of("dbip_path")
        .map(|path| PathBuf::from(path.to_string()));

    db_path.map(|path| {
        info!("Opening maxminddb...");
        let dbip = Arc::new(maxminddb::Reader::open_mmap(&path).expect("Failed to open dbip"));
        info!("maxminddb successfully opened");

        let loc = dbip
            .lookup::<LocationAndIsp>("123.33.22.123".parse().unwrap())
            .unwrap();

        info!(
            "{}/{}",
            loc.country
                .clone()
                .and_then(|c| c.iso_code)
                .unwrap_or_default(),
            loc.city
                .as_ref()
                .and_then(|c| c.names.as_ref().and_then(|n| n.en.clone()))
                .unwrap_or_default()
        );

        dbip
    })
}
