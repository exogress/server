use clap::{Arg, ArgMatches};

pub fn add_args<'a>(app: clap::App<'a, 'a>) -> clap::App<'a, 'a> {
    app.arg(
        Arg::with_name("kafka_brokers")
            .long("kafka-brokers")
            .help("Broker list in kafka format")
            .required(true)
            .takes_value(true),
    )
}

pub fn extract_matches(matches: &ArgMatches) -> String {
    matches
        .value_of("kafka_brokers")
        .expect("--kafka-brokers not set")
        .to_string()
}
