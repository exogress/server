use clap::{Arg, ArgMatches};
use url::Url;

pub fn add_args<'a>(
    app: clap::App<'a, 'a>,
    use_webapp: bool,
    use_assistant: bool,
    use_signaler: bool,
) -> clap::App<'a, 'a> {
    let mut v = vec![];
    let mut app = app.arg(
        Arg::with_name("int_client_cert")
            .long("int-client-cert")
            .value_name("FILE")
            .required(false)
            .help("Internal API client certificate")
            .takes_value(true),
    );
    if use_webapp {
        const NAME: &str = "webapp_base_url";
        v.push(NAME);
        app = app.arg(
            Arg::with_name(NAME)
                .long("webapp-base-url")
                .value_name("URL")
                .required(false)
                .help("Overwrite Webapp Base URL")
                .takes_value(true),
        )
    }
    if use_assistant {
        const NAME: &str = "assistant_base_url";
        v.push(NAME);
        app = app.arg(
            Arg::with_name(NAME)
                .long("assistant-base-url")
                .value_name("URL")
                .required(false)
                .help("Overwrite assistant Base URL")
                .takes_value(true),
        );
    }
    if use_signaler {
        const NAME: &str = "signaler_base_url";
        v.push(NAME);
        app = app.arg(
            Arg::with_name(NAME)
                .long("signaler-base-url")
                .value_name("URL")
                .required(false)
                .help("Overwrite signaler Base URL")
                .takes_value(true),
        );
    }

    if use_webapp || use_signaler || use_assistant {
        app = app.arg(
            Arg::with_name("int_base_url")
                .long("int-base-url")
                .value_name("URL")
                .required_unless_all(v.as_ref())
                .help("Set Int API Base URL")
                .takes_value(true),
        )
    }

    app
}

pub struct IntApiBaseUrls {
    pub assistant_url: Option<Url>,
    pub signaler_url: Option<Url>,
    pub webapp_url: Option<Url>,
    pub int_client_cert: Option<Vec<u8>>,
}

pub fn extract_matches(
    matches: &ArgMatches,
    use_webapp: bool,
    use_assistant: bool,
    use_signaler: bool,
) -> IntApiBaseUrls {
    let base_url = matches.value_of("int_base_url");

    let webapp_url = if use_webapp {
        Some(
            matches
                .value_of("webapp_base_url")
                .map(|v| v.parse().expect("bad Webapp API base url"))
                .unwrap_or_else(|| {
                    base_url
                        .expect("Int API base URL should be set")
                        .parse()
                        .expect("bad int api base url")
                }),
        )
    } else {
        None
    };

    let assistant_url = if use_assistant {
        Some(
            matches
                .value_of("assistant_base_url")
                .map(|v| v.parse().expect("bad Assistant API base url"))
                .unwrap_or_else(|| {
                    base_url
                        .expect("Int API base URL should be set")
                        .parse()
                        .expect("bad int api base url")
                }),
        )
    } else {
        None
    };

    let signaler_url = if use_signaler {
        Some(
            matches
                .value_of("signaler_base_url")
                .map(|v| v.parse().expect("bad Signaler API base url"))
                .unwrap_or_else(|| {
                    base_url
                        .expect("Int API base URL should be set")
                        .parse()
                        .expect("bad int api base url")
                }),
        )
    } else {
        None
    };

    let int_client_cert = matches
        .value_of("int_client_cert")
        .map(|path| std::fs::read(path).expect("cannot read int api client cert"));

    IntApiBaseUrls {
        assistant_url,
        signaler_url,
        webapp_url,
        int_client_cert,
    }
}
