pub fn extract_sni_hostname(buf: &[u8]) -> Result<Option<Option<String>>, anyhow::Error> {
    let parse = tls_parser::parse_tls_plaintext(buf);
    match parse {
        Ok((_rem, record)) => Ok(Some(
            record
                .msg
                .into_iter()
                .filter_map(|msg| {
                    match msg {
                        tls_parser::tls::TlsMessage::Handshake(handshake) => match handshake {
                            tls_parser::tls::TlsMessageHandshake::ClientHello(hello) => {
                                if let Some(ext) = hello.ext {
                                    tls_parser::tls_extensions::parse_tls_extensions(ext)
                                        .ok()
                                        .and_then(|(_, ext)| {
                                            ext
                                                .into_iter()
                                                .filter_map(|ext| match ext {
                                                    tls_parser::tls_extensions::TlsExtension::SNI(snis) => snis
                                                        .into_iter()
                                                        .filter_map(|(sni_type, value)| {
                                                            if tls_parser::tls_extensions::SNIType::HostName
                                                                == sni_type
                                                            {
                                                                Some(value)
                                                            } else {
                                                                None
                                                            }
                                                        })
                                                        .next(),
                                                    _ => None,
                                                })
                                                .next()
                                        })
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        },
                        _ => None,
                    }
                })
                .next()
                .and_then(|m| String::from_utf8(m.to_vec()).ok()),
        )),
        Err(nom::Err::Incomplete(_needed)) => {
            Ok(None)
        }
        Err(e) => Err(anyhow!("parse error: {}", e)),
    }
}
