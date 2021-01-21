use http::header::{
    HeaderName, ACCEPT_ENCODING, CONNECTION, FORWARDED, HOST, PROXY_AUTHENTICATE,
    PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING,
};
use http::{HeaderMap, Request, Response};
use hyper::Body;
use std::net::SocketAddr;

lazy_static! {
    /// https://tools.ietf.org/html/rfc2616#section-13.5.1v
    /// The following HTTP/1.1 headers are hop-by-hop headers:
    ///     - Connection
    ///     - Keep-Alive
    ///     - Proxy-Authenticate
    ///     - Proxy-Authorization
    ///     - TE
    ///     - Trailers
    ///     - Transfer-Encoding
    ///     - Upgrade
    pub static ref HOP_BY_HOP_HEADERS: [HeaderName; 7] = [
        CONNECTION,
        HeaderName::from_static("keep-alive"),
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,

        // not sure why is it hop-by-hop
        // UPGRADE,
    ];
}
pub fn copy_headers_from_proxy_res_to_res(
    proxy_headers: &HeaderMap,
    res: &mut Response<Body>,
    is_upgrade_allowed: bool,
) {
    for (incoming_header_name, incoming_header_value) in proxy_headers.iter() {
        if incoming_header_name == ACCEPT_ENCODING {
            continue;
        }

        if incoming_header_name == CONNECTION {
            if is_upgrade_allowed {
                if !incoming_header_value
                    .to_str()
                    .unwrap()
                    .to_lowercase()
                    .contains("upgrade")
                {
                    continue;
                } else {
                    res.headers_mut()
                        .insert(CONNECTION, "Upgrade".parse().unwrap());
                }
            } else {
                continue;
            }
        }

        if HOP_BY_HOP_HEADERS.contains(incoming_header_name) {
            continue;
        }

        res.headers_mut()
            .append(incoming_header_name, incoming_header_value.clone());
    }
}

pub fn copy_headers_to_proxy_req(
    req: &Request<Body>,
    proxy_req: &mut Request<Body>,
    is_upgrade_allowed: bool,
) {
    for (incoming_header_name, incoming_header_value) in req.headers() {
        if incoming_header_name == ACCEPT_ENCODING || incoming_header_name == HOST {
            continue;
        }

        if incoming_header_name == CONNECTION {
            if is_upgrade_allowed {
                if !incoming_header_value
                    .to_str()
                    .unwrap()
                    .to_lowercase()
                    .contains("upgrade")
                {
                    continue;
                } else {
                    proxy_req
                        .headers_mut()
                        .insert(CONNECTION, "keep-alive, Upgrade".parse().unwrap());
                }
            } else {
                continue;
            }
        }

        if HOP_BY_HOP_HEADERS.contains(incoming_header_name) {
            continue;
        }

        proxy_req
            .headers_mut()
            .append(incoming_header_name, incoming_header_value.clone());
    }
}

pub fn add_forwarded_headers(
    req: &mut Request<Body>,
    local_addr: &SocketAddr,
    remote_addr: &SocketAddr,
    public_hostname: &str,
    force_host_header: Option<&str>,
) {
    req.headers_mut()
        .append("x-forwarded-host", public_hostname.parse().unwrap());

    req.headers_mut()
        .append("x-forwarded-proto", "https".parse().unwrap());

    //X-Forwarded-Host and X-Forwarded-Proto
    let mut x_forwarded_for = req
        .headers_mut()
        .remove("x-forwarded-for")
        .map(|h| h.to_str().unwrap().to_string())
        .unwrap_or_else(|| remote_addr.ip().to_string());

    x_forwarded_for.push_str(&format!(", {}", local_addr.ip()));

    req.headers_mut()
        .insert("x-forwarded-for", x_forwarded_for.parse().unwrap());

    if !req.headers().contains_key("x-real-ip") {
        req.headers_mut()
            .append("x-real-ip", remote_addr.ip().to_string().parse().unwrap());
    }

    // FIXME: consider chain of proxies
    let forwarded_header = format!(
        "by={};for={};host={};proto=https",
        local_addr.ip(),
        remote_addr.ip(),
        public_hostname
    );

    req.headers_mut()
        .insert(FORWARDED, forwarded_header.parse().unwrap());

    let host_header = force_host_header.unwrap_or(public_hostname);
    req.headers_mut().insert(HOST, host_header.parse().unwrap());

    info!("with forwarded headers = {:?}", req.headers());
}
