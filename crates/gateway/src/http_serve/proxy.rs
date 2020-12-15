use crate::http_serve::compression::SupportedContentEncoding;
use exogress::tunnel::ConnectTarget;
use http::header::HeaderName;
use http::{HeaderValue, Request};
use hyper::Body;

async fn proxy_http_request(
    // req: &mut RequestBody,
    // client_ip_addr: IpAddr,
    // headers: http::HeaderMap,
    // mut proxy_to: Url,
    // method: http::Method,
    // local_ip: IpAddr,
    // external_host: &str,
    req: &Request<Body>,
    res: &mut Respose<Body>,
    hyper: hyper::client::Client<Connector>,
    connect_target: ConnectTarget,
) -> Result<Response<hyper::Body>, Error> {
    connect_target.update_url(&mut proxy_to);

    let proxy_headers = proxy_request_headers(local_ip, external_host, client_ip_addr, headers);

    info!("Proxy request to {}", proxy_to);

    let mut proxy_req = hyper::Request::builder()
        .uri(proxy_to.to_string())
        .method(method);

    debug!("Request built");

    for (header, value) in proxy_headers.into_iter() {
        debug!("copy header {:?}: {:?}", header, value);
        proxy_req.headers_mut().unwrap().append(
            HeaderName::from_bytes(header.as_bytes()).unwrap(),
            HeaderValue::from_str(&value).unwrap(),
        );
    }

    let body_stream = req
        .take()
        .ok_or(Error::AlreadyUsed)?
        .take_http()
        .expect("bad request type");

    let r = tokio::time::timeout(
        HTTP_REQ_TIMEOUT,
        hyper.request(proxy_req.body(body_stream).expect("FIXME")),
    )
    .await;

    debug!("finished request {:?}", r);

    match r {
        Err(_) => {
            info!("timeout processing request");

            Err(Error::Timeout)
        }
        Ok(Err(e)) => {
            info!("error requesting client connection: {}", e);

            Err(Error::RequestError(e))
        }
        Ok(Ok(hyper_response)) => {
            debug!("building response");
            let mut resp = Response::builder().status(match hyper_response.status() {
                StatusCode::PERMANENT_REDIRECT => StatusCode::TEMPORARY_REDIRECT,
                code => code,
            });

            let content_type = hyper_response
                .headers()
                .typed_get::<typed_headers::ContentType>()
                .ok()
                .and_then(|r| r);
            let upstream_resp_headers = hyper_response
                .headers()
                .into_iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<Vec<_>>();
            let upstream_response_body = hyper_response.into_body();
            let (body_processing, compression) =
                maybe_compress_body(upstream_response_body, accept_encoding, content_type);

            let resp_stream = hyper::Body::wrap_stream(
                tokio::stream::StreamExt::timeout(body_processing, HTTP_BYTES_TIMEOUT).map(|r| {
                    debug!("streaming data {:?}", r);
                    match r {
                        Err(e) => Err(anyhow::Error::new(e)),
                        Ok(Err(e)) => Err(anyhow::Error::new(e)),
                        Ok(Ok(r)) => Ok(r),
                    }
                }), //Timeout on data
            );

            {
                let resp_headers = resp.headers_mut().unwrap();

                debug!("copy headers to response");
                for (header, value) in &upstream_resp_headers {
                    if header == CONNECTION || header == CONTENT_ENCODING {
                        continue;
                    }

                    if compression.is_some() && header == CONTENT_LENGTH {
                        continue;
                    }

                    if header.as_str().to_lowercase().starts_with("x-exg") {
                        info!("Trying to proxy already proxied request (prevent loops)");
                        return Err(Error::LoopDetected);
                    }

                    match resp_headers.entry(header) {
                        Entry::Occupied(mut e) => {
                            e.append(value.try_into().unwrap());
                        }
                        Entry::Vacant(e) => {
                            e.insert(value.try_into().unwrap());
                        }
                    }
                }

                info!("copied resp_headers = {:?}", resp_headers);

                resp_headers.insert("x-exg-proxied", HeaderValue::from_str("1").unwrap());
                info!("updated resp_headers = {:?}", resp_headers);
            }

            Ok(resp.body(resp_stream).expect("FIXME"))
        }
    }
}
