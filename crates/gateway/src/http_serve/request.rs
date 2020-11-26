use core::mem;
use futures::stream::Peekable;
use futures::StreamExt;
use hyper::body::HttpBody;
use hyper::Body;
use std::pin::Pin;

#[derive(Debug)]
pub enum RequestBody {
    EmptyHttp,
    Http(Body),
    Ws(warp::ws::Ws),
    Consumed,
}

impl RequestBody {
    pub(crate) async fn new_http(body: Body) -> Self {
        // TODO: the initial idea was to make POST requests with empty body potentially retyable
        // unfortunately, peek doesn't work as expected, and after calling peek and into_inner,
        // the peeked message is lost

        if body.is_end_stream() {
            RequestBody::EmptyHttp
        } else {
            RequestBody::Http(body)
        }
    }

    pub(crate) fn new_ws(ws: warp::ws::Ws) -> Self {
        RequestBody::Ws(ws)
    }
}

pub enum ReqVariant {
    Http(Body),
    Ws(warp::ws::Ws),
}

impl ReqVariant {
    pub fn take_ws(self) -> Option<warp::ws::Ws> {
        match self {
            ReqVariant::Ws(ws) => Some(ws),
            _ => None,
        }
    }

    pub fn take_http(self) -> Option<Body> {
        match self {
            ReqVariant::Http(http) => Some(http),
            _ => None,
        }
    }
}

impl RequestBody {
    /// Take request out. May work multiple times on empty request
    pub fn take(&mut self) -> Option<ReqVariant> {
        match self {
            RequestBody::EmptyHttp => Some(ReqVariant::Http(Body::empty())),
            RequestBody::Http(_) => {
                let http = mem::replace(self, RequestBody::Consumed);
                Some(ReqVariant::Http(http.http_body().unwrap()))
            }
            RequestBody::Ws(_) => {
                let ws = mem::replace(self, RequestBody::Consumed);
                Some(ReqVariant::Ws(ws.ws().unwrap()))
            }
            RequestBody::Consumed => return None,
        }
    }

    pub fn is_http(&self) -> bool {
        match self {
            RequestBody::Http(_) | RequestBody::EmptyHttp => true,
            _ => false,
        }
    }

    pub fn is_ws_body(&self) -> bool {
        match self {
            RequestBody::Ws(_) => true,
            _ => false,
        }
    }

    fn http_body(self) -> Option<Body> {
        match self {
            RequestBody::Http(body) => Some(body),
            _ => None,
        }
    }

    fn ws(self) -> Option<warp::ws::Ws> {
        match self {
            RequestBody::Ws(body) => Some(body),
            _ => None,
        }
    }
}
