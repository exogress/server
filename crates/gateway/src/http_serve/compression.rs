use crate::http_serve::handle::StreamingError;
use bytes::{Buf, Bytes};
use futures::stream::BoxStream;
use futures::{StreamExt, TryStreamExt};
use hashbrown::HashSet;
use http::header::ACCEPT_ENCODING;
use itertools::Itertools;
use std::convert::{TryFrom, TryInto};
use std::io;
use std::pin::Pin;
use tokio::stream::Stream;
use tokio_either::Either;
use typed_headers::{
    AcceptEncoding, ContentCoding, ContentEncoding, ContentLength, ContentType, HeaderMapExt,
    Quality,
};
use warp::Filter;

lazy_static! {
    pub static ref COMPRESSABLE_MIME_TYPES: HashSet<mime::Mime> = vec![
        mime::TEXT_CSS,
        mime::TEXT_CSV,
        mime::TEXT_HTML,
        mime::TEXT_JAVASCRIPT,
        mime::TEXT_PLAIN,
        mime::TEXT_STAR,
        mime::TEXT_TAB_SEPARATED_VALUES,
        mime::TEXT_VCARD,
        mime::TEXT_XML,
        mime::IMAGE_BMP,
        mime::IMAGE_SVG,
        mime::APPLICATION_JAVASCRIPT,
        mime::APPLICATION_JSON,
        "application/atom+xml".parse().unwrap(),
        "application/geo+json".parse().unwrap(),
        "application/x-javascript".parse().unwrap(),
        "application/ld+json".parse().unwrap(),
        "application/manifest+json".parse().unwrap(),
        "application/rdf+xml".parse().unwrap(),
        "application/rss+xml".parse().unwrap(),
        "application/vnd.ms-fontobject".parse().unwrap(),
        "application/wasm".parse().unwrap(),
        "application/x-web-app-manifest+json".parse().unwrap(),
        "application/xhtml+xml".parse().unwrap(),
        "application/xml".parse().unwrap(),
        "font/eot".parse().unwrap(),
        "font/otf".parse().unwrap(),
        "font/ttf".parse().unwrap(),
        "text/cache-manifest".parse().unwrap(),
        "text/calendar".parse().unwrap(),
        "text/markdown".parse().unwrap(),
        "text/vnd.rim.location.xloc".parse().unwrap(),
        "text/vtt".parse().unwrap(),
        "text/x-component".parse().unwrap(),
        "text/x-cross-domain-policy".parse().unwrap(),
    ]
    .into_iter()
    .collect();
}

#[derive(Debug, Clone, Copy)]
pub enum SupportedContentEncoding {
    // Brotli compression hangs for some reason
    // Brotli,
    Gzip,
    // Deflate,
}

impl<'a> TryFrom<&'a ContentCoding> for SupportedContentEncoding {
    type Error = ();

    fn try_from(value: &'a ContentCoding) -> Result<Self, Self::Error> {
        match value {
            // &ContentCoding::BROTLI => Ok(SupportedContentEncoding::Brotli),
            &ContentCoding::GZIP | &ContentCoding::STAR => Ok(SupportedContentEncoding::Gzip),
            // &ContentCoding::DEFLATE => Ok(SupportedContentEncoding::Deflate),
            _ => Err(()),
        }
    }
}

#[inline]
pub fn maybe_compress_body(
    s: impl Stream<Item = Result<impl Buf + 'static, hyper::Error>> + Send + 'static,
    maybe_accept_encoding: Option<AcceptEncoding>,
    content_type: Option<ContentType>,
) -> (
    BoxStream<'static, Result<Bytes, StreamingError>>,
    Option<SupportedContentEncoding>,
) {
    let compression = if content_type.is_none() {
        None
    } else if !COMPRESSABLE_MIME_TYPES.contains(&content_type.unwrap()) {
        None
    } else if let Some(accept_encoding) = maybe_accept_encoding {
        accept_encoding
            .iter()
            .filter(|a| &a.quality > &Quality::from_u16(0))
            .sorted_by(|&a, &b| a.quality.cmp(&b.quality).reverse())
            .filter_map(|a| SupportedContentEncoding::try_from(&a.item).ok())
            .next()
    } else {
        None
    };

    let bytes_stream = s
        .map_ok(|s| {
            let bytes = s.bytes();
            // FIXME! inefficient
            Bytes::copy_from_slice(bytes)
        })
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("hyper error: {}", e)));

    let processed_stream = match compression {
        // Some(SupportedContentEncoding::Brotli) => {
        //     async_compression::stream::BrotliEncoder::new(bytes_stream)
        //         .err_into()
        //         .boxed()
        // }
        Some(SupportedContentEncoding::Gzip) => {
            async_compression::stream::GzipEncoder::new(bytes_stream)
                .err_into()
                .boxed()
        }
        // Some(SupportedContentEncoding::Deflate) => {
        //     async_compression::stream::DeflateEncoder::new(bytes_stream)
        //         .err_into()
        //         .boxed()
        // }
        None => bytes_stream.err_into().boxed(),
    };

    (processed_stream, compression)
}
