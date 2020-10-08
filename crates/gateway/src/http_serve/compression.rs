use crate::http_serve::handle::StreamingError;
use crate::mime_helpers::ordered_by_quality;
use bytes::{Buf, Bytes};
use futures::stream::BoxStream;
use futures::{StreamExt, TryStreamExt};
use hashbrown::HashSet;
use std::convert::TryFrom;
use std::io;
use tokio::stream::Stream;
use typed_headers::{AcceptEncoding, ContentCoding, ContentType};

lazy_static! {
    pub static ref COMPRESSABLE_MIME_TYPES: HashSet<&'static str> = vec![
        mime::TEXT_CSS.essence_str(),
        mime::TEXT_CSV.essence_str(),
        mime::TEXT_HTML.essence_str(),
        mime::TEXT_JAVASCRIPT.essence_str(),
        mime::TEXT_PLAIN.essence_str(),
        mime::TEXT_STAR.essence_str(),
        mime::TEXT_TAB_SEPARATED_VALUES.essence_str(),
        mime::TEXT_VCARD.essence_str(),
        mime::TEXT_XML.essence_str(),
        mime::IMAGE_BMP.essence_str(),
        mime::IMAGE_SVG.essence_str(),
        mime::APPLICATION_JAVASCRIPT.essence_str(),
        mime::APPLICATION_JSON.essence_str(),
        "application/atom+xml",
        "application/geo+json",
        "application/x-javascript",
        "application/ld+json",
        "application/manifest+json",
        "application/rdf+xml",
        "application/rss+xml",
        "application/vnd.ms-fontobject",
        "application/wasm",
        "application/x-web-app-manifest+json",
        "application/xhtml+xml",
        "application/xml",
        "font/eot",
        "font/otf",
        "font/ttf",
        "text/cache-manifest",
        "text/calendar",
        "text/markdown",
        "text/vnd.rim.location.xloc",
        "text/vtt",
        "text/x-component",
        "text/x-cross-domain-policy",
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
    } else if !COMPRESSABLE_MIME_TYPES.contains(content_type.unwrap().essence_str()) {
        None
    } else if let Some(accept_encoding) = maybe_accept_encoding {
        ordered_by_quality(&accept_encoding)
            .filter_map(|a| SupportedContentEncoding::try_from(a).ok())
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
