use crate::http_serve::{logging::LogMessageSendOnDrop, RequestsProcessor};
use exogress_common::config_core::referenced;
use futures::TryStreamExt;
use hashbrown::HashSet;
use http::{HeaderValue, Request, Response};
use hyper::Body;
use itertools::Itertools;
use smol_str::SmolStr;
use std::{convert::TryFrom, io, mem, sync::Arc};
use tokio_util::either::Either;
use typed_headers::{ContentCoding, HeaderMapExt};

#[derive(Clone, Debug)]
pub struct ResolvedPostProcessing {
    pub encoding: ResolvedEncoding,
    pub image: ResolvedImage,
}

#[derive(Clone, Debug)]
pub struct ResolvedEncoding {
    pub mime_types: Result<HashSet<SmolStr>, referenced::Error>,
    pub brotli: bool,
    pub gzip: bool,
    pub deflate: bool,
    pub min_size: u32,
}

#[derive(Clone, Debug)]
pub struct ResolvedImage {
    pub is_png: bool,
    pub is_jpeg: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum SupportedContentEncoding {
    Brotli,
    Gzip,
    Deflate,
}

impl SupportedContentEncoding {
    pub fn weight(&self) -> u8 {
        match self {
            SupportedContentEncoding::Brotli => 200,
            SupportedContentEncoding::Gzip => 150,
            SupportedContentEncoding::Deflate => 10,
        }
    }
}

impl<'a> TryFrom<&'a ContentCoding> for SupportedContentEncoding {
    type Error = ();

    fn try_from(value: &'a ContentCoding) -> Result<Self, Self::Error> {
        match value {
            &ContentCoding::BROTLI => Ok(SupportedContentEncoding::Brotli),
            &ContentCoding::GZIP | &ContentCoding::STAR => Ok(SupportedContentEncoding::Gzip),
            &ContentCoding::DEFLATE => Ok(SupportedContentEncoding::Deflate),
            _ => Err(()),
        }
    }
}

impl RequestsProcessor {
    pub fn compress_if_applicable(
        &self,
        req: &Request<Body>,
        res: &mut Response<Body>,
        encoding: Option<&ResolvedEncoding>,
        log_message_container: &Arc<parking_lot::Mutex<LogMessageSendOnDrop>>,
    ) -> Result<(), anyhow::Error> {
        let encoding = match encoding {
            None => return Ok(()),
            Some(encoding) => encoding,
        };

        match res.headers().typed_get::<typed_headers::ContentLength>() {
            Ok(Some(content_length)) if content_length.0 >= encoding.min_size as u64 => {}
            _ => return Ok(()),
        };

        let maybe_accept_encoding = req
            .headers()
            .typed_get::<typed_headers::AcceptEncoding>()
            .ok()
            .flatten();
        let maybe_content_type = res
            .headers()
            .typed_get::<typed_headers::ContentType>()
            .ok()
            .flatten();

        // FIXME: remove clone
        let mime_types = encoding.mime_types.clone()?;

        let maybe_compression = if maybe_content_type.is_none()
            || !mime_types.contains(maybe_content_type.unwrap().essence_str())
        {
            None
        } else if let Some(accept_encoding) = maybe_accept_encoding {
            accept_encoding
                .iter()
                .map(|qi| &qi.item)
                .filter_map(|a| SupportedContentEncoding::try_from(a).ok())
                .filter(|supported| match supported {
                    SupportedContentEncoding::Brotli => encoding.brotli,
                    SupportedContentEncoding::Deflate => encoding.deflate,
                    SupportedContentEncoding::Gzip => encoding.gzip,
                })
                .sorted_by(|&a, &b| a.weight().cmp(&b.weight()).reverse())
                .next()
        } else {
            None
        };

        let compression = match maybe_compression {
            None => return Ok(()),
            Some(compression) => compression,
        };

        let uncompressed_body = mem::replace(res.body_mut(), Body::empty())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()));

        res.headers_mut()
            .insert("vary", HeaderValue::from_str("Accept-Encoding").unwrap());
        let _ = res
            .headers_mut()
            .typed_remove::<typed_headers::ContentLength>();
        let processed_stream = match compression {
            SupportedContentEncoding::Brotli => {
                let header = typed_headers::ContentCoding::BROTLI;
                log_message_container.lock().as_mut().response.compression =
                    Some(SmolStr::from("br"));

                res.headers_mut()
                    .typed_insert(&typed_headers::ContentEncoding::from(header));

                Either::Left(tokio_util::io::ReaderStream::new(
                    async_compression::tokio::bufread::BrotliEncoder::with_quality(
                        tokio_util::io::StreamReader::new(uncompressed_body),
                        async_compression::Level::Precise(6),
                    ),
                ))
            }
            SupportedContentEncoding::Gzip => {
                let header = typed_headers::ContentCoding::GZIP;

                log_message_container.lock().as_mut().response.compression =
                    Some(SmolStr::from("gzip"));

                res.headers_mut()
                    .typed_insert(&typed_headers::ContentEncoding::from(header));

                Either::Right(Either::Left(tokio_util::io::ReaderStream::new(
                    async_compression::tokio::bufread::GzipEncoder::new(
                        tokio_util::io::StreamReader::new(uncompressed_body),
                    ),
                )))
            }
            SupportedContentEncoding::Deflate => {
                let header = typed_headers::ContentCoding::DEFLATE;

                log_message_container.lock().as_mut().response.compression =
                    Some(SmolStr::from("deflate"));

                res.headers_mut()
                    .typed_insert(&typed_headers::ContentEncoding::from(header));

                Either::Right(Either::Right(tokio_util::io::ReaderStream::new(
                    async_compression::tokio::bufread::DeflateEncoder::new(
                        tokio_util::io::StreamReader::new(uncompressed_body),
                    ),
                )))
            }
        };

        *res.body_mut() = Body::wrap_stream(processed_stream);

        Ok(())
    }
}
