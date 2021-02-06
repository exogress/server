use crate::http_serve::RequestsProcessor;
use exogress_common::config_core::parametrized;
use exogress_server_common::logging::{
    CompressProcessingStep, LogMessage, OptimizeProcessingStep, ProcessingStep,
};
use futures::TryStreamExt;
use hashbrown::HashSet;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{HeaderValue, Request, Response};
use hyper::Body;
use itertools::Itertools;
use magick_rust::{magick_wand_genesis, MagickWand};
use smol_str::SmolStr;
use std::convert::TryFrom;
use std::str::FromStr;
use std::sync::{Arc, Once};
use std::{io, mem};
use tokio::task;
use tokio_util::either::Either;
use typed_headers::{ContentCoding, ContentType, HeaderMapExt};

static IMAGE_MAGIC: Once = Once::new();

#[derive(Clone, Debug)]
pub struct ResolvedPostProcessing {
    pub encoding: ResolvedEncoding,
}

#[derive(Clone, Debug)]
pub struct ResolvedEncoding {
    pub mime_types: Result<HashSet<SmolStr>, parametrized::Error>,
    pub brotli: bool,
    pub gzip: bool,
    pub deflate: bool,
    #[serde(rename = "min-size")]
    pub min_size: u32,
}

// lazy_static! {
//     pub static ref COMPRESSABLE_MIME_TYPES: HashSet<&'static str> = vec![
//         mime::TEXT_CSS.essence_str(),
//         mime::TEXT_CSV.essence_str(),
//         mime::TEXT_HTML.essence_str(),
//         mime::TEXT_JAVASCRIPT.essence_str(),
//         mime::TEXT_PLAIN.essence_str(),
//         mime::TEXT_STAR.essence_str(),
//         mime::TEXT_TAB_SEPARATED_VALUES.essence_str(),
//         mime::TEXT_VCARD.essence_str(),
//         mime::TEXT_XML.essence_str(),
//         mime::IMAGE_BMP.essence_str(),
//         mime::IMAGE_SVG.essence_str(),
//         mime::APPLICATION_JAVASCRIPT.essence_str(),
//         mime::APPLICATION_JSON.essence_str(),
//         "application/atom+xml",
//         "application/geo+json",
//         "application/x-javascript",
//         "application/ld+json",
//         "application/manifest+json",
//         "application/rdf+xml",
//         "application/rss+xml",
//         "application/vnd.ms-fontobject",
//         "application/wasm",
//         "application/x-web-app-manifest+json",
//         "application/xhtml+xml",
//         "application/xml",
//         "font/eot",
//         "font/otf",
//         "font/ttf",
//         "text/cache-manifest",
//         "text/calendar",
//         "text/markdown",
//         "text/vnd.rim.location.xloc",
//         "text/vtt",
//         "text/x-component",
//         "text/x-cross-domain-policy",
//     ]
//     .into_iter()
//     .collect();
// }

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
    pub async fn optimize_image(
        &self,
        req: &Request<Body>,
        res: &mut Response<Body>,
        log_message: &mut LogMessage,
    ) -> Result<(), anyhow::Error> {
        let is_webp_supported = req
            .headers()
            .typed_get::<typed_headers::Accept>()?
            .ok_or_else(|| anyhow!("no accept header"))?
            .iter()
            .find(|&item| item.item == mime::Mime::from_str("image/webp").unwrap())
            .is_some();
        if !is_webp_supported {
            return Ok(());
        }
        let content_type: mime::Mime = res
            .headers()
            .get(CONTENT_TYPE)
            .ok_or_else(|| anyhow!("no content-type"))?
            .to_str()?
            .parse()?;
        if content_type == mime::IMAGE_JPEG || content_type == mime::IMAGE_PNG {
            IMAGE_MAGIC.call_once(|| {
                magick_wand_genesis();
            });

            let image_body = Arc::new(
                mem::replace(res.body_mut(), Body::empty())
                    .try_fold(Vec::new(), |mut data, chunk| async move {
                        data.extend_from_slice(&chunk);
                        Ok(data)
                    })
                    .await?,
            );

            let source_image_len = image_body.len();

            let converted_image_result = task::spawn_blocking({
                shadow_clone!(image_body);

                move || {
                    let wand = MagickWand::new();
                    wand.read_image_blob(image_body.as_ref())
                        .map_err(|e| anyhow!("imagemagick read error: {}", e))?;
                    let converted_image = wand
                        .write_image_blob("webp")
                        .map_err(|e| anyhow!("imagemagick write error: {}", e))?;
                    Ok::<_, anyhow::Error>(converted_image)
                }
            })
            .await?;

            match converted_image_result {
                Ok(buf) => {
                    const WEBP_MIME: &str = "image/webp";
                    let buf_len = buf.len();
                    let ratio = source_image_len as f64 / buf_len as f64;
                    log_message
                        .steps
                        .push(ProcessingStep::Optimize(OptimizeProcessingStep {
                            from_content_type: content_type.essence_str().into(),
                            to_content_type: WEBP_MIME.into(),
                            compression_ratio: ratio,
                        }));
                    *res.body_mut() = Body::from(buf);
                    res.headers_mut().typed_insert::<ContentType>(&ContentType(
                        mime::Mime::from_str(WEBP_MIME.into()).unwrap(),
                    ));
                    res.headers_mut()
                        .insert(CONTENT_LENGTH, HeaderValue::from(buf_len));
                }
                Err(e) => {
                    warn!("error converting image to WebP: {}", e);
                    assert_eq!(Arc::strong_count(&image_body), 1);
                    // restore original image body
                    *res.body_mut() = Body::from(Arc::try_unwrap(image_body).unwrap());
                }
            }

            Ok(())
        } else {
            Ok(())
        }
    }

    pub fn compress(
        &self,
        req: &Request<Body>,
        res: &mut Response<Body>,
        encoding: Option<&ResolvedEncoding>,
        log_message: &mut LogMessage,
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

        let maybe_compression = if maybe_content_type.is_none() {
            None
        } else if !mime_types.contains(maybe_content_type.unwrap().essence_str()) {
            None
        } else if let Some(accept_encoding) = maybe_accept_encoding {
            accept_encoding
                .iter()
                .map(|qi| &qi.item)
                .filter_map(|a| SupportedContentEncoding::try_from(a).ok())
                .filter(|supported| {
                    info!("supported encoding: {:?}", supported);
                    match supported {
                        SupportedContentEncoding::Brotli => encoding.brotli,
                        SupportedContentEncoding::Deflate => encoding.deflate,
                        SupportedContentEncoding::Gzip => encoding.gzip,
                    }
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
                log_message
                    .steps
                    .push(ProcessingStep::Compress(CompressProcessingStep {
                        encoding: header.as_str().into(),
                    }));

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

                log_message
                    .steps
                    .push(ProcessingStep::Compress(CompressProcessingStep {
                        encoding: header.as_str().into(),
                    }));

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

                log_message
                    .steps
                    .push(ProcessingStep::Compress(CompressProcessingStep {
                        encoding: header.as_str().into(),
                    }));

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
