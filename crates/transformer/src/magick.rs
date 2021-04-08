use bytes::Bytes;
use exogress_common::entities::serde::__private::Formatter;
use magick_rust::{magick_wand_genesis, MagickWand};
use std::{
    sync::Once,
    time::{Duration, Instant},
};

#[derive(Debug)]
pub struct ImageConversionMeta {
    pub content_type: String,
    pub source_size: u64,
    pub transformed_size: u64,
    pub took_time: Duration,
    pub compression_ratio: f32,
}

pub struct ImageConversionResult {
    pub(crate) transformed: Bytes,
    pub(crate) meta: ImageConversionMeta,
}

impl core::fmt::Debug for ImageConversionResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ImageConversionResult")
            .field("meta", &self.meta)
            .finish()
    }
}

static IMAGE_MAGIC: Once = Once::new();

pub(crate) fn convert(
    image_body: &Bytes,
    format: &str,
    mime_type: &str,
) -> anyhow::Result<ImageConversionResult> {
    IMAGE_MAGIC.call_once(|| {
        magick_wand_genesis();
    });

    let wand = MagickWand::new();

    wand.read_image_blob(image_body.as_ref())
        .map_err(|e| anyhow!("imagemagick read error: {}", e))?;

    let start_conversion = Instant::now();
    let transformed: Bytes = wand
        .write_image_blob(format)
        .map_err(|e| anyhow!("imagemagick write error: {}", e))?
        .into();
    let elapsed = start_conversion.elapsed();

    let source_size = image_body.len() as u64;

    let compression_ratio = source_size as f32 / transformed.len() as f32;

    Ok::<_, anyhow::Error>(ImageConversionResult {
        meta: ImageConversionMeta {
            content_type: mime_type.to_string(),
            source_size,
            transformed_size: transformed.len() as u64,
            took_time: elapsed,
            compression_ratio,
        },
        transformed,
    })
}
