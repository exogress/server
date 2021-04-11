use bytes::Bytes;
use magick_rust::{MagickWand, ResourceType};
use std::{
    convert::TryInto,
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

pub(crate) fn convert(
    conversion_threads: Option<u8>,
    conversion_memory: Option<u64>,
    image_body: &Bytes,
    format: &str,
    mime_type: &str,
) -> anyhow::Result<ImageConversionResult> {
    let wand = MagickWand::new();

    if let Some(threads) = conversion_threads {
        info!("set conversion threads to {}", threads);
        MagickWand::set_resource_limit(ResourceType::Thread, threads.into())
            .expect("failed to set magick wand thread limit");
    }

    if let Some(mem) = conversion_memory {
        info!("set conversion mem to {}", mem);
        MagickWand::set_resource_limit(ResourceType::Memory, mem.try_into().unwrap())
            .expect("failed to set magick wand memory limit");
    }

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
