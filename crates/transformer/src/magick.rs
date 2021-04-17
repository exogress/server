use bytes::Bytes;
use std::{
    io,
    io::Write,
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    task::spawn_blocking,
};

#[derive(Debug, Clone)]
pub struct ImageConversionMeta {
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

pub(crate) async fn convert(
    conversion_threads: Option<u8>,
    conversion_memory: Option<u64>,
    image_body: Bytes,
    transform_to_format: &str,
    mime_type: &str,
) -> anyhow::Result<ImageConversionResult> {
    let mut cmd = tokio::process::Command::new("magick");

    if let Some(threads) = conversion_threads {
        info!("set conversion threads to {}", threads);
        cmd.arg("-limit").arg("thread").arg(threads.to_string());
    }

    if let Some(mem) = conversion_memory {
        info!("set conversion mem to {}", mem);
        cmd.arg("-limit").arg("memory").arg(mem.to_string());
    }

    if mime_type == "image/png" {
        cmd.arg("-quality 100");
        if transform_to_format == "webp" {
            cmd.arg("-define webp:lossless=true");
        }
    }

    let src_tempfile = spawn_blocking({
        shadow_clone!(image_body);

        move || {
            let mut tempfile = tempfile::NamedTempFile::new()?;
            tempfile.write_all(&image_body)?;
            Ok::<_, io::Error>(tempfile)
        }
    })
    .await??;

    let src_path = src_tempfile.path().to_path_buf();
    cmd.arg(src_path.to_str().unwrap());

    let dst_tempfile = spawn_blocking(move || tempfile::NamedTempFile::new()).await??;

    cmd.arg(format!(
        "{}:{}",
        transform_to_format.to_uppercase(),
        dst_tempfile.path().to_str().unwrap()
    ));

    let start_conversion = Instant::now();

    error!("Will spawn cmd: {:?}", cmd);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = cmd.spawn()?;

    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();

    let mut stdout_reader = BufReader::new(stdout).lines();
    let mut stderr_reader = BufReader::new(stderr).lines();

    tokio::spawn(async move {
        while let Some(line) = stdout_reader.next_line().await? {
            info!("Imagemagick >> {}", line);
        }

        Ok::<_, io::Error>(())
    });

    tokio::spawn(async move {
        while let Some(line) = stderr_reader.next_line().await? {
            info!("Imagemagick >> {}", line);
        }

        Ok::<_, io::Error>(())
    });

    let cmd_res = child.wait().await;
    let elapsed = start_conversion.elapsed();
    error!("conversion result = {:?}. took = {:?}", cmd_res, elapsed);

    let status = cmd_res?;

    if !status.success() {
        bail!("bad conversion command status: {}", status);
    };

    let mut tokio_dst = tokio::fs::File::from_std(dst_tempfile.reopen()?);

    let mut transformed = Vec::new();

    tokio_dst.read_to_end(&mut transformed).await?;

    let source_size = image_body.len() as u64;
    let compression_ratio = source_size as f32 / transformed.len() as f32;

    Ok::<_, anyhow::Error>(ImageConversionResult {
        meta: ImageConversionMeta {
            transformed_size: transformed.len() as u64,
            took_time: elapsed,
            compression_ratio,
        },
        transformed: transformed.into(),
    })
}
