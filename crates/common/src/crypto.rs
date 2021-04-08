use anyhow::anyhow;
use futures::{Stream, StreamExt};
use sodiumoxide::crypto::secretstream::xchacha20poly1305;
use std::{convert::TryFrom, io};
use tokio_util::codec::LengthDelimitedCodec;

pub fn decrypt_stream(
    reader: impl tokio::io::AsyncRead,
    xchacha20poly1305_secret_key: &xchacha20poly1305::Key,
    body_encryption_header: &sodiumoxide::crypto::secretstream::Header,
) -> anyhow::Result<impl Stream<Item = Result<Vec<u8>, io::Error>>> {
    let mut dec_stream = sodiumoxide::crypto::secretstream::Stream::init_pull(
        &body_encryption_header,
        xchacha20poly1305_secret_key,
    )
    .map_err(|_| anyhow!("could not init decryption"))?;

    let framed_reader = LengthDelimitedCodec::builder()
        .max_frame_length(u32::MAX as usize)
        .new_read(reader);

    let decoded = framed_reader.map(move |encrypted_frame| {
        Ok::<Vec<u8>, io::Error>(
            dec_stream
                .pull(&encrypted_frame?, None)
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::Other, "failed to decoded encrypted frame")
                })?
                .0,
        )
    });

    Ok(decoded)
}

pub fn encrypt_stream<E: std::error::Error + Unpin>(
    mut source: impl Stream<Item = Result<impl AsRef<[u8]>, E>> + Unpin,
    xchacha20poly1305_secret_key: &xchacha20poly1305::Key,
) -> anyhow::Result<(
    impl Stream<Item = Result<(Vec<u8>, u64), E>>,
    sodiumoxide::crypto::secretstream::Header,
)> {
    let (mut enc_stream, header) =
        sodiumoxide::crypto::secretstream::Stream::init_push(&xchacha20poly1305_secret_key)
            .map_err(|_| anyhow!("could not init encryption"))?;

    let stream = async_stream::stream! {
        while let Some(item_result) = source.next().await {
            let item = item_result?;

            let mut result_vec = enc_stream
                .push(
                    item.as_ref(),
                    None,
                    sodiumoxide::crypto::secretstream::Tag::Message,
                )
                .unwrap();

            let mut v = u32::try_from(result_vec.len())
                .unwrap()
                .to_be_bytes()
                .to_vec();
            v.append(&mut result_vec);

            yield Ok((v, item.as_ref().len() as u64));
        }
    };

    Ok((stream, header))
}
