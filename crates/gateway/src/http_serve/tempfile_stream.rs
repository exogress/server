//! Stream wrapper which saves the data to a tempfile

use bytes::Bytes;
use futures::{Future, Stream, StreamExt};
use std::{io, io::SeekFrom};
use tokio::{
    io::{AsyncSeekExt, AsyncWriteExt},
    sync::oneshot,
    task::spawn_blocking,
};

pub async fn save_stream<
    H: sha2::Digest + Send,
    E: core::fmt::Debug + Send + Unpin + From<std::io::Error>,
    S: Stream<Item = Result<Bytes, E>> + Send + Unpin,
>(
    input: S,
) -> Result<
    (
        impl Stream<Item = Result<Bytes, E>> + Send + Unpin,
        impl Future<Output = Option<(impl tokio::io::AsyncRead, String, usize)>> + Send,
    ),
    io::Error,
> {
    let mut digest = H::new();

    let file = spawn_blocking(|| tempfile::tempfile()).await??;
    let mut tokio_file = tokio::fs::File::from_std(file);
    let (done_tx, done_rx) = oneshot::channel();

    let mut peekable = Box::pin(input.peekable());

    let mut len: usize = 0;

    let output = async_stream::stream! {
        while let Some(buf_res) = peekable.next().await {
            let buf = buf_res?;

            digest.update(buf.as_ref());

            len += buf.len();

            {
                let b = buf.clone();
                tokio_file.write_all(&b).await?;
            }

            if peekable.as_mut().peek().await.is_none() {
                // that was the last element
                tokio_file.seek(SeekFrom::Start(0)).await?;

                let reader = tokio_file;
                let content_hash = bs58::encode(digest.finalize().as_ref()).into_string();

                let _ = done_tx.send((reader, content_hash, len));

                yield Ok(buf);

                break;
            } else {
                yield Ok(buf);
            }
        };
    };

    let file_ready = async move {
        if let Ok(tokio_file) = done_rx.await {
            Some(tokio_file)
        } else {
            None
        }
    };

    Ok((Box::pin(output), file_ready))
}
