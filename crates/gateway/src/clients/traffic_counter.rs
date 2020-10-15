///! Count traffic on AsyncRead/AsyncWrite channels
use bytes::{Buf, BufMut};
use chrono::{DateTime, Utc};
use core::mem;
use exogress_entities::AccountName;
use futures::ready;
use parking_lot::Mutex;
use std::convert::TryInto;
use std::io;
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::Context;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::macros::support::Poll;

pub struct TrafficCounters {
    account_name: AccountName,
    bytes_read: AtomicU64,
    bytes_written: AtomicU64,
    initiated_at: Mutex<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct RecordedTrafficStatistics {
    pub account_name: AccountName,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
}

impl TrafficCounters {
    pub fn flush(self: &Arc<TrafficCounters>) -> Option<RecordedTrafficStatistics> {
        let bytes_read = self.bytes_read.swap(0, Ordering::SeqCst);
        let bytes_written = self.bytes_written.swap(0, Ordering::SeqCst);

        if bytes_read == 0 && bytes_written == 0 {
            return None;
        }

        let now = Utc::now();
        Some(RecordedTrafficStatistics {
            account_name: self.account_name.clone(),
            bytes_read,
            bytes_written,
            from: mem::replace(&mut self.initiated_at.lock(), now),
            to: now,
        })
    }

    pub fn new(account_name: AccountName) -> Arc<Self> {
        Arc::new(TrafficCounters {
            account_name,
            bytes_read: Default::default(),
            bytes_written: Default::default(),
            initiated_at: Mutex::new(Utc::now()),
        })
    }
}

pub struct TrafficCountedStream<I: AsyncRead + AsyncWrite + Unpin> {
    io: I,
    counters: Arc<TrafficCounters>,
}

impl<I: AsyncRead + AsyncWrite + Unpin> AsyncRead for TrafficCountedStream<I> {
    unsafe fn prepare_uninitialized_buffer(&self, buf: &mut [MaybeUninit<u8>]) -> bool {
        self.io.prepare_uninitialized_buffer(buf)
    }

    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let num_bytes = ready!(Pin::new(&mut self.io).poll_read(cx, buf))?;
        self.counters
            .bytes_read
            .fetch_add(num_bytes.try_into().unwrap(), Ordering::SeqCst);
        Poll::Ready(Ok(num_bytes))
    }

    fn poll_read_buf<B: BufMut>(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut B,
    ) -> Poll<io::Result<usize>>
    where
        Self: Sized,
    {
        let num_bytes = ready!(Pin::new(&mut self.io).poll_read_buf(cx, buf))?;
        self.counters
            .bytes_read
            .fetch_add(num_bytes.try_into().unwrap(), Ordering::SeqCst);
        Poll::Ready(Ok(num_bytes))
    }
}

impl<I: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TrafficCountedStream<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let num_bytes = ready!(Pin::new(&mut self.io).poll_write(cx, buf))?;
        self.counters
            .bytes_written
            .fetch_add(num_bytes.try_into().unwrap(), Ordering::SeqCst);
        Poll::Ready(Ok(num_bytes))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }

    fn poll_write_buf<B: Buf>(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut B,
    ) -> Poll<Result<usize, io::Error>>
    where
        Self: Sized,
    {
        let num_bytes = ready!(Pin::new(&mut self.io).poll_write_buf(cx, buf))?;
        self.counters
            .bytes_written
            .fetch_add(num_bytes.try_into().unwrap(), Ordering::SeqCst);
        Poll::Ready(Ok(num_bytes))
    }
}

impl<I: AsyncRead + AsyncWrite + Unpin> TrafficCountedStream<I> {
    pub fn new(io: I, counters: Arc<TrafficCounters>) -> Self {
        TrafficCountedStream { io, counters }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;
    use std::sync::atomic::Ordering;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn test_counting() {
        let mut buf = vec![0u8; 32768];
        let mut io = Cursor::new(&mut buf);

        let counters = TrafficCounters::new("account".parse().unwrap());

        let mut counted_stream = TrafficCountedStream::new(io, counters.clone());
        let mut result = Vec::new();
        let read_bytes = counted_stream.read_to_end(&mut result).await.unwrap();
        assert_eq!(read_bytes, 32768);

        let to_write = vec![0u8; 1000];
        counted_stream.write_all(&to_write).await.unwrap();

        let counts = counters.flush().unwrap();

        assert_eq!(counts.bytes_read, 32768);
        assert_eq!(counts.bytes_written, 1000);
    }
}
