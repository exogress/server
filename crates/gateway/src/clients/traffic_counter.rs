///! Count traffic on AsyncRead/AsyncWrite channels
use chrono::{DateTime, Utc};
use core::{fmt, mem};
use exogress_common::entities::{AccountUniqueId, ProjectUniqueId};
use futures::{
    channel::{mpsc, oneshot},
    ready, SinkExt,
};
use parking_lot::Mutex;
use prometheus::IntCounter;
use std::{
    convert::TryInto,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    task::Context,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    macros::support::Poll,
    time::{sleep, Duration},
};

pub struct TrafficCounters {
    account_unique_id: AccountUniqueId,
    project_unique_id: ProjectUniqueId,
    bytes_read: AtomicU64,
    bytes_written: AtomicU64,
    is_closed: AtomicBool,
    initiated_at: Mutex<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct RecordedTrafficStatistics {
    pub account_unique_id: AccountUniqueId,
    pub project_unique_id: ProjectUniqueId,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
}

#[derive(Debug)]
pub enum OneOfTrafficStatistics {
    Tunnel(RecordedTrafficStatistics),
    Https(RecordedTrafficStatistics),
    Public(RecordedTrafficStatistics),
}

impl OneOfTrafficStatistics {
    pub fn account_unique_id(&self) -> &AccountUniqueId {
        match self {
            OneOfTrafficStatistics::Https(s) => &s.account_unique_id,
            OneOfTrafficStatistics::Tunnel(s) => &s.account_unique_id,
            OneOfTrafficStatistics::Public(s) => &s.account_unique_id,
        }
    }
    pub fn project_unique_id(&self) -> &ProjectUniqueId {
        match self {
            OneOfTrafficStatistics::Https(s) => &s.project_unique_id,
            OneOfTrafficStatistics::Tunnel(s) => &s.project_unique_id,
            OneOfTrafficStatistics::Public(s) => &s.project_unique_id,
        }
    }
    pub fn to(&self) -> &DateTime<Utc> {
        match self {
            OneOfTrafficStatistics::Https(s) => &s.to,
            OneOfTrafficStatistics::Tunnel(s) => &s.to,
            OneOfTrafficStatistics::Public(s) => &s.to,
        }
    }
    pub fn bytes_read(&self) -> &u64 {
        match self {
            OneOfTrafficStatistics::Https(s) => &s.bytes_read,
            OneOfTrafficStatistics::Tunnel(s) => &s.bytes_read,
            OneOfTrafficStatistics::Public(s) => &s.bytes_read,
        }
    }
    pub fn bytes_written(&self) -> &u64 {
        match self {
            OneOfTrafficStatistics::Https(s) => &s.bytes_written,
            OneOfTrafficStatistics::Tunnel(s) => &s.bytes_written,
            OneOfTrafficStatistics::Public(s) => &s.bytes_written,
        }
    }
    pub fn is_https(&self) -> bool {
        match self {
            OneOfTrafficStatistics::Https(_) => true,
            _ => false,
        }
    }
    pub fn is_tunnel(&self) -> bool {
        match self {
            OneOfTrafficStatistics::Tunnel(_) => true,
            _ => false,
        }
    }

    pub fn is_public(&self) -> bool {
        match self {
            OneOfTrafficStatistics::Public(_) => true,
            _ => false,
        }
    }
}

impl TrafficCounters {
    pub fn flush(self: &Arc<TrafficCounters>) -> Result<Option<RecordedTrafficStatistics>, ()> {
        let bytes_read = self.bytes_read.swap(0, Ordering::SeqCst);
        let bytes_written = self.bytes_written.swap(0, Ordering::SeqCst);

        if bytes_read == 0 && bytes_written == 0 {
            return if self.is_closed.load(Ordering::SeqCst) {
                Err(())
            } else {
                Ok(None)
            };
        }

        let now = Utc::now();
        Ok(Some(RecordedTrafficStatistics {
            account_unique_id: self.account_unique_id.clone(),
            project_unique_id: self.project_unique_id.clone(),
            bytes_read,
            bytes_written,
            from: mem::replace(&mut self.initiated_at.lock(), now),
            to: now,
        }))
    }

    pub fn new(
        account_unique_id: AccountUniqueId,
        project_unique_id: ProjectUniqueId,
    ) -> Arc<Self> {
        Arc::new(TrafficCounters {
            account_unique_id,
            project_unique_id,
            bytes_read: Default::default(),
            bytes_written: Default::default(),
            is_closed: false.into(),
            initiated_at: Mutex::new(Utc::now()),
        })
    }

    pub async fn spawn_flusher(
        counters: Arc<Self>,
        mut traffic_counters_tx: mpsc::Sender<RecordedTrafficStatistics>,
        stop_rx: oneshot::Receiver<()>,
    ) -> anyhow::Result<()> {
        let periodically_flush = {
            shadow_clone!(counters, mut traffic_counters_tx);

            async move {
                loop {
                    sleep(Duration::from_secs(60)).await;
                    match counters.flush() {
                        Ok(Some(stats)) => {
                            traffic_counters_tx.send(stats).await?;
                        }
                        Err(()) => {
                            break;
                        }
                        Ok(None) => {}
                    }
                }

                Ok::<_, anyhow::Error>(())
            }
        };

        let r = tokio::select! {
            r = periodically_flush => {
                info!("Statistics public traffic dumper unexpectedly stopped with message: {:?}", r);
                r
            },
            _ = stop_rx => Ok(()),
        };

        info!("Statistics public traffic dumper stopped. Flushing outstanding data.");

        // make sure data us dumped
        if let Ok(Some(stats)) = counters.flush() {
            traffic_counters_tx.send(stats).await?;
        }

        r
    }
}

pub struct TrafficCountedStream<I: AsyncRead + AsyncWrite + Unpin> {
    io: I,
    counters: Arc<TrafficCounters>,
    sent_counter: IntCounter,
    recv_counter: IntCounter,
}

impl<I> TrafficCountedStream<I>
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    pub fn get_ref(&self) -> &I {
        &self.io
    }
}

impl<I> fmt::Debug for TrafficCountedStream<I>
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TrafficCountedStream")
    }
}

impl<I: AsyncRead + AsyncWrite + Unpin> AsyncRead for TrafficCountedStream<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let was_filled = buf.filled().len();

        let res = (|| {
            ready!(Pin::new(&mut self.io).poll_read(cx, buf))?;
            Poll::Ready(Ok(()))
        })();

        let became_filled = buf.filled().len();

        let num_bytes = became_filled - was_filled;

        match (&res, num_bytes) {
            (Poll::Ready(Err(_)), _) | (_, 0) => {
                self.counters.is_closed.store(true, Ordering::Relaxed);
            }
            (Poll::Ready(Ok(_)), num_bytes) => {
                self.recv_counter.inc_by(num_bytes as u64);
                self.counters
                    .bytes_read
                    .fetch_add(num_bytes.try_into().unwrap(), Ordering::Relaxed);
            }
            _ => {}
        }

        res
    }
}

impl<I: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TrafficCountedStream<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let res = (|| {
            let num_bytes = ready!(Pin::new(&mut self.io).poll_write(cx, buf))?;
            self.sent_counter.inc_by(num_bytes as u64);
            self.counters
                .bytes_written
                .fetch_add(num_bytes.try_into().unwrap(), Ordering::Relaxed);
            Poll::Ready(Ok(num_bytes))
        })();
        match res {
            Poll::Ready(Err(_)) | Poll::Ready(Ok(0)) => {
                self.counters.is_closed.store(true, Ordering::SeqCst);
            }
            _ => {}
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let res = Pin::new(&mut self.io).poll_flush(cx);
        match res {
            Poll::Ready(Err(_)) => {
                self.counters.is_closed.store(true, Ordering::SeqCst);
            }
            _ => {}
        }
        res
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let res = Pin::new(&mut self.io).poll_shutdown(cx);
        match res {
            Poll::Ready(_) => {
                self.counters.is_closed.store(true, Ordering::SeqCst);
            }
            _ => {}
        }
        res
    }
}

impl<I: AsyncRead + AsyncWrite + Unpin> TrafficCountedStream<I> {
    pub fn new(
        io: I,
        counters: Arc<TrafficCounters>,
        sent_counter: IntCounter,
        recv_counter: IntCounter,
    ) -> Self {
        TrafficCountedStream {
            io,
            counters,
            sent_counter,
            recv_counter,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use exogress_common::entities::Ulid;
    use std::io::Cursor;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_counting() {
        let mut buf = vec![0u8; 32768];
        let io = Cursor::new(&mut buf);

        let counters = TrafficCounters::new(
            Ulid::new().to_string().parse().unwrap(),
            Ulid::new().to_string().parse().unwrap(),
        );

        let mut counted_stream = TrafficCountedStream::new(
            io,
            counters.clone(),
            crate::statistics::HTTPS_BYTES_SENT.clone(),
            crate::statistics::HTTPS_BYTES_RECV.clone(),
        );
        let mut result = Vec::new();
        let read_bytes = counted_stream.read_to_end(&mut result).await.unwrap();
        assert_eq!(read_bytes, 32768);

        let to_write = vec![0u8; 1000];
        counted_stream.write_all(&to_write).await.unwrap();

        let counts = counters.flush().unwrap().unwrap();

        assert_eq!(counts.bytes_read, 32768);
        assert_eq!(counts.bytes_written, 1000);
    }
}
