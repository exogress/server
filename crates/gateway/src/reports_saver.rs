use core::mem;
use exogress_common::entities::Ulid;
use exogress_server_common::assistant::WsFromGwMessage;
use futures_util::{SinkExt, StreamExt};
use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tempfile::NamedTempFile;
use tokio::{
    io::AsyncWriteExt,
    sync::oneshot,
    time::{sleep, Instant},
};

/// Saves reports to file system if not enough of capacity in the cloud
pub struct Inner {
    pool: Vec<tokio::sync::mpsc::Sender<WsFromGwMessage>>,
    current_idx: usize,
    pool_size: usize,
    stop_txs: Vec<tokio::sync::oneshot::Sender<()>>,
    termination_semaphore: Arc<tokio::sync::Semaphore>,
}

#[derive(Clone)]
pub struct FsReportsSaver {
    dir: PathBuf,
    inner: Arc<parking_lot::Mutex<Inner>>,
}

struct OpenedSaver {
    tempfile: NamedTempFile,
    writer: tokio_util::codec::FramedWrite<tokio::fs::File, tokio_util::codec::LinesCodec>,
    dir: PathBuf,
    saved_bytes: u64,
}

impl OpenedSaver {
    async fn new(dir: impl AsRef<Path>) -> anyhow::Result<OpenedSaver> {
        let mut tmp_path = dir.as_ref().to_path_buf();
        tmp_path.push("tmp");

        let tempfile = tokio::task::spawn_blocking(|| NamedTempFile::new_in(tmp_path)).await??;

        let (reopened, tempfile) = tokio::task::spawn_blocking(|| {
            let reopened = tempfile.reopen()?;
            Ok::<_, io::Error>((reopened, tempfile))
        })
        .await??;

        let file = tokio::fs::File::from_std(reopened);
        let newline_delimited = tokio_util::codec::LinesCodec::new();

        Ok(OpenedSaver {
            tempfile,
            writer: tokio_util::codec::FramedWrite::new(file, newline_delimited),
            dir: dir.as_ref().to_path_buf(),
            saved_bytes: 0,
        })
    }

    // Returns the number of bytes stored in the file
    async fn write(&mut self, batch: WsFromGwMessage) -> anyhow::Result<u64> {
        let bytes = serde_json::to_string(&batch)?;

        self.saved_bytes += bytes.len() as u64;
        self.writer.send(bytes).await?;

        Ok(self.saved_bytes)
    }

    fn file_size(&self) -> u64 {
        self.saved_bytes
    }

    async fn reopen(&mut self) -> anyhow::Result<()> {
        let mut old = mem::replace(self, OpenedSaver::new(self.dir.clone()).await?);

        let chunk_id = Ulid::new();
        let mut out_path = old.dir.clone();
        out_path.push("chunks");
        out_path.push(chunk_id.to_string());

        futures::SinkExt::<String>::close(&mut old.writer).await?;
        let mut file = old.writer.into_inner();
        file.sync_data().await?;
        file.flush().await?;
        mem::drop(file);

        let tempfile = old.tempfile;

        tokio::task::spawn_blocking(|| tempfile.persist(out_path)).await??;

        Ok(())
    }
}

impl FsReportsSaver {
    pub async fn new(dir: PathBuf, pool_size: usize, max_file_size: u64) -> anyhow::Result<Self> {
        let mut chunks_dir = dir.clone();
        chunks_dir.push("chunks");
        tokio::fs::create_dir_all(chunks_dir).await?;

        let mut tmp_dir = dir.clone();
        tmp_dir.push("tmp");
        tokio::fs::create_dir_all(tmp_dir).await?;

        let mut pool = Vec::new();
        let mut stop_txs = Vec::new();

        let termination_semaphore = Arc::new(tokio::sync::Semaphore::new(pool_size));

        for i in 0..pool_size {
            let running = termination_semaphore.clone().acquire_owned().await;

            let (stop_tx, mut stop_rx) = oneshot::channel();

            stop_txs.push(stop_tx);

            let (tx, mut rx) = tokio::sync::mpsc::channel(1);
            pool.push(tx);

            let mut saver = OpenedSaver::new(&dir).await?;

            tokio::spawn(async move {
                const MAX_UNSAVED_REPORT_TIME: Duration = Duration::from_secs(10);

                let r = async move {
                    let flush_on_ttl = sleep(MAX_UNSAVED_REPORT_TIME);

                    tokio::pin!(flush_on_ttl);

                    loop {
                        tokio::select! {
                            next = rx.recv() => {
                                if let Some(msg) = next {
                                    let file_size = saver.write(msg).await?;

                                    if file_size > max_file_size {
                                        saver.reopen().await?;
                                    }
                                } else {
                                    break;
                                }
                            },
                            _ = &mut flush_on_ttl => {
                                // time's up. pack and create new
                                if saver.file_size() > 0 {
                                    info!("Flush on reaching the TTL");
                                    saver.reopen().await?;
                                }
                                flush_on_ttl.as_mut().reset(Instant::now() + MAX_UNSAVED_REPORT_TIME)
                            },
                            _ = &mut stop_rx => {
                                break;
                            },
                        }
                    }

                    Ok::<_, anyhow::Error>(saver)
                }
                .await;

                warn!(
                    "reports FS saver {} stopped. Error = {:?}",
                    i,
                    r.as_ref().err()
                );

                if let Ok(mut saver) = r {
                    if saver.file_size() > 0 {
                        if let Err(e) = saver.reopen().await {
                            error!("Could not persist reports on closing: {}", e);
                        }
                    }
                }

                mem::drop(running);
            });
        }

        Ok(FsReportsSaver {
            dir,
            inner: Arc::new(parking_lot::Mutex::new(Inner {
                pool,
                current_idx: 0,
                pool_size,
                stop_txs,
                termination_semaphore,
            })),
        })
    }

    pub async fn save(&self, batch: WsFromGwMessage) -> anyhow::Result<()> {
        let pool = {
            let mut inner = self.inner.lock();
            inner.current_idx = (inner.current_idx + 1) % inner.pool_size;
            inner.pool[inner.current_idx].clone()
        };

        pool.send(batch).await?;

        Ok(())
    }

    pub async fn close(&self) {
        let mut locked = self.inner.lock();

        for tx in locked.stop_txs.drain(..) {
            tx.send(()).ok();
        }
        let pool_size = locked.pool_size;

        let termination_semaphore = locked.termination_semaphore.clone();
        mem::drop(locked);

        info!("Wait for all reports FS writers termination");
        let _ = termination_semaphore
            .acquire_many(pool_size as u32)
            .await
            .unwrap();
        info!("All reports FS writers terminated");
    }

    pub async fn outstanding_flusher(
        &self,
        gw_to_assistant_messages_tx: tokio::sync::mpsc::Sender<WsFromGwMessage>,
    ) -> anyhow::Result<()> {
        let mut chunks_dir = self.dir.clone();
        chunks_dir.push("chunks");
        tokio::fs::create_dir_all(&chunks_dir).await?;

        loop {
            let mut dir = tokio::fs::read_dir(&chunks_dir).await?;

            let mut any_found = false;

            while let Some(dir_entry) = dir.next_entry().await? {
                let ulid_result = dir_entry
                    .path()
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .parse::<Ulid>();
                let filename = match ulid_result {
                    Err(_e) => {
                        continue;
                    }
                    Ok(r) => r,
                };

                any_found = true;

                info!("start flushing: {}", filename);

                let res = async {
                    let file = tokio::fs::File::open(dir_entry.path()).await?;
                    tokio::fs::remove_file(dir_entry.path()).await?;

                    let newline_delimited = tokio_util::codec::LinesCodec::new();
                    let mut reader = tokio_util::codec::FramedRead::new(file, newline_delimited);
                    let tx = gw_to_assistant_messages_tx.clone();

                    'lines: while let Some(msg_result) = reader.next().await {
                        let permit = loop {
                            // this code will never blocks if the query is busy. This reduces the
                            // amount of file operations

                            // FIXME: use tx from Err response
                            match tx.clone().try_reserve_owned() {
                                Err(_e) => {
                                    // wait a bit if channel is busy
                                    sleep(Duration::from_millis(50)).await;
                                }
                                Ok(permit) => {
                                    break permit;
                                }
                            }
                        };

                        match msg_result {
                            Ok(msg) => match serde_json::from_str(&msg) {
                                Ok(r) => {
                                    permit.send(r);
                                    crate::statistics::OUTSTANDING_REPORTS_SENT.inc();
                                }
                                Err(e) => {
                                    error!("Error reading from outstanding report: {}", e);
                                    continue 'lines;
                                }
                            },
                            Err(e) => {
                                error!("Error reading from outstanding report: {}", e);
                                continue 'lines;
                            }
                        }
                    }

                    Ok::<_, anyhow::Error>(())
                }
                .await;

                // FIXME: if error occurred, all outstanding data from the file should be written
                // to another file

                if let Err(e) = res {
                    error!("error flushing outstanding statistics: {}", e);
                }
            }

            if !any_found {
                sleep(Duration::from_secs(1)).await;
            }
        }
    }
}
