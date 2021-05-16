use chrono::Utc;
use core::mem;
use exogress_server_common::logging::{BodyLog, BodyStatusLog, HttpBodyLog, LogMessage};
use futures::StreamExt;
use std::{sync::Arc, time::Duration};

pub fn save_body_info_to_log_message(
    body: hyper::Body,
    shared_log_message: Arc<parking_lot::Mutex<LogMessageSendOnDrop>>,
    body_entry: HttpBodyLog,
) -> hyper::Body {
    let mut peekable = Box::pin(body.peekable());

    let mut len: usize = 0;

    let mut started_at = None;

    let instrumented = async_stream::stream! {
        while let Some(buf_res) = peekable.next().await {
            if started_at.is_none() {
                started_at = Some(Utc::now());
            }

            match buf_res {
                Ok(buf) => {
                    len += buf.len();
                    let next_ref = peekable.as_mut().peek().await;

                    if next_ref.is_none() {
                        let started_at = started_at.unwrap();
                        let ended_at = Utc::now();
                        let time_taken = (ended_at - started_at).to_std().unwrap_or_else(|_| Duration::from_secs(0));

                        let millis = time_taken.as_nanos() as f64;
                        let bytes_per_sec: f64 = if millis > 0.0 {
                            1_000_000_000.0 * (len as f64) / millis
                        } else {
                            0.0
                        };

                        *body_entry.0.lock() = Some(BodyLog {
                            started_at,
                            ended_at,
                            time_taken_ms: time_taken,
                            transferred_bytes: len as u32,
                            bytes_per_sec: bytes_per_sec as f32,
                            status: BodyStatusLog::Finished,
                        });

                        yield Ok::<_, hyper::Error>(buf);

                        break;
                    } else {
                        yield Ok(buf);
                    }
                },
                Err(e) => {
                    let started_at = started_at.unwrap();
                    let ended_at = Utc::now();
                    let time_taken = (ended_at - started_at).to_std().unwrap_or_else(|_| Duration::from_secs(0));

                    let millis = time_taken.as_nanos() as f64;

                    let bytes_per_sec: f64 = if millis > 0.0 {
                        1_000_000_000.0 * (len as f64) / millis
                    } else {
                        0.0
                    };


                    *body_entry.0.lock() = Some(BodyLog {
                        started_at,
                        ended_at,
                        time_taken_ms: time_taken,
                        transferred_bytes: len as u32,
                        bytes_per_sec: bytes_per_sec as f32,
                        status: BodyStatusLog::Cancelled { error: e.to_string() },
                    });

                    yield Err(e);

                    break;
                }
            }
        };

        mem::drop(shared_log_message);
    };

    hyper::Body::wrap_stream(instrumented)
}

pub struct LogMessageSendOnDrop {
    inner: Option<LogMessage>,
    send_tx: tokio::sync::mpsc::Sender<LogMessage>,
}

impl AsMut<LogMessage> for LogMessageSendOnDrop {
    fn as_mut(&mut self) -> &mut LogMessage {
        self.inner.as_mut().unwrap()
    }
}

impl LogMessageSendOnDrop {
    pub fn new(log_message: LogMessage, send_tx: tokio::sync::mpsc::Sender<LogMessage>) -> Self {
        LogMessageSendOnDrop {
            inner: Some(log_message),
            send_tx,
        }
    }
}

impl Drop for LogMessageSendOnDrop {
    fn drop(&mut self) {
        if let Some(mut msg) = self.inner.take() {
            let now = Utc::now();
            msg.ended_at = Some(now);
            msg.time_taken_ms = Some(
                (now - msg.started_at)
                    .to_std()
                    .unwrap_or_else(|_| Duration::from_secs(0)),
            );
            msg.set_message_string();

            if let Err(e) = self.send_tx.try_send(msg) {
                error!("failed to send log message on drop: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::Utc;
    use exogress_common::entities::Ulid;
    use exogress_server_common::logging::{RequestMetaInfo, ResponseMetaInfo};
    use futures::{channel::mpsc, StreamExt};
    use std::{mem, sync::Arc};

    #[tokio::test]
    async fn test_send_on_drop() {
        let msg = LogMessage {
            request_id: Ulid::new(),
            gw_location: Default::default(),
            remote_addr: "127.0.0.1".parse().unwrap(),
            account_unique_id: Default::default(),
            project: "prj".parse().unwrap(),
            project_unique_id: Default::default(),
            mount_point: "mnt".parse().unwrap(),
            protocol: Default::default(),
            request: RequestMetaInfo {
                headers: Default::default(),
                body: Default::default(),
                url: Default::default(),
                method: Default::default(),
            },
            response: ResponseMetaInfo {
                headers: Default::default(),
                body: Default::default(),
                compression: None,
                status_code: None,
            },
            steps: vec![],
            facts: Arc::new(Default::default()),
            str: None,
            timestamp: Utc::now(),
            started_at: Utc::now(),
            ended_at: None,
            time_taken_ms: None,
        };

        let (send_tx, mut send_rx) = mpsc::channel(16);

        let will_send = LogMessageSendOnDrop {
            inner: Some(msg),
            send_tx,
        };

        assert!(send_rx.try_next().is_err());

        mem::drop(will_send);

        send_rx.next().await.unwrap();
    }
}
