use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::Mutex;

use vsbmas_core::events::{Event, EventEnvelope};

pub struct Audit {
    writer: Mutex<BufWriter<File>>,
    seq: AtomicU64,
    pub path: PathBuf,
}

impl Audit {
    pub async fn open(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let seq = match tokio::fs::read_to_string(&path).await {
            Ok(s) => s.lines().filter(|l| !l.is_empty()).count() as u64,
            Err(_) => 0,
        };

        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;
        Ok(Self {
            writer: Mutex::new(BufWriter::new(f)),
            seq: AtomicU64::new(seq),
            path,
        })
    }

    pub async fn emit(&self, event: Event, boot_id: &str) -> anyhow::Result<EventEnvelope> {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let envelope = EventEnvelope::wrap(seq, boot_id.to_string(), event);
        let mut w = self.writer.lock().await;
        let line = serde_json::to_string(&envelope)?;
        w.write_all(line.as_bytes()).await?;
        w.write_all(b"\n").await?;
        w.flush().await?;
        Ok(envelope)
    }
}
