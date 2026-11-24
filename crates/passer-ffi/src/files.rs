//! Files over streams, for apps that think in files rather than bytes.
//!
//! - On the target, a capability declared with [`StreamKind::Upload`] receives the
//!   caller's bytes into a private file; the app's handler then gets its path
//!   ([`CapabilityHandler::receive_file`]) and moves it where it belongs. One declared with
//!   [`StreamKind::Download`] asks the handler for a file ([`CapabilityHandler::provide_file`])
//!   and streams it back.
//! - On the caller, [`crate::PasserDevice::send_file`] and
//!   [`crate::PasserDevice::fetch_file`] do the same from a path.
//!
//! A transfer that breaks leaves nothing behind: partial files are deleted, and a
//! download is renamed to its destination only once the target confirmed it complete.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use passer_bus::StreamIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{CallerInfo, CapabilityHandler, PasserError, TransferProgress};

/// Size of each piece read from disk.
const PIECE: usize = 256 * 1024;
/// Upload limit when a capability declares none.
pub const DEFAULT_MAX_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Progress is reported at most this often (in bytes), plus once at the end.
const PROGRESS_STEP: u64 = 1024 * 1024;

/// Which way the bytes of a stream capability go.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum StreamKind {
    /// The caller sends a file to this device.
    Upload,
    /// The caller gets a file from this device.
    Download,
}

static NEXT: AtomicU64 = AtomicU64::new(0);

/// A fresh name in the device's private `incoming` folder.
pub fn part_path(dir: &Path) -> PathBuf {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    dir.join(format!("{nanos:x}-{n}.part"))
}

struct Progress {
    listener: Option<Arc<dyn TransferProgress>>,
    total: Option<u64>,
    done: u64,
    reported: u64,
}

impl Progress {
    fn new(listener: Option<Arc<dyn TransferProgress>>, total: Option<u64>) -> Self {
        Self {
            listener,
            total,
            done: 0,
            reported: 0,
        }
    }

    fn add(&mut self, n: usize) {
        self.done += n as u64;
        if self.done - self.reported >= PROGRESS_STEP {
            self.report();
        }
    }

    fn report(&mut self) {
        self.reported = self.done;
        if let Some(l) = &self.listener {
            l.progress(self.done, self.total);
        }
    }

    /// The last report, unless the last step already said it.
    fn finish(&mut self) {
        if self.done != self.reported || self.done == 0 {
            self.report();
        }
    }
}

/// Target side of an upload: the caller's bytes into a private file, then the handler.
pub async fn receive(
    io: StreamIo,
    dir: &Path,
    max_bytes: u64,
    handler: &Arc<dyn CapabilityHandler>,
    call: (String, Option<String>, String, CallerInfo),
) -> Result<String, String> {
    let StreamIo { mut incoming, .. } = io;
    tokio::fs::create_dir_all(dir)
        .await
        .map_err(|e| format!("cannot prepare the incoming folder: {e}"))?;
    let path = part_path(dir);
    let result = async {
        let mut file = tokio::fs::File::create(&path)
            .await
            .map_err(|e| format!("cannot create the file: {e}"))?;
        let mut size = 0u64;
        loop {
            match incoming.next().await {
                Ok(Some(bytes)) => {
                    size += bytes.len() as u64;
                    if size > max_bytes {
                        return Err(format!("the file is larger than {max_bytes} bytes"));
                    }
                    file.write_all(&bytes)
                        .await
                        .map_err(|e| format!("cannot write the file: {e}"))?;
                }
                Ok(None) => break,
                Err(e) => return Err(e.to_string()),
            }
        }
        file.flush()
            .await
            .map_err(|e| format!("cannot write the file: {e}"))?;
        drop(file);
        let (capability, target, input, caller) = call;
        handler
            .receive_file(
                capability,
                target,
                input,
                caller,
                path.to_string_lossy().into_owned(),
            )
            .await
            .map_err(|e| e.to_string())
    }
    .await;
    // Whatever the handler did not take, and anything incomplete, goes.
    let _ = tokio::fs::remove_file(&path).await;
    result
}

/// Target side of a download: the handler names a file, its bytes go to the caller.
pub async fn provide(
    io: StreamIo,
    handler: &Arc<dyn CapabilityHandler>,
    call: (String, Option<String>, String, CallerInfo),
) -> Result<u64, String> {
    let StreamIo { outgoing, .. } = io;
    let (capability, target, input, caller) = call;
    let path = handler
        .provide_file(capability, target, input, caller)
        .await
        .map_err(|e| e.to_string())?;
    let mut file = tokio::fs::File::open(&path)
        .await
        .map_err(|e| format!("cannot open the file: {e}"))?;
    let mut buf = vec![0u8; PIECE];
    let mut sent = 0u64;
    loop {
        let n = file
            .read(&mut buf)
            .await
            .map_err(|e| format!("cannot read the file: {e}"))?;
        if n == 0 {
            return Ok(sent);
        }
        outgoing.send(&buf[..n]).await.map_err(|e| e.to_string())?;
        sent += n as u64;
    }
}

/// Caller side of an upload: the file's bytes, with progress. Returns how many were sent.
pub async fn send(
    outgoing: passer_bus::stream::Outgoing,
    path: &Path,
    listener: Option<Arc<dyn TransferProgress>>,
) -> Result<u64, PasserError> {
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(PasserError::storage)?;
    let total = file.metadata().await.ok().map(|m| m.len());
    let mut progress = Progress::new(listener, total);
    let mut buf = vec![0u8; PIECE];
    loop {
        let n = file.read(&mut buf).await.map_err(PasserError::storage)?;
        if n == 0 {
            break;
        }
        if outgoing.send(&buf[..n]).await.is_err() {
            // The target stopped reading: its answer says why.
            break;
        }
        progress.add(n);
    }
    progress.finish();
    Ok(progress.done)
}

/// Caller side of a download into `<destination>.part`. `Ok(false)` if the stream broke.
pub async fn fetch(
    mut incoming: passer_bus::stream::Incoming,
    part: &Path,
    listener: Option<Arc<dyn TransferProgress>>,
) -> Result<bool, PasserError> {
    let mut file = tokio::fs::File::create(part)
        .await
        .map_err(PasserError::storage)?;
    let mut progress = Progress::new(listener, None);
    loop {
        match incoming.next().await {
            Ok(Some(bytes)) => {
                file.write_all(&bytes).await.map_err(PasserError::storage)?;
                progress.add(bytes.len());
            }
            Ok(None) => break,
            Err(_) => return Ok(false),
        }
    }
    file.flush().await.map_err(PasserError::storage)?;
    progress.finish();
    Ok(true)
}
