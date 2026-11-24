//! Length-prefixed JSON frames on a QUIC stream.
//!
//! Every frame is a 4-byte big-endian length followed by that many bytes of JSON. The
//! length is checked against a limit *before* allocating, so a peer cannot make us
//! reserve gigabytes by announcing them.
//!
//! Streams add binary chunks: the same 4-byte length, then raw bytes, at most
//! [`passer_bus::stream::MAX_CHUNK`]. A zero length ends the chunks, so a stream that
//! simply stops is told apart from one that finished.

use passer_bus::stream::MAX_CHUNK;

use iroh::endpoint::{RecvStream, SendStream};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Largest frame accepted for control messages and calls.
pub const MAX_FRAME: usize = 1024 * 1024;
/// How long a peer may take to send a whole request.
pub const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
/// How long a caller waits for an answer: a human approval alone may take a minute.
pub const ANSWER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(150);
/// How long a stream may stay silent before it is considered broken.
pub const STREAM_IDLE: std::time::Duration = std::time::Duration::from_secs(60);
/// How long a caller waits for the target's side of a stream: the longest lease. The
/// target sends nothing while it receives an upload; it ends when its lease ends.
pub const STREAM_ANSWER_IDLE: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame of {0} bytes exceeds the {MAX_FRAME}-byte limit")]
    TooLarge(usize),
    #[error("stream error: {0}")]
    Stream(String),
    #[error("malformed frame: {0}")]
    Malformed(#[from] serde_json::Error),
    #[error("the peer was too slow")]
    Timeout,
}

pub async fn write_frame<T: Serialize>(send: &mut SendStream, value: &T) -> Result<(), FrameError> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_FRAME {
        return Err(FrameError::TooLarge(bytes.len()));
    }
    send.write_all(&(bytes.len() as u32).to_be_bytes())
        .await
        .map_err(|e| FrameError::Stream(e.to_string()))?;
    send.write_all(&bytes)
        .await
        .map_err(|e| FrameError::Stream(e.to_string()))?;
    Ok(())
}

/// One binary chunk of a stream. Empty chunks are not sent: zero means the end.
pub async fn write_chunk(send: &mut SendStream, bytes: &[u8]) -> Result<(), FrameError> {
    if bytes.is_empty() {
        return Ok(());
    }
    if bytes.len() > MAX_CHUNK {
        return Err(FrameError::TooLarge(bytes.len()));
    }
    send.write_all(&(bytes.len() as u32).to_be_bytes())
        .await
        .map_err(|e| FrameError::Stream(e.to_string()))?;
    send.write_all(bytes)
        .await
        .map_err(|e| FrameError::Stream(e.to_string()))
}

/// Marks the end of this side's chunks.
pub async fn write_end(send: &mut SendStream) -> Result<(), FrameError> {
    send.write_all(&0u32.to_be_bytes())
        .await
        .map_err(|e| FrameError::Stream(e.to_string()))
}

/// The next chunk, `None` at the end marker. A peer silent for `idle` is a broken stream.
pub async fn read_chunk(
    recv: &mut RecvStream,
    idle: std::time::Duration,
) -> Result<Option<Vec<u8>>, FrameError> {
    tokio::time::timeout(idle, async {
        let mut len = [0u8; 4];
        recv.read_exact(&mut len)
            .await
            .map_err(|e| FrameError::Stream(e.to_string()))?;
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 {
            return Ok(None);
        }
        if len > MAX_CHUNK {
            return Err(FrameError::TooLarge(len));
        }
        let mut buf = vec![0u8; len];
        recv.read_exact(&mut buf)
            .await
            .map_err(|e| FrameError::Stream(e.to_string()))?;
        Ok(Some(buf))
    })
    .await
    .map_err(|_| FrameError::Timeout)?
}

pub async fn read_frame<T: DeserializeOwned>(recv: &mut RecvStream) -> Result<T, FrameError> {
    read_frame_within(recv, READ_TIMEOUT).await
}

/// Like [`read_frame`], with an explicit time limit (for answers that may wait on a human).
pub async fn read_frame_within<T: DeserializeOwned>(
    recv: &mut RecvStream,
    limit: std::time::Duration,
) -> Result<T, FrameError> {
    tokio::time::timeout(limit, read_frame_inner(recv))
        .await
        .map_err(|_| FrameError::Timeout)?
}

/// Reads the announced length incrementally: memory grows with the bytes actually
/// received, not with what the peer claims it will send.
async fn read_frame_inner<T: DeserializeOwned>(recv: &mut RecvStream) -> Result<T, FrameError> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len)
        .await
        .map_err(|e| FrameError::Stream(e.to_string()))?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    let mut buf = Vec::with_capacity(len.min(16 * 1024));
    let mut chunk = [0u8; 16 * 1024];
    while buf.len() < len {
        let want = (len - buf.len()).min(chunk.len());
        match recv
            .read(&mut chunk[..want])
            .await
            .map_err(|e| FrameError::Stream(e.to_string()))?
        {
            Some(n) => buf.extend_from_slice(&chunk[..n]),
            None => return Err(FrameError::Stream("stream ended inside a frame".into())),
        }
    }
    Ok(serde_json::from_slice(&buf)?)
}
