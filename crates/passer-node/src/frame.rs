//! Length-prefixed JSON frames on a QUIC stream.
//!
//! Every frame is a 4-byte big-endian length followed by that many bytes of JSON. The
//! length is checked against a limit *before* allocating, so a peer cannot make us
//! reserve gigabytes by announcing them.

use iroh::endpoint::{RecvStream, SendStream};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Largest frame accepted for control messages and calls.
pub const MAX_FRAME: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame of {0} bytes exceeds the {MAX_FRAME}-byte limit")]
    TooLarge(usize),
    #[error("stream error: {0}")]
    Stream(String),
    #[error("malformed frame: {0}")]
    Malformed(#[from] serde_json::Error),
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

pub async fn read_frame<T: DeserializeOwned>(recv: &mut RecvStream) -> Result<T, FrameError> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len)
        .await
        .map_err(|e| FrameError::Stream(e.to_string()))?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| FrameError::Stream(e.to_string()))?;
    Ok(serde_json::from_slice(&buf)?)
}
