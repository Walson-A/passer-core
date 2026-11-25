//! Raw byte streams for Swift and Kotlin apps: `PasserDevice::connect_stream`.
//!
//! What arrives is handed to a [`StreamSink`] the app implements, piece by piece (a few
//! KiB to 256 KiB each, never one call per byte); what the app sends goes through the
//! [`StreamHandle`]. The bytes are the capability's own protocol: the core neither frames
//! nor reads them, and pieces need not line up with the app's messages.

use std::sync::{Arc, Mutex};

use passer_bus::Response;
use passer_bus::stream::Outgoing;

use crate::PasserError;

/// Receives a stream's bytes. Implemented by the app.
#[uniffi::export(with_foreign)]
pub trait StreamSink: Send + Sync {
    /// The next piece the other device sent, in order.
    fn on_data(&self, bytes: Vec<u8>);
    /// The other device is done sending (`error` is `None`), or the stream broke
    /// (`error` says why). No `on_data` follows.
    fn on_closed(&self, error: Option<String>);
}

/// An open stream, as the app holds it.
#[derive(uniffi::Object)]
pub struct StreamHandle {
    outgoing: tokio::sync::Mutex<Option<Outgoing>>,
    done: tokio::sync::Mutex<Option<tokio::task::JoinHandle<anyhow::Result<Response>>>>,
    receiving: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl StreamHandle {
    pub(crate) fn start(open: passer_node::OpenStream, sink: Arc<dyn StreamSink>) -> Arc<Self> {
        let passer_node::OpenStream { io, done } = open;
        let passer_bus::StreamIo {
            mut incoming,
            outgoing,
        } = io;
        let receiving = tokio::spawn(async move {
            loop {
                match incoming.next().await {
                    Ok(Some(bytes)) => sink.on_data(bytes),
                    Ok(None) => {
                        sink.on_closed(None);
                        return;
                    }
                    Err(e) => {
                        sink.on_closed(Some(e.to_string()));
                        return;
                    }
                }
            }
        });
        Arc::new(Self {
            outgoing: tokio::sync::Mutex::new(Some(outgoing)),
            done: tokio::sync::Mutex::new(Some(done)),
            receiving: Mutex::new(Some(receiving)),
        })
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl StreamHandle {
    /// Sends bytes to the other device (any size: the core splits them). Waits while the
    /// other side is slower. Fails once the stream is closed.
    pub async fn send(&self, bytes: Vec<u8>) -> Result<(), PasserError> {
        let outgoing = self.outgoing.lock().await;
        let out = outgoing.as_ref().ok_or_else(|| PasserError::Invalid {
            message: "this side of the stream is closed".into(),
        })?;
        out.send(&bytes).await.map_err(|e| PasserError::Network {
            message: e.to_string(),
        })
    }

    /// This side is done sending; the other device may still send until it closes.
    pub async fn close(&self) {
        self.outgoing.lock().await.take();
    }

    /// Ends everything at once: no more sending, no more `on_data`.
    pub async fn cancel(&self) {
        self.outgoing.lock().await.take();
        if let Some(task) = self.receiving.lock().expect("receiving lock").take() {
            task.abort();
        }
        if let Some(task) = self.done.lock().await.take() {
            task.abort();
        }
    }

    /// The other device's final answer (JSON), once the stream ended: its result, or a
    /// typed refusal such as `interrupted` when its user pressed stop. Call it once.
    pub async fn result(&self) -> Result<String, PasserError> {
        let task = self
            .done
            .lock()
            .await
            .take()
            .ok_or_else(|| PasserError::Invalid {
                message: "the result was already taken, or the stream was cancelled".into(),
            })?;
        match task.await {
            Ok(Ok(response)) => crate::answer(response),
            Ok(Err(e)) => Err(PasserError::Network {
                message: format!("{e:#}"),
            }),
            Err(e) => Err(PasserError::Network {
                message: e.to_string(),
            }),
        }
    }
}
