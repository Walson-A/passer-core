//! Bytes flowing both ways once a stream capability has been accepted.
//!
//! The bus does not know about QUIC: the transport feeds [`Incoming`] with what the peer
//! sends and drains [`Outgoing`] towards it. Both are bounded, so a slow side slows the
//! other instead of filling memory.
//!
//! An incoming stream ends in one of two ways, and a module must tell them apart: the
//! peer said it was done ([`Incoming::next`] returns `Ok(None)`), or the stream broke
//! (`Err(StreamBroken)`: the peer vanished, was removed, or stopped talking). A file that
//! arrives through a broken stream is incomplete and must be discarded.

use tokio::sync::mpsc;

/// Largest chunk a peer may send in one piece.
pub const MAX_CHUNK: usize = 256 * 1024;
/// Chunks buffered in each direction before the sender waits.
const BUFFERED: usize = 8;

/// What the transport hands to [`Incoming`].
#[derive(Debug)]
pub enum Chunk {
    Data(Vec<u8>),
    /// The peer finished sending.
    End,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the stream broke before the peer finished sending")]
pub struct StreamBroken;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the peer no longer reads this stream")]
pub struct StreamClosed;

/// What the peer sends.
pub struct Incoming {
    rx: mpsc::Receiver<Chunk>,
    ended: bool,
}

impl Incoming {
    /// The next piece, `Ok(None)` once the peer said it is done.
    pub async fn next(&mut self) -> Result<Option<Vec<u8>>, StreamBroken> {
        if self.ended {
            return Ok(None);
        }
        match self.rx.recv().await {
            Some(Chunk::Data(bytes)) => Ok(Some(bytes)),
            Some(Chunk::End) => {
                self.ended = true;
                Ok(None)
            }
            None => Err(StreamBroken),
        }
    }
}

/// What this side sends. Dropping it tells the peer this side is done.
pub struct Outgoing {
    tx: mpsc::Sender<Vec<u8>>,
}

impl Outgoing {
    /// Sends bytes, split into chunks the peer accepts; waits while the peer is slower.
    pub async fn send(&self, bytes: &[u8]) -> Result<(), StreamClosed> {
        for piece in bytes.chunks(MAX_CHUNK) {
            self.tx
                .send(piece.to_vec())
                .await
                .map_err(|_| StreamClosed)?;
        }
        Ok(())
    }
}

/// Both directions, as a module sees them.
pub struct StreamIo {
    pub incoming: Incoming,
    pub outgoing: Outgoing,
}

/// The other ends, held by the transport.
pub struct StreamPeer {
    /// Feed what arrives from the network; drop it without sending [`Chunk::End`] if the
    /// network stream breaks.
    pub to_module: mpsc::Sender<Chunk>,
    /// What to send to the network; `None` once the module is done sending.
    pub from_module: mpsc::Receiver<Vec<u8>>,
}

/// A connected pair: the module's side and the transport's side.
pub fn pair() -> (StreamIo, StreamPeer) {
    let (to_module, rx) = mpsc::channel(BUFFERED);
    let (tx, from_module) = mpsc::channel(BUFFERED);
    (
        StreamIo {
            incoming: Incoming { rx, ended: false },
            outgoing: Outgoing { tx },
        },
        StreamPeer {
            to_module,
            from_module,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn end_and_break_are_different() {
        let (mut io, peer) = pair();
        peer.to_module
            .send(Chunk::Data(b"ab".to_vec()))
            .await
            .unwrap();
        peer.to_module.send(Chunk::End).await.unwrap();
        assert_eq!(io.incoming.next().await, Ok(Some(b"ab".to_vec())));
        assert_eq!(io.incoming.next().await, Ok(None));
        assert_eq!(io.incoming.next().await, Ok(None));

        let (mut io, peer) = pair();
        peer.to_module
            .send(Chunk::Data(b"ab".to_vec()))
            .await
            .unwrap();
        drop(peer);
        assert_eq!(io.incoming.next().await, Ok(Some(b"ab".to_vec())));
        assert_eq!(io.incoming.next().await, Err(StreamBroken));
    }

    #[tokio::test]
    async fn large_sends_are_split() {
        let (io, mut peer) = pair();
        let big = vec![7u8; MAX_CHUNK * 2 + 10];
        let sender = tokio::spawn(async move {
            io.outgoing.send(&big).await.unwrap();
        });
        let mut sizes = Vec::new();
        while let Some(c) = peer.from_module.recv().await {
            sizes.push(c.len());
        }
        sender.await.unwrap();
        assert_eq!(sizes, vec![MAX_CHUNK, MAX_CHUNK, 10]);
    }
}
