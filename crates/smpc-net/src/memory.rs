use async_trait::async_trait;
use smpc_core::{MpcError, NetMessage, PartyId, Result, SessionId, Transport};
use tokio::sync::mpsc;

/// A deterministic in-memory network for simulator tests.
pub struct InMemoryNetwork {
    session_id: SessionId,
}

impl InMemoryNetwork {
    pub fn new(session_id: SessionId) -> Self {
        Self { session_id }
    }

    pub fn transports(self) -> [InMemoryTransport; 3] {
        let (tx0, rx0) = mpsc::channel(128);
        let (tx1, rx1) = mpsc::channel(128);
        let (tx2, rx2) = mpsc::channel(128);
        let senders = [tx0, tx1, tx2];
        [
            InMemoryTransport::new(PartyId::P0, self.session_id, senders.clone(), rx0),
            InMemoryTransport::new(PartyId::P1, self.session_id, senders.clone(), rx1),
            InMemoryTransport::new(PartyId::P2, self.session_id, senders, rx2),
        ]
    }
}

/// In-memory `Transport` implementation.
pub struct InMemoryTransport {
    party_id: PartyId,
    session_id: SessionId,
    senders: [mpsc::Sender<NetMessage>; 3],
    receiver: mpsc::Receiver<NetMessage>,
}

impl InMemoryTransport {
    fn new(
        party_id: PartyId,
        session_id: SessionId,
        senders: [mpsc::Sender<NetMessage>; 3],
        receiver: mpsc::Receiver<NetMessage>,
    ) -> Self {
        Self {
            party_id,
            session_id,
            senders,
            receiver,
        }
    }
}

#[async_trait]
impl Transport for InMemoryTransport {
    fn party_id(&self) -> PartyId {
        self.party_id
    }

    fn session_id(&self) -> SessionId {
        self.session_id
    }

    async fn send(&mut self, message: NetMessage) -> Result<()> {
        if message.session_id != self.session_id {
            return Err(MpcError::SessionMismatch);
        }
        if message.from != self.party_id {
            return Err(MpcError::PeerMismatch {
                expected: self.party_id.as_u8(),
                actual: message.from.as_u8(),
            });
        }
        self.senders[message.to.index()]
            .send(message)
            .await
            .map_err(|_| MpcError::Transport("in-memory receiver closed".to_string()))
    }

    async fn recv(&mut self) -> Result<NetMessage> {
        let message = self
            .receiver
            .recv()
            .await
            .ok_or_else(|| MpcError::Transport("in-memory network closed".to_string()))?;
        if message.session_id != self.session_id {
            return Err(MpcError::SessionMismatch);
        }
        if message.to != self.party_id {
            return Err(MpcError::PeerMismatch {
                expected: self.party_id.as_u8(),
                actual: message.to.as_u8(),
            });
        }
        Ok(message)
    }
}
