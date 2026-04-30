use async_trait::async_trait;

use crate::{PartyId, Result, SecretU64, SecretVecU64, SessionId};

/// Protocol-level message kinds used in v0.1 frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MessageKind {
    PrivateInput = 1,
    Open = 2,
    Multiply = 3,
}

impl TryFrom<u8> for MessageKind {
    type Error = crate::MpcError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::PrivateInput),
            2 => Ok(Self::Open),
            3 => Ok(Self::Multiply),
            _ => Err(crate::MpcError::Frame("unknown message kind".to_string())),
        }
    }
}

/// One authenticated, session-scoped transport message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetMessage {
    pub session_id: SessionId,
    pub from: PartyId,
    pub to: PartyId,
    pub kind: MessageKind,
    pub counter: u64,
    pub payload: Vec<u8>,
}

/// Async transport abstraction implemented by in-memory and rustls transports.
#[async_trait]
pub trait Transport: Send {
    fn party_id(&self) -> PartyId;
    fn session_id(&self) -> SessionId;
    async fn send(&mut self, message: NetMessage) -> Result<()>;
    async fn recv(&mut self) -> Result<NetMessage>;
}

/// Extension trait for secret-sharing schemes.
pub trait ShareScheme {
    type Secret;
    type SecretVector;
    const PARTY_COUNT: usize;
}

/// Pseudorandom secret sharing source.
pub trait Prss {
    fn next_pair_masks(&self, op: &[u8], counter: u64, len: usize) -> (Vec<u64>, Vec<u64>);
}

/// Protocol extension surface for arithmetic backends.
#[async_trait]
pub trait Protocol {
    async fn mul(&mut self, lhs: &SecretU64, rhs: &SecretU64) -> Result<SecretU64>;
    async fn mul_vec(&mut self, lhs: &SecretVecU64, rhs: &SecretVecU64) -> Result<SecretVecU64>;
}

#[cfg(test)]
mod tests {
    use crate::{PartyId, Rep3ShareU64, SecretU64, WrappingU64};

    #[test]
    fn wrapping_ring_wraps() {
        assert_eq!(WrappingU64::add(u64::MAX, 1), 0);
        assert_eq!(WrappingU64::sub(0, 1), u64::MAX);
        assert_eq!(WrappingU64::mul(u64::MAX, 2), u64::MAX - 1);
    }

    #[test]
    fn local_secret_ops_are_party_scoped() {
        let lhs = SecretU64::from_share(PartyId::P0, Rep3ShareU64::new(1, 2));
        let rhs = SecretU64::from_share(PartyId::P0, Rep3ShareU64::new(3, 4));
        let sum = lhs.add(&rhs).unwrap();
        assert_eq!(sum.share().own(), 4);
        assert_eq!(sum.share().next(), 6);
    }
}
