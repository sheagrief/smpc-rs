use thiserror::Error;

/// Result type used across the workspace.
pub type Result<T> = std::result::Result<T, MpcError>;

/// Error type used by protocol, transport, and frame validation code.
#[derive(Debug, Error)]
pub enum MpcError {
    #[error("invalid party id {0}; expected 0, 1, or 2")]
    InvalidPartyId(u8),
    #[error("expected exactly three parties")]
    WrongPartyCount,
    #[error("party {party} cannot provide private input for owner {owner}")]
    NotInputOwner { party: u8, owner: u8 },
    #[error("length mismatch: left={left}, right={right}")]
    LengthMismatch { left: usize, right: usize },
    #[error("invalid share shape: {0}")]
    InvalidShareShape(&'static str),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("frame error: {0}")]
    Frame(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("session mismatch")]
    SessionMismatch,
    #[error("peer mismatch: expected {expected}, got {actual}")]
    PeerMismatch { expected: u8, actual: u8 },
    #[error("message counter mismatch: expected {expected}, got {actual}")]
    CounterMismatch { expected: u64, actual: u64 },
    #[error("unexpected message kind: expected {expected:?}, got {actual:?}")]
    UnexpectedMessageKind {
        expected: crate::MessageKind,
        actual: crate::MessageKind,
    },
    #[error("tls error: {0}")]
    Tls(String),
    #[error("io error: {0}")]
    Io(String),
}

impl From<std::io::Error> for MpcError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}
