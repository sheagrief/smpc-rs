use crate::{MpcError, Result};

/// `smpc-rs` v0.1 supports exactly three parties.
pub const PARTY_COUNT: usize = 3;

/// Identifier for one of the three parties in the computation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct PartyId(u8);

impl PartyId {
    pub const P0: Self = Self(0);
    pub const P1: Self = Self(1);
    pub const P2: Self = Self(2);

    pub fn new(value: u8) -> Result<Self> {
        if value < PARTY_COUNT as u8 {
            Ok(Self(value))
        } else {
            Err(MpcError::InvalidPartyId(value))
        }
    }

    pub fn index(self) -> usize {
        self.0 as usize
    }

    pub fn as_u8(self) -> u8 {
        self.0
    }

    pub fn next(self) -> Self {
        Self((self.0 + 1) % PARTY_COUNT as u8)
    }

    pub fn prev(self) -> Self {
        Self((self.0 + PARTY_COUNT as u8 - 1) % PARTY_COUNT as u8)
    }

    pub fn all() -> [Self; PARTY_COUNT] {
        [Self::P0, Self::P1, Self::P2]
    }
}

/// Domain separator for one MPC execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SessionId([u8; 32]);

impl SessionId {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_u64_for_testing(value: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&value.to_be_bytes());
        bytes[8..16].copy_from_slice(&(!value).to_be_bytes());
        Self(bytes)
    }

    pub fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}
