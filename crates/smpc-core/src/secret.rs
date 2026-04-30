use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{MpcError, PartyId, Result, SessionId, WrappingU64};

/// Local configuration for one party.
#[derive(Clone)]
pub struct MpcConfig {
    pub party_id: PartyId,
    pub session_id: SessionId,
    /// Optional deterministic seed for tests and reproducible examples.
    pub rng_seed: Option<[u8; 32]>,
    /// PRSS seed shared with the previous party.
    pub prss_prev_seed: [u8; 32],
    /// PRSS seed shared with the next party.
    pub prss_next_seed: [u8; 32],
}

impl core::fmt::Debug for MpcConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MpcConfig")
            .field("party_id", &self.party_id)
            .field("session_id", &self.session_id)
            .field("rng_seed", &self.rng_seed.as_ref().map(|_| "[redacted]"))
            .field("prss_prev_seed", &"[redacted]")
            .field("prss_next_seed", &"[redacted]")
            .finish()
    }
}

impl MpcConfig {
    pub fn new(
        party_id: PartyId,
        session_id: SessionId,
        prss_prev_seed: [u8; 32],
        prss_next_seed: [u8; 32],
    ) -> Self {
        Self {
            party_id,
            session_id,
            rng_seed: None,
            prss_prev_seed,
            prss_next_seed,
        }
    }

    pub fn with_rng_seed(mut self, seed: [u8; 32]) -> Self {
        self.rng_seed = Some(seed);
        self
    }
}

/// Public `u64` value in the v0.1 ring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicU64(pub u64);

/// One party's replicated share `(x_i, x_{i+1})`.
///
/// This intentionally does not implement `Debug`; shares can be sensitive.
#[derive(Clone, Copy, Eq, PartialEq, Zeroize)]
pub struct Rep3ShareU64 {
    own: u64,
    next: u64,
}

impl Rep3ShareU64 {
    pub fn new(own: u64, next: u64) -> Self {
        Self { own, next }
    }

    pub fn own(self) -> u64 {
        self.own
    }

    pub fn next(self) -> u64 {
        self.next
    }

    pub fn add_share(self, rhs: Self) -> Self {
        Self::new(
            WrappingU64::add(self.own, rhs.own),
            WrappingU64::add(self.next, rhs.next),
        )
    }

    pub fn sub_share(self, rhs: Self) -> Self {
        Self::new(
            WrappingU64::sub(self.own, rhs.own),
            WrappingU64::sub(self.next, rhs.next),
        )
    }

    pub fn mul_public(self, rhs: u64) -> Self {
        Self::new(
            WrappingU64::mul(self.own, rhs),
            WrappingU64::mul(self.next, rhs),
        )
    }

    pub fn add_public(self, party_id: PartyId, rhs: u64) -> Self {
        match party_id.index() {
            0 => Self::new(WrappingU64::add(self.own, rhs), self.next),
            2 => Self::new(self.own, WrappingU64::add(self.next, rhs)),
            _ => self,
        }
    }

    pub fn sub_public(self, party_id: PartyId, rhs: u64) -> Self {
        match party_id.index() {
            0 => Self::new(WrappingU64::sub(self.own, rhs), self.next),
            2 => Self::new(self.own, WrappingU64::sub(self.next, rhs)),
            _ => self,
        }
    }
}

/// A local handle to one secret shared `u64`.
///
/// This intentionally does not implement `Debug`.
#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct SecretU64 {
    #[zeroize(skip)]
    party_id: PartyId,
    share: Rep3ShareU64,
}

impl SecretU64 {
    pub fn from_share(party_id: PartyId, share: Rep3ShareU64) -> Self {
        Self { party_id, share }
    }

    pub fn party_id(&self) -> PartyId {
        self.party_id
    }

    pub fn share(&self) -> Rep3ShareU64 {
        self.share
    }

    pub fn add(&self, rhs: &Self) -> Result<Self> {
        self.ensure_same_party(rhs)?;
        Ok(Self::from_share(
            self.party_id,
            self.share.add_share(rhs.share),
        ))
    }

    pub fn sub(&self, rhs: &Self) -> Result<Self> {
        self.ensure_same_party(rhs)?;
        Ok(Self::from_share(
            self.party_id,
            self.share.sub_share(rhs.share),
        ))
    }

    pub fn add_public(&self, rhs: u64) -> Self {
        Self::from_share(self.party_id, self.share.add_public(self.party_id, rhs))
    }

    pub fn sub_public(&self, rhs: u64) -> Self {
        Self::from_share(self.party_id, self.share.sub_public(self.party_id, rhs))
    }

    pub fn mul_public(&self, rhs: u64) -> Self {
        Self::from_share(self.party_id, self.share.mul_public(rhs))
    }

    fn ensure_same_party(&self, rhs: &Self) -> Result<()> {
        if self.party_id == rhs.party_id {
            Ok(())
        } else {
            Err(MpcError::PeerMismatch {
                expected: self.party_id.as_u8(),
                actual: rhs.party_id.as_u8(),
            })
        }
    }
}

/// A local handle to a vector of secret shared `u64` values.
///
/// This intentionally does not implement `Debug`.
#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct SecretVecU64 {
    #[zeroize(skip)]
    party_id: PartyId,
    shares: Vec<Rep3ShareU64>,
}

impl SecretVecU64 {
    pub fn from_shares(party_id: PartyId, shares: Vec<Rep3ShareU64>) -> Self {
        Self { party_id, shares }
    }

    pub fn party_id(&self) -> PartyId {
        self.party_id
    }

    pub fn shares(&self) -> &[Rep3ShareU64] {
        &self.shares
    }

    pub fn len(&self) -> usize {
        self.shares.len()
    }

    pub fn is_empty(&self) -> bool {
        self.shares.is_empty()
    }

    pub fn add(&self, rhs: &Self) -> Result<Self> {
        self.zip(rhs, Rep3ShareU64::add_share)
    }

    pub fn sub(&self, rhs: &Self) -> Result<Self> {
        self.zip(rhs, Rep3ShareU64::sub_share)
    }

    pub fn mul_public(&self, rhs: u64) -> Self {
        Self::from_shares(
            self.party_id,
            self.shares
                .iter()
                .map(|share| share.mul_public(rhs))
                .collect(),
        )
    }

    pub fn add_public(&self, rhs: u64) -> Self {
        Self::from_shares(
            self.party_id,
            self.shares
                .iter()
                .map(|share| share.add_public(self.party_id, rhs))
                .collect(),
        )
    }

    fn zip(&self, rhs: &Self, f: fn(Rep3ShareU64, Rep3ShareU64) -> Rep3ShareU64) -> Result<Self> {
        if self.party_id != rhs.party_id {
            return Err(MpcError::PeerMismatch {
                expected: self.party_id.as_u8(),
                actual: rhs.party_id.as_u8(),
            });
        }
        if self.len() != rhs.len() {
            return Err(MpcError::LengthMismatch {
                left: self.len(),
                right: rhs.len(),
            });
        }
        Ok(Self::from_shares(
            self.party_id,
            self.shares
                .iter()
                .copied()
                .zip(rhs.shares.iter().copied())
                .map(|(lhs, rhs)| f(lhs, rhs))
                .collect(),
        ))
    }
}
