//! Rep3 protocol implementation over wrapping `u64` arithmetic.

use std::collections::VecDeque;

use async_trait::async_trait;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use smpc_core::{
    MessageKind, MpcConfig, MpcError, NetMessage, PartyId, Protocol, Prss, Rep3ShareU64, Result,
    SecretU64, SecretVecU64, SessionId, ShareScheme, Transport, WrappingU64,
};

/// Marker type for the v0.1 replicated 3-party `u64` sharing scheme.
pub struct Rep3U64;

impl ShareScheme for Rep3U64 {
    type Secret = SecretU64;
    type SecretVector = SecretVecU64;
    const PARTY_COUNT: usize = 3;
}

/// PRSS source for the Rep3 `u64` protocol.
#[derive(Clone)]
pub struct Rep3Prss {
    party_id: PartyId,
    session_id: SessionId,
    prev_seed: [u8; 32],
    next_seed: [u8; 32],
}

impl Rep3Prss {
    pub fn new(
        party_id: PartyId,
        session_id: SessionId,
        prev_seed: [u8; 32],
        next_seed: [u8; 32],
    ) -> Self {
        Self {
            party_id,
            session_id,
            prev_seed,
            next_seed,
        }
    }

    fn stream(&self, seed: [u8; 32], op: &[u8], counter: u64, pair_owner: PartyId) -> ChaCha20Rng {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(self.session_id.as_bytes());
        hasher.update(op);
        hasher.update(counter.to_be_bytes());
        hasher.update([pair_owner.as_u8()]);
        let digest: [u8; 32] = hasher.finalize().into();
        ChaCha20Rng::from_seed(digest)
    }
}

impl Prss for Rep3Prss {
    fn next_pair_masks(&self, op: &[u8], counter: u64, len: usize) -> (Vec<u64>, Vec<u64>) {
        let mut prev_rng = self.stream(self.prev_seed, op, counter, self.party_id.prev());
        let mut next_rng = self.stream(self.next_seed, op, counter, self.party_id);
        let mut prev = Vec::with_capacity(len);
        let mut next = Vec::with_capacity(len);
        for _ in 0..len {
            prev.push(prev_rng.next_u64());
            next.push(next_rng.next_u64());
        }
        (prev, next)
    }
}

/// High-level v0.1 MPC session for one party.
pub struct MpcSession<T> {
    config: MpcConfig,
    transport: T,
    prss: Rep3Prss,
    rng: ChaCha20Rng,
    counter: u64,
    pending: VecDeque<NetMessage>,
}

impl<T: Transport> MpcSession<T> {
    pub fn new(config: MpcConfig, transport: T) -> Result<Self> {
        if config.party_id != transport.party_id() {
            return Err(MpcError::PeerMismatch {
                expected: config.party_id.as_u8(),
                actual: transport.party_id().as_u8(),
            });
        }
        if config.session_id != transport.session_id() {
            return Err(MpcError::SessionMismatch);
        }
        let rng = match config.rng_seed {
            Some(seed) => ChaCha20Rng::from_seed(seed),
            None => ChaCha20Rng::from_entropy(),
        };
        let prss = Rep3Prss::new(
            config.party_id,
            config.session_id,
            config.prss_prev_seed,
            config.prss_next_seed,
        );
        Ok(Self {
            config,
            transport,
            prss,
            rng,
            counter: 0,
            pending: VecDeque::new(),
        })
    }

    pub fn party_id(&self) -> PartyId {
        self.config.party_id
    }

    pub fn session_id(&self) -> SessionId {
        self.config.session_id
    }

    pub fn add(&self, lhs: &SecretU64, rhs: &SecretU64) -> Result<SecretU64> {
        lhs.add(rhs)
    }

    pub fn sub(&self, lhs: &SecretU64, rhs: &SecretU64) -> Result<SecretU64> {
        lhs.sub(rhs)
    }

    pub fn add_public(&self, lhs: &SecretU64, rhs: u64) -> SecretU64 {
        lhs.add_public(rhs)
    }

    pub fn sub_public(&self, lhs: &SecretU64, rhs: u64) -> SecretU64 {
        lhs.sub_public(rhs)
    }

    pub fn mul_public(&self, lhs: &SecretU64, rhs: u64) -> SecretU64 {
        lhs.mul_public(rhs)
    }

    pub async fn private_input(&mut self, owner: PartyId, value: u64) -> Result<SecretU64> {
        let values = self.private_inputs(owner, &[value]).await?;
        Ok(SecretU64::from_share(
            self.party_id(),
            values
                .shares()
                .first()
                .copied()
                .ok_or(MpcError::InvalidShareShape("missing scalar share"))?,
        ))
    }

    pub async fn private_inputs(&mut self, owner: PartyId, values: &[u64]) -> Result<SecretVecU64> {
        let counter = self.next_counter()?;
        if self.party_id() == owner {
            let mut by_party = [Vec::new(), Vec::new(), Vec::new()];
            for value in values.iter().copied() {
                let x0 = self.rng.next_u64();
                let x1 = self.rng.next_u64();
                let x2 = value.wrapping_sub(x0).wrapping_sub(x1);
                let shares = [x0, x1, x2];
                for party in PartyId::all() {
                    by_party[party.index()].push(Rep3ShareU64::new(
                        shares[party.index()],
                        shares[party.next().index()],
                    ));
                }
            }

            for party in PartyId::all() {
                if party == owner {
                    continue;
                }
                self.send(
                    party,
                    MessageKind::PrivateInput,
                    counter,
                    encode_share_pairs(&by_party[party.index()]),
                )
                .await?;
            }
            Ok(SecretVecU64::from_shares(
                self.party_id(),
                by_party[self.party_id().index()].clone(),
            ))
        } else {
            let message = self
                .recv_expected(owner, MessageKind::PrivateInput, counter)
                .await?;
            Ok(SecretVecU64::from_shares(
                self.party_id(),
                decode_share_pairs(&message.payload)?,
            ))
        }
    }

    pub async fn open(&mut self, secret: &SecretU64) -> Result<u64> {
        let values = self
            .open_vec(&SecretVecU64::from_shares(
                self.party_id(),
                vec![secret.share()],
            ))
            .await?;
        values
            .first()
            .copied()
            .ok_or(MpcError::InvalidShareShape("missing opened scalar"))
    }

    pub async fn open_vec(&mut self, secret: &SecretVecU64) -> Result<Vec<u64>> {
        self.ensure_vec_party(secret)?;
        let counter = self.next_counter()?;
        let own: Vec<u64> = secret.shares().iter().map(|share| share.own()).collect();
        let payload = encode_u64_vec(&own);
        for peer in PartyId::all() {
            if peer != self.party_id() {
                self.send(peer, MessageKind::Open, counter, payload.clone())
                    .await?;
            }
        }

        let mut components: [Option<Vec<u64>>; 3] = [None, None, None];
        components[self.party_id().index()] = Some(own);
        for _ in 0..2 {
            let message = self.recv_kind(MessageKind::Open, counter).await?;
            let values = decode_u64_vec(&message.payload)?;
            if values.len() != secret.len() {
                return Err(MpcError::LengthMismatch {
                    left: secret.len(),
                    right: values.len(),
                });
            }
            components[message.from.index()] = Some(values);
        }

        let mut opened = Vec::with_capacity(secret.len());
        for idx in 0..secret.len() {
            let mut value = 0u64;
            for component in &components {
                let component = component
                    .as_ref()
                    .ok_or(MpcError::InvalidShareShape("missing open component"))?;
                value = value.wrapping_add(component[idx]);
            }
            opened.push(value);
        }
        Ok(opened)
    }

    pub async fn mul(&mut self, lhs: &SecretU64, rhs: &SecretU64) -> Result<SecretU64> {
        let product = self
            .mul_vec(
                &SecretVecU64::from_shares(self.party_id(), vec![lhs.share()]),
                &SecretVecU64::from_shares(self.party_id(), vec![rhs.share()]),
            )
            .await?;
        Ok(SecretU64::from_share(
            self.party_id(),
            product
                .shares()
                .first()
                .copied()
                .ok_or(MpcError::InvalidShareShape("missing product share"))?,
        ))
    }

    pub async fn mul_vec(
        &mut self,
        lhs: &SecretVecU64,
        rhs: &SecretVecU64,
    ) -> Result<SecretVecU64> {
        self.ensure_vec_party(lhs)?;
        self.ensure_vec_party(rhs)?;
        if lhs.len() != rhs.len() {
            return Err(MpcError::LengthMismatch {
                left: lhs.len(),
                right: rhs.len(),
            });
        }
        let counter = self.next_counter()?;
        let (prev_masks, next_masks) =
            self.prss
                .next_pair_masks(b"rep3-u64-mul", counter, lhs.len());
        let mut own_components = Vec::with_capacity(lhs.len());
        for ((lhs, rhs), (prev_mask, next_mask)) in lhs
            .shares()
            .iter()
            .copied()
            .zip(rhs.shares().iter().copied())
            .zip(prev_masks.into_iter().zip(next_masks.into_iter()))
        {
            let local = local_mul_component(lhs, rhs);
            let own = local.wrapping_add(next_mask).wrapping_sub(prev_mask);
            own_components.push(own);
        }

        self.send(
            self.party_id().prev(),
            MessageKind::Multiply,
            counter,
            encode_u64_vec(&own_components),
        )
        .await?;
        let message = self
            .recv_expected(self.party_id().next(), MessageKind::Multiply, counter)
            .await?;
        let next_components = decode_u64_vec(&message.payload)?;
        if next_components.len() != own_components.len() {
            return Err(MpcError::LengthMismatch {
                left: own_components.len(),
                right: next_components.len(),
            });
        }
        let shares = own_components
            .into_iter()
            .zip(next_components)
            .map(|(own, next)| Rep3ShareU64::new(own, next))
            .collect();
        Ok(SecretVecU64::from_shares(self.party_id(), shares))
    }

    pub fn sum(&self, values: &SecretVecU64) -> Result<SecretU64> {
        self.ensure_vec_party(values)?;
        let mut own = 0u64;
        let mut next = 0u64;
        for share in values.shares() {
            own = own.wrapping_add(share.own());
            next = next.wrapping_add(share.next());
        }
        Ok(SecretU64::from_share(
            self.party_id(),
            Rep3ShareU64::new(own, next),
        ))
    }

    pub async fn dot(&mut self, lhs: &SecretVecU64, rhs: &SecretVecU64) -> Result<SecretU64> {
        let products = self.mul_vec(lhs, rhs).await?;
        self.sum(&products)
    }

    async fn send(
        &mut self,
        to: PartyId,
        kind: MessageKind,
        counter: u64,
        payload: Vec<u8>,
    ) -> Result<()> {
        self.transport
            .send(NetMessage {
                session_id: self.session_id(),
                from: self.party_id(),
                to,
                kind,
                counter,
                payload,
            })
            .await
    }

    async fn recv_expected(
        &mut self,
        from: PartyId,
        kind: MessageKind,
        counter: u64,
    ) -> Result<NetMessage> {
        self.recv_matching(Some(from), kind, counter).await
    }

    async fn recv_kind(&mut self, kind: MessageKind, counter: u64) -> Result<NetMessage> {
        self.recv_matching(None, kind, counter).await
    }

    async fn recv_matching(
        &mut self,
        from: Option<PartyId>,
        kind: MessageKind,
        counter: u64,
    ) -> Result<NetMessage> {
        if let Some(index) = self
            .pending
            .iter()
            .position(|message| message_matches(message, from, kind, counter))
        {
            return Ok(self
                .pending
                .remove(index)
                .expect("position returned a valid pending index"));
        }

        loop {
            let message = self.transport.recv().await?;
            if message_matches(&message, from, kind, counter) {
                return Ok(message);
            }
            if message.counter > counter {
                self.pending.push_back(message);
                continue;
            }
            if message.counter < counter {
                return Err(MpcError::CounterMismatch {
                    expected: counter,
                    actual: message.counter,
                });
            }
            if message.kind != kind {
                return Err(MpcError::UnexpectedMessageKind {
                    expected: kind,
                    actual: message.kind,
                });
            }
            if let Some(expected_from) = from {
                return Err(MpcError::PeerMismatch {
                    expected: expected_from.as_u8(),
                    actual: message.from.as_u8(),
                });
            }
        }
    }

    fn next_counter(&mut self) -> Result<u64> {
        let counter = self.counter;
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| MpcError::Protocol("operation counter overflow".to_string()))?;
        Ok(counter)
    }

    fn ensure_vec_party(&self, value: &SecretVecU64) -> Result<()> {
        if value.party_id() == self.party_id() {
            Ok(())
        } else {
            Err(MpcError::PeerMismatch {
                expected: self.party_id().as_u8(),
                actual: value.party_id().as_u8(),
            })
        }
    }
}

fn message_matches(
    message: &NetMessage,
    from: Option<PartyId>,
    kind: MessageKind,
    counter: u64,
) -> bool {
    message.kind == kind
        && message.counter == counter
        && from.is_none_or(|from| message.from == from)
}

#[async_trait]
impl<T: Transport> Protocol for MpcSession<T> {
    async fn mul(&mut self, lhs: &SecretU64, rhs: &SecretU64) -> Result<SecretU64> {
        MpcSession::mul(self, lhs, rhs).await
    }

    async fn mul_vec(&mut self, lhs: &SecretVecU64, rhs: &SecretVecU64) -> Result<SecretVecU64> {
        MpcSession::mul_vec(self, lhs, rhs).await
    }
}

fn local_mul_component(lhs: Rep3ShareU64, rhs: Rep3ShareU64) -> u64 {
    let own_own = WrappingU64::mul(lhs.own(), rhs.own());
    let own_next = WrappingU64::mul(lhs.own(), rhs.next());
    let next_own = WrappingU64::mul(lhs.next(), rhs.own());
    own_own.wrapping_add(own_next).wrapping_add(next_own)
}

fn encode_share_pairs(shares: &[Rep3ShareU64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + shares.len() * 16);
    out.extend_from_slice(&(shares.len() as u32).to_be_bytes());
    for share in shares {
        out.extend_from_slice(&share.own().to_be_bytes());
        out.extend_from_slice(&share.next().to_be_bytes());
    }
    out
}

fn decode_share_pairs(bytes: &[u8]) -> Result<Vec<Rep3ShareU64>> {
    if bytes.len() < 4 {
        return Err(MpcError::Protocol("short share-pair payload".to_string()));
    }
    let len = u32::from_be_bytes(bytes[..4].try_into().expect("slice length checked")) as usize;
    if bytes.len() != 4 + len * 16 {
        return Err(MpcError::Protocol(
            "share-pair payload length mismatch".to_string(),
        ));
    }
    let mut shares = Vec::with_capacity(len);
    for chunk in bytes[4..].chunks_exact(16) {
        let own = u64::from_be_bytes(chunk[..8].try_into().expect("slice length checked"));
        let next = u64::from_be_bytes(chunk[8..].try_into().expect("slice length checked"));
        shares.push(Rep3ShareU64::new(own, next));
    }
    Ok(shares)
}

fn encode_u64_vec(values: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + values.len() * 8);
    out.extend_from_slice(&(values.len() as u32).to_be_bytes());
    for value in values {
        out.extend_from_slice(&value.to_be_bytes());
    }
    out
}

fn decode_u64_vec(bytes: &[u8]) -> Result<Vec<u64>> {
    if bytes.len() < 4 {
        return Err(MpcError::Protocol("short u64 vector payload".to_string()));
    }
    let len = u32::from_be_bytes(bytes[..4].try_into().expect("slice length checked")) as usize;
    if bytes.len() != 4 + len * 8 {
        return Err(MpcError::Protocol(
            "u64 vector payload length mismatch".to_string(),
        ));
    }
    Ok(bytes[4..]
        .chunks_exact(8)
        .map(|chunk| u64::from_be_bytes(chunk.try_into().expect("slice length checked")))
        .collect())
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::{RngCore, SeedableRng};
    use smpc_core::{MpcConfig, PartyId, SessionId};
    use smpc_net::InMemoryNetwork;

    use super::*;

    fn configs(session_id: SessionId) -> [MpcConfig; 3] {
        let seed01 = [1u8; 32];
        let seed12 = [2u8; 32];
        let seed20 = [3u8; 32];
        [
            MpcConfig::new(PartyId::P0, session_id, seed20, seed01).with_rng_seed([10u8; 32]),
            MpcConfig::new(PartyId::P1, session_id, seed01, seed12).with_rng_seed([11u8; 32]),
            MpcConfig::new(PartyId::P2, session_id, seed12, seed20).with_rng_seed([12u8; 32]),
        ]
    }

    fn sessions() -> [MpcSession<smpc_net::InMemoryTransport>; 3] {
        let session_id = SessionId::from_u64_for_testing(42);
        let [t0, t1, t2] = InMemoryNetwork::new(session_id).transports();
        let [c0, c1, c2] = configs(session_id);
        [
            MpcSession::new(c0, t0).unwrap(),
            MpcSession::new(c1, t1).unwrap(),
            MpcSession::new(c2, t2).unwrap(),
        ]
    }

    async fn run_scalar_circuit(a: u64, b: u64) -> [u64; 3] {
        let [mut s0, mut s1, mut s2] = sessions();
        let p0 = tokio::spawn(async move {
            let x = s0.private_input(PartyId::P0, a).await?;
            let y = s0.private_input(PartyId::P1, 0).await?;
            let z = s0.mul(&x.add_public(5), &y).await?;
            s0.open(&z).await
        });
        let p1 = tokio::spawn(async move {
            let x = s1.private_input(PartyId::P0, 0).await?;
            let y = s1.private_input(PartyId::P1, b).await?;
            let z = s1.mul(&x.add_public(5), &y).await?;
            s1.open(&z).await
        });
        let p2 = tokio::spawn(async move {
            let x = s2.private_input(PartyId::P0, 0).await?;
            let y = s2.private_input(PartyId::P1, 0).await?;
            let z = s2.mul(&x.add_public(5), &y).await?;
            s2.open(&z).await
        });
        let (p0, p1, p2) = tokio::join!(p0, p1, p2);
        [
            p0.unwrap().unwrap(),
            p1.unwrap().unwrap(),
            p2.unwrap().unwrap(),
        ]
    }

    #[tokio::test]
    async fn simulator_scalar_arithmetic() {
        let opened = run_scalar_circuit(7, 11).await;
        assert_eq!(opened, [132, 132, 132]);
    }

    #[tokio::test]
    async fn simulator_scalar_edge_max() {
        let opened = run_scalar_circuit(0, u64::MAX).await;
        assert_eq!(opened, [u64::MAX - 4, u64::MAX - 4, u64::MAX - 4]);
    }

    #[tokio::test]
    async fn simulator_vectors_sum_and_dot() {
        let [mut s0, mut s1, mut s2] = sessions();
        let p0 = tokio::spawn(async move {
            let x = s0.private_inputs(PartyId::P0, &[1, 2, 3, 4]).await?;
            let y = s0.private_inputs(PartyId::P1, &[0, 0, 0, 0]).await?;
            let dot = s0.dot(&x, &y).await?;
            let sum = s0.sum(&x)?;
            Ok::<_, MpcError>((s0.open(&dot).await?, s0.open(&sum).await?))
        });
        let p1 = tokio::spawn(async move {
            let x = s1.private_inputs(PartyId::P0, &[0, 0, 0, 0]).await?;
            let y = s1.private_inputs(PartyId::P1, &[5, 6, 7, 8]).await?;
            let dot = s1.dot(&x, &y).await?;
            let sum = s1.sum(&x)?;
            Ok::<_, MpcError>((s1.open(&dot).await?, s1.open(&sum).await?))
        });
        let p2 = tokio::spawn(async move {
            let x = s2.private_inputs(PartyId::P0, &[0, 0, 0, 0]).await?;
            let y = s2.private_inputs(PartyId::P1, &[0, 0, 0, 0]).await?;
            let dot = s2.dot(&x, &y).await?;
            let sum = s2.sum(&x)?;
            Ok::<_, MpcError>((s2.open(&dot).await?, s2.open(&sum).await?))
        });
        let out = [
            p0.await.unwrap().unwrap(),
            p1.await.unwrap().unwrap(),
            p2.await.unwrap().unwrap(),
        ];
        assert_eq!(out, [(70, 10), (70, 10), (70, 10)]);
    }

    #[test]
    fn prss_counter_domain_separation() {
        let session_id = SessionId::from_u64_for_testing(7);
        let prss = Rep3Prss::new(PartyId::P0, session_id, [3u8; 32], [1u8; 32]);
        let first = prss.next_pair_masks(b"mul", 0, 4);
        let second = prss.next_pair_masks(b"mul", 1, 4);
        assert_ne!(first.0, second.0);
        assert_ne!(first.1, second.1);
    }

    #[tokio::test]
    async fn randomized_scalar_matches_cleartext() {
        let mut cases = vec![
            (0, 0),
            (0, u64::MAX),
            (u64::MAX, 0),
            (u64::MAX, 2),
            (u64::MAX - 4, 7),
        ];
        let mut rng = ChaCha20Rng::from_seed([99u8; 32]);
        for _ in 0..16 {
            cases.push((rng.next_u64(), rng.next_u64()));
        }

        for (a, b) in cases {
            let out = run_scalar_circuit(a, b).await;
            let expected = a.wrapping_add(5).wrapping_mul(b);
            assert_eq!(out, [expected, expected, expected]);
        }
    }
}
