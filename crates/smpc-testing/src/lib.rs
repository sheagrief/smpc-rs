//! Deterministic test helpers for three-party v0.1 sessions.

use smpc_core::{MpcConfig, PartyId, Result, SessionId};
use smpc_net::InMemoryNetwork;
use smpc_protocols::MpcSession;

pub type TestSession = MpcSession<smpc_net::InMemoryTransport>;

pub fn test_configs(session_id: SessionId) -> [MpcConfig; 3] {
    let seed01 = [1u8; 32];
    let seed12 = [2u8; 32];
    let seed20 = [3u8; 32];
    [
        MpcConfig::new(PartyId::P0, session_id, seed20, seed01).with_rng_seed([10u8; 32]),
        MpcConfig::new(PartyId::P1, session_id, seed01, seed12).with_rng_seed([11u8; 32]),
        MpcConfig::new(PartyId::P2, session_id, seed12, seed20).with_rng_seed([12u8; 32]),
    ]
}

pub fn test_sessions(session_id: SessionId) -> Result<[TestSession; 3]> {
    let [t0, t1, t2] = InMemoryNetwork::new(session_id).transports();
    let [c0, c1, c2] = test_configs(session_id);
    Ok([
        MpcSession::new(c0, t0)?,
        MpcSession::new(c1, t1)?,
        MpcSession::new(c2, t2)?,
    ])
}

pub fn cleartext_dot(lhs: &[u64], rhs: &[u64]) -> u64 {
    lhs.iter()
        .copied()
        .zip(rhs.iter().copied())
        .fold(0u64, |acc, (lhs, rhs)| {
            acc.wrapping_add(lhs.wrapping_mul(rhs))
        })
}

pub fn cleartext_sum(values: &[u64]) -> u64 {
    values
        .iter()
        .copied()
        .fold(0u64, |acc, value| acc.wrapping_add(value))
}
