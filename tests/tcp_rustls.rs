use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener};

use smpc_core::{MpcConfig, PartyId, SessionId};
use smpc_net::{TcpRustlsConfig, TcpRustlsTransport, TlsIdentity};
use smpc_protocols::MpcSession;

const P0_CERT: &str = include_str!("fixtures/p0.crt");
const P0_KEY: &str = include_str!("fixtures/p0.key");
const P0_CA_CERT: &str = include_str!("fixtures/p0-ca.crt");
const P1_CERT: &str = include_str!("fixtures/p1.crt");
const P1_KEY: &str = include_str!("fixtures/p1.key");
const P1_CA_CERT: &str = include_str!("fixtures/p1-ca.crt");
const P2_CERT: &str = include_str!("fixtures/p2.crt");
const P2_KEY: &str = include_str!("fixtures/p2.key");
const P2_CA_CERT: &str = include_str!("fixtures/p2-ca.crt");

#[tokio::test]
async fn tcp_rustls_loopback_runs_three_party_circuit() {
    let session_id = SessionId::from_u64_for_testing(77);
    let Some(addrs) = free_addrs() else {
        eprintln!("skipping TCP loopback test because this environment denies local bind");
        return;
    };
    let [cfg0, cfg1, cfg2] = tcp_configs(session_id, addrs);
    let [c0, c1, c2] = mpc_configs(session_id);

    let p0 = tokio::spawn(async move {
        let transport = TcpRustlsTransport::connect(cfg0).await?;
        let mut session = MpcSession::new(c0, transport)?;
        let x = session.private_input(PartyId::P0, 9).await?;
        let y = session.private_input(PartyId::P1, 0).await?;
        let z = session.mul(&x, &y.add_public(1)).await?;
        session.open(&z).await
    });
    let p1 = tokio::spawn(async move {
        let transport = TcpRustlsTransport::connect(cfg1).await?;
        let mut session = MpcSession::new(c1, transport)?;
        let x = session.private_input(PartyId::P0, 0).await?;
        let y = session.private_input(PartyId::P1, 6).await?;
        let z = session.mul(&x, &y.add_public(1)).await?;
        session.open(&z).await
    });
    let p2 = tokio::spawn(async move {
        let transport = TcpRustlsTransport::connect(cfg2).await?;
        let mut session = MpcSession::new(c2, transport)?;
        let x = session.private_input(PartyId::P0, 0).await?;
        let y = session.private_input(PartyId::P1, 0).await?;
        let z = session.mul(&x, &y.add_public(1)).await?;
        session.open(&z).await
    });

    let out = [
        p0.await.unwrap().unwrap(),
        p1.await.unwrap().unwrap(),
        p2.await.unwrap().unwrap(),
    ];
    assert_eq!(out, [63, 63, 63]);
}

fn free_addrs() -> Option<[SocketAddr; 3]> {
    let bind = || match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener),
        Err(err) if err.kind() == ErrorKind::PermissionDenied => None,
        Err(err) => panic!("failed to reserve loopback port: {err}"),
    };
    let sockets = [bind()?, bind()?, bind()?];
    let addrs = [
        sockets[0].local_addr().unwrap(),
        sockets[1].local_addr().unwrap(),
        sockets[2].local_addr().unwrap(),
    ];
    drop(sockets);
    Some(addrs)
}

fn mpc_configs(session_id: SessionId) -> [MpcConfig; 3] {
    let seed01 = [1u8; 32];
    let seed12 = [2u8; 32];
    let seed20 = [3u8; 32];
    [
        MpcConfig::new(PartyId::P0, session_id, seed20, seed01).with_rng_seed([10u8; 32]),
        MpcConfig::new(PartyId::P1, session_id, seed01, seed12).with_rng_seed([11u8; 32]),
        MpcConfig::new(PartyId::P2, session_id, seed12, seed20).with_rng_seed([12u8; 32]),
    ]
}

fn tcp_configs(session_id: SessionId, addrs: [SocketAddr; 3]) -> [TcpRustlsConfig; 3] {
    let certs = [
        P0_CA_CERT.as_bytes().to_vec(),
        P1_CA_CERT.as_bytes().to_vec(),
        P2_CA_CERT.as_bytes().to_vec(),
    ];
    let identities = [
        TlsIdentity::new(P0_CERT, P0_KEY),
        TlsIdentity::new(P1_CERT, P1_KEY),
        TlsIdentity::new(P2_CERT, P2_KEY),
    ];

    std::array::from_fn(|idx| {
        let party = PartyId::new(idx as u8).unwrap();
        let mut peers = BTreeMap::new();
        let mut trusted = BTreeMap::new();
        for peer_idx in 0..3 {
            let peer = PartyId::new(peer_idx as u8).unwrap();
            if peer != party {
                peers.insert(peer, addrs[peer_idx]);
                trusted.insert(peer, certs[peer_idx].clone());
            }
        }
        TcpRustlsConfig::new(
            party,
            session_id,
            addrs[idx],
            peers,
            identities[idx].clone(),
            trusted,
        )
    })
}
