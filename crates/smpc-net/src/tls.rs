use std::collections::{BTreeMap, HashMap};
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pemfile::Item;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer};
use smpc_core::{MpcError, NetMessage, PartyId, Result, SessionId, Transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

use crate::frame::{DEFAULT_MAX_FRAME_LEN, read_frame, write_frame};

/// PEM-encoded certificate and private key for one party.
#[derive(Clone)]
pub struct TlsIdentity {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

impl std::fmt::Debug for TlsIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsIdentity")
            .field("cert_pem_len", &self.cert_pem.len())
            .field("key_pem", &"[redacted]")
            .finish()
    }
}

impl TlsIdentity {
    pub fn new(cert_pem: impl Into<Vec<u8>>, key_pem: impl Into<Vec<u8>>) -> Self {
        Self {
            cert_pem: cert_pem.into(),
            key_pem: key_pem.into(),
        }
    }
}

/// Configuration for a mutual-TLS TCP transport.
#[derive(Clone, Debug)]
pub struct TcpRustlsConfig {
    pub party_id: PartyId,
    pub session_id: SessionId,
    pub bind_addr: SocketAddr,
    pub peers: BTreeMap<PartyId, SocketAddr>,
    pub identity: TlsIdentity,
    pub trusted_peer_certs: BTreeMap<PartyId, Vec<u8>>,
    pub server_name: String,
    pub max_frame_len: usize,
}

impl TcpRustlsConfig {
    pub fn new(
        party_id: PartyId,
        session_id: SessionId,
        bind_addr: SocketAddr,
        peers: BTreeMap<PartyId, SocketAddr>,
        identity: TlsIdentity,
        trusted_peer_certs: BTreeMap<PartyId, Vec<u8>>,
    ) -> Self {
        Self {
            party_id,
            session_id,
            bind_addr,
            peers,
            identity,
            trusted_peer_certs,
            server_name: "localhost".to_string(),
            max_frame_len: DEFAULT_MAX_FRAME_LEN,
        }
    }
}

/// TCP transport protected by rustls mutual authentication.
pub struct TcpRustlsTransport {
    party_id: PartyId,
    session_id: SessionId,
    writers: HashMap<PartyId, mpsc::Sender<NetMessage>>,
    incoming: mpsc::Receiver<NetMessage>,
}

impl TcpRustlsTransport {
    pub async fn connect(config: TcpRustlsConfig) -> Result<Self> {
        validate_peer_config(&config)?;
        let server_config = Arc::new(server_config(&config)?);
        let listener = TcpListener::bind(config.bind_addr).await?;
        let acceptor = TlsAcceptor::from(server_config);
        let lower_peers: Vec<_> = config
            .peers
            .keys()
            .copied()
            .filter(|peer| *peer < config.party_id)
            .collect();
        let accept_party = config.party_id;

        let accept_task = tokio::spawn(async move {
            let mut accepted = Vec::new();
            for _ in lower_peers {
                let (tcp, _) = listener.accept().await.map_err(MpcError::from)?;
                let mut stream = acceptor
                    .accept(tcp)
                    .await
                    .map(TlsStream::from)
                    .map_err(|err| MpcError::Tls(err.to_string()))?;
                let mut peer_buf = [0u8; 1];
                stream.read_exact(&mut peer_buf).await?;
                let peer = PartyId::new(peer_buf[0])?;
                if peer >= accept_party {
                    return Err(MpcError::PeerMismatch {
                        expected: accept_party.prev().as_u8(),
                        actual: peer.as_u8(),
                    });
                }
                stream.write_all(&[accept_party.as_u8()]).await?;
                stream.flush().await?;
                accepted.push((peer, stream));
            }
            Ok::<_, MpcError>(accepted)
        });

        let mut streams = HashMap::new();
        for (peer, addr) in config
            .peers
            .iter()
            .filter(|(peer, _)| **peer > config.party_id)
        {
            let client_config = Arc::new(client_config(&config, *peer)?);
            let mut stream = connect_one(
                config.party_id,
                *peer,
                *addr,
                client_config.clone(),
                &config.server_name,
            )
            .await?;
            stream.write_all(&[config.party_id.as_u8()]).await?;
            stream.flush().await?;
            let mut peer_buf = [0u8; 1];
            stream.read_exact(&mut peer_buf).await?;
            let actual = PartyId::new(peer_buf[0])?;
            if actual != *peer {
                return Err(MpcError::PeerMismatch {
                    expected: peer.as_u8(),
                    actual: actual.as_u8(),
                });
            }
            streams.insert(*peer, stream);
        }

        for (peer, stream) in accept_task
            .await
            .map_err(|err| MpcError::Transport(err.to_string()))??
        {
            streams.insert(peer, stream);
        }

        let (incoming_tx, incoming_rx) = mpsc::channel(256);
        let mut writers = HashMap::new();
        for (peer, stream) in streams {
            let (reader, writer) = tokio::io::split(stream);
            let (writer_tx, mut writer_rx) = mpsc::channel::<NetMessage>(128);
            writers.insert(peer, writer_tx);

            let mut writer = writer;
            let max_frame_len = config.max_frame_len;
            tokio::spawn(async move {
                while let Some(message) = writer_rx.recv().await {
                    if write_frame(&mut writer, &message, max_frame_len)
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });

            let mut reader = reader;
            let tx = incoming_tx.clone();
            let session_id = config.session_id;
            let party_id = config.party_id;
            let max_frame_len = config.max_frame_len;
            tokio::spawn(async move {
                while let Ok(message) =
                    read_frame(&mut reader, session_id, party_id, max_frame_len).await
                {
                    if tx.send(message).await.is_err() {
                        break;
                    }
                }
            });
        }

        Ok(Self {
            party_id: config.party_id,
            session_id: config.session_id,
            writers,
            incoming: incoming_rx,
        })
    }
}

#[async_trait]
impl Transport for TcpRustlsTransport {
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
        let writer = self
            .writers
            .get(&message.to)
            .ok_or_else(|| MpcError::Transport("unknown tcp peer".to_string()))?;
        writer
            .send(message)
            .await
            .map_err(|_| MpcError::Transport("tcp writer closed".to_string()))
    }

    async fn recv(&mut self) -> Result<NetMessage> {
        self.incoming
            .recv()
            .await
            .ok_or_else(|| MpcError::Transport("tcp transport closed".to_string()))
    }
}

async fn connect_one(
    self_id: PartyId,
    peer: PartyId,
    addr: SocketAddr,
    client_config: Arc<ClientConfig>,
    server_name: &str,
) -> Result<TlsStream<TcpStream>> {
    let connector = TlsConnector::from(client_config);
    let server_name = rustls_pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|err| MpcError::Tls(err.to_string()))?;
    let mut last_err = None;
    for _ in 0..100 {
        match TcpStream::connect(addr).await {
            Ok(tcp) => {
                let stream = connector
                    .connect(server_name.clone(), tcp)
                    .await
                    .map(TlsStream::from)
                    .map_err(|err| MpcError::Tls(err.to_string()))?;
                return Ok(stream);
            }
            Err(err) => {
                last_err = Some(err);
                sleep(Duration::from_millis(20)).await;
            }
        }
    }
    Err(MpcError::Transport(format!(
        "party {} could not connect to party {} at {}: {}",
        self_id.as_u8(),
        peer.as_u8(),
        addr,
        last_err
            .map(|err| err.to_string())
            .unwrap_or_else(|| "unknown error".to_string())
    )))
}

fn validate_peer_config(config: &TcpRustlsConfig) -> Result<()> {
    if config.peers.len() != 2 {
        return Err(MpcError::WrongPartyCount);
    }
    for party in PartyId::all() {
        if party == config.party_id {
            continue;
        }
        if !config.peers.contains_key(&party) {
            return Err(MpcError::Transport("missing peer address".to_string()));
        }
        if !config.trusted_peer_certs.contains_key(&party) {
            return Err(MpcError::Tls(
                "missing trusted peer certificate".to_string(),
            ));
        }
    }
    Ok(())
}

fn server_config(config: &TcpRustlsConfig) -> Result<ServerConfig> {
    let verifier = WebPkiClientVerifier::builder(Arc::new(root_store_for_certs(
        config.trusted_peer_certs.values(),
    )?))
    .build()
    .map_err(|err| MpcError::Tls(err.to_string()))?;
    ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            parse_certs(&config.identity.cert_pem)?,
            parse_key(&config.identity.key_pem)?,
        )
        .map_err(|err| MpcError::Tls(err.to_string()))
}

fn client_config(config: &TcpRustlsConfig, peer: PartyId) -> Result<ClientConfig> {
    let peer_cert = config
        .trusted_peer_certs
        .get(&peer)
        .ok_or_else(|| MpcError::Tls("missing trusted peer certificate".to_string()))?;
    ClientConfig::builder()
        .with_root_certificates(root_store_for_certs([peer_cert])?)
        .with_client_auth_cert(
            parse_certs(&config.identity.cert_pem)?,
            parse_key(&config.identity.key_pem)?,
        )
        .map_err(|err| MpcError::Tls(err.to_string()))
}

fn root_store_for_certs<'a>(certs: impl IntoIterator<Item = &'a Vec<u8>>) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for cert_pem in certs {
        for cert in parse_certs(cert_pem)? {
            roots
                .add(cert)
                .map_err(|err| MpcError::Tls(err.to_string()))?;
        }
    }
    Ok(roots)
}

fn parse_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(pem);
    let mut certs = Vec::new();
    while let Some(item) =
        rustls_pemfile::read_one(&mut reader).map_err(|err| MpcError::Tls(err.to_string()))?
    {
        if let Item::X509Certificate(cert) = item {
            certs.push(CertificateDer::from(cert));
        }
    }
    if certs.is_empty() {
        return Err(MpcError::Tls("no certificate found in PEM".to_string()));
    }
    Ok(certs)
}

fn parse_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(pem);
    while let Some(item) =
        rustls_pemfile::read_one(&mut reader).map_err(|err| MpcError::Tls(err.to_string()))?
    {
        match item {
            Item::PKCS8Key(key) => {
                return Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)));
            }
            Item::RSAKey(key) => {
                return Ok(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(key)));
            }
            _ => {}
        }
    }
    Err(MpcError::Tls("no private key found in PEM".to_string()))
}
