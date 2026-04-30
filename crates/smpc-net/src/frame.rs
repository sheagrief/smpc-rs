use smpc_core::{MessageKind, MpcError, NetMessage, PartyId, Result, SessionId};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAGIC: &[u8; 4] = b"SMPC";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 32 + 1 + 1 + 1 + 8 + 4;

/// Default upper bound for a single encoded MPC frame.
pub const DEFAULT_MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// Encode a protocol message as a length-prefixed frame body.
pub fn encode_frame(message: &NetMessage, max_frame_len: usize) -> Result<Vec<u8>> {
    let body_len = HEADER_LEN + message.payload.len();
    if body_len > max_frame_len {
        return Err(MpcError::Frame(
            "payload exceeds maximum frame length".to_string(),
        ));
    }
    let mut frame = Vec::with_capacity(4 + body_len);
    frame.extend_from_slice(&(body_len as u32).to_be_bytes());
    frame.extend_from_slice(MAGIC);
    frame.push(VERSION);
    frame.extend_from_slice(&message.session_id.as_bytes());
    frame.push(message.from.as_u8());
    frame.push(message.to.as_u8());
    frame.push(message.kind as u8);
    frame.extend_from_slice(&message.counter.to_be_bytes());
    frame.extend_from_slice(&(message.payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&message.payload);
    Ok(frame)
}

/// Decode and validate a frame body after the outer length prefix has been read.
pub fn decode_frame_body(
    body: &[u8],
    expected_session: SessionId,
    expected_to: PartyId,
    max_frame_len: usize,
) -> Result<NetMessage> {
    if body.len() > max_frame_len {
        return Err(MpcError::Frame("frame exceeds maximum length".to_string()));
    }
    if body.len() < HEADER_LEN {
        return Err(MpcError::Frame("short frame".to_string()));
    }
    if &body[..4] != MAGIC {
        return Err(MpcError::Frame("bad magic".to_string()));
    }
    if body[4] != VERSION {
        return Err(MpcError::Frame("unsupported frame version".to_string()));
    }

    let mut session = [0u8; 32];
    session.copy_from_slice(&body[5..37]);
    let session_id = SessionId::new(session);
    if session_id != expected_session {
        return Err(MpcError::SessionMismatch);
    }

    let from = PartyId::new(body[37])?;
    let to = PartyId::new(body[38])?;
    if to != expected_to {
        return Err(MpcError::PeerMismatch {
            expected: expected_to.as_u8(),
            actual: to.as_u8(),
        });
    }
    let kind = MessageKind::try_from(body[39])?;
    let counter = u64::from_be_bytes(body[40..48].try_into().expect("slice length checked"));
    let payload_len =
        u32::from_be_bytes(body[48..52].try_into().expect("slice length checked")) as usize;
    if HEADER_LEN + payload_len != body.len() {
        return Err(MpcError::Frame("payload length mismatch".to_string()));
    }
    Ok(NetMessage {
        session_id,
        from,
        to,
        kind,
        counter,
        payload: body[HEADER_LEN..].to_vec(),
    })
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &NetMessage,
    max_frame_len: usize,
) -> Result<()> {
    let encoded = encode_frame(message, max_frame_len)?;
    writer.write_all(&encoded).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    expected_session: SessionId,
    expected_to: PartyId,
    max_frame_len: usize,
) -> Result<NetMessage> {
    let len = reader.read_u32().await? as usize;
    if len > max_frame_len {
        return Err(MpcError::Frame("frame exceeds maximum length".to_string()));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).await?;
    decode_frame_body(&body, expected_session, expected_to, max_frame_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_session() {
        let session = SessionId::from_u64_for_testing(1);
        let msg = NetMessage {
            session_id: session,
            from: PartyId::P0,
            to: PartyId::P1,
            kind: MessageKind::Open,
            counter: 7,
            payload: vec![1, 2, 3],
        };
        let encoded = encode_frame(&msg, DEFAULT_MAX_FRAME_LEN).unwrap();
        let body = &encoded[4..];
        let err = decode_frame_body(
            body,
            SessionId::from_u64_for_testing(2),
            PartyId::P1,
            DEFAULT_MAX_FRAME_LEN,
        )
        .unwrap_err();
        assert!(matches!(err, MpcError::SessionMismatch));
    }

    #[test]
    fn rejects_wrong_recipient() {
        let session = SessionId::from_u64_for_testing(1);
        let msg = NetMessage {
            session_id: session,
            from: PartyId::P0,
            to: PartyId::P1,
            kind: MessageKind::Open,
            counter: 7,
            payload: vec![],
        };
        let encoded = encode_frame(&msg, DEFAULT_MAX_FRAME_LEN).unwrap();
        let body = &encoded[4..];
        let err = decode_frame_body(body, session, PartyId::P2, DEFAULT_MAX_FRAME_LEN).unwrap_err();
        assert!(matches!(err, MpcError::PeerMismatch { .. }));
    }
}
