//! Transport implementations for `smpc-rs`.

mod frame;
mod memory;
mod tls;

pub use frame::{DEFAULT_MAX_FRAME_LEN, decode_frame_body, encode_frame, read_frame, write_frame};
pub use memory::{InMemoryNetwork, InMemoryTransport};
pub use tls::{TcpRustlsConfig, TcpRustlsTransport, TlsIdentity};
