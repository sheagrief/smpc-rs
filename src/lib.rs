//! Public facade for the `smpc-rs` workspace.
//!
//! This crate re-exports the production-minded v0.1 SDK surface. The initial
//! protocol is semi-honest, honest-majority 3PC over wrapping `u64`
//! arithmetic. It is not externally audited.

pub use smpc_core::*;
pub use smpc_net::{
    InMemoryNetwork, InMemoryTransport, TcpRustlsConfig, TcpRustlsTransport, TlsIdentity,
};
pub use smpc_protocols::{MpcSession, Rep3Prss, Rep3U64};
