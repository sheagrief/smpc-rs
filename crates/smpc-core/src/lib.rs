//! Core identifiers, errors, rings, shares, and extension traits.

mod error;
mod ids;
mod ring;
mod secret;
mod traits;

pub use error::{MpcError, Result};
pub use ids::{PARTY_COUNT, PartyId, SessionId};
pub use ring::{Ring, WrappingU64};
pub use secret::{MpcConfig, PublicU64, Rep3ShareU64, SecretU64, SecretVecU64};
pub use traits::{MessageKind, NetMessage, Protocol, Prss, ShareScheme, Transport};
