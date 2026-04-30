/// Minimal ring abstraction for v0.1 arithmetic.
pub trait Ring:
    Copy
    + Clone
    + Eq
    + Send
    + Sync
    + 'static
    + core::ops::Add<Output = Self>
    + core::ops::Sub<Output = Self>
    + core::ops::Mul<Output = Self>
{
    fn zero() -> Self;
    fn one() -> Self;
}

/// Marker for wrapping `u64` arithmetic over `Z / 2^64 Z`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WrappingU64;

impl Ring for u64 {
    fn zero() -> Self {
        0
    }

    fn one() -> Self {
        1
    }
}

impl WrappingU64 {
    pub fn add(lhs: u64, rhs: u64) -> u64 {
        lhs.wrapping_add(rhs)
    }

    pub fn sub(lhs: u64, rhs: u64) -> u64 {
        lhs.wrapping_sub(rhs)
    }

    pub fn mul(lhs: u64, rhs: u64) -> u64 {
        lhs.wrapping_mul(rhs)
    }
}
