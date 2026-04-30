# smpc-rs

`smpc-rs` is a production-minded Rust SDK for secure multiparty computation.
The v0.1 implementation starts with exactly three-party replicated secret
sharing over wrapping `u64` arithmetic.

## Status

This project is a beta-quality OSS implementation intended for evaluation,
testing, and extension. It is not externally audited and should not be used with
sensitive production data until an independent cryptographic review has been
completed.

Current security model:

- exactly three parties
- semi-honest / passive adversaries
- honest majority, privacy against one corrupted party
- arithmetic over `Z / 2^64 Z`

Out of scope for v0.1: malicious security, comparisons, Boolean circuits,
fixed-point nonlinear ML layers, fairness, guaranteed output delivery, and
production-ready security claims.

## Quickstart

```rust
use smpc_core::{PartyId, SessionId};
use smpc_testing::test_sessions;

#[tokio::main]
async fn main() -> smpc_core::Result<()> {
    let [mut p0, mut p1, mut p2] =
        test_sessions(SessionId::from_u64_for_testing(1))?;

    let t0 = tokio::spawn(async move {
        let x = p0.private_input(PartyId::P0, 7).await?;
        let y = p0.private_input(PartyId::P1, 0).await?;
        let z = p0.mul(&x.add_public(5), &y).await?;
        p0.open(&z).await
    });
    let t1 = tokio::spawn(async move {
        let x = p1.private_input(PartyId::P0, 0).await?;
        let y = p1.private_input(PartyId::P1, 11).await?;
        let z = p1.mul(&x.add_public(5), &y).await?;
        p1.open(&z).await
    });
    let t2 = tokio::spawn(async move {
        let x = p2.private_input(PartyId::P0, 0).await?;
        let y = p2.private_input(PartyId::P1, 0).await?;
        let z = p2.mul(&x.add_public(5), &y).await?;
        p2.open(&z).await
    });

    assert_eq!(t0.await.unwrap()?, 132);
    assert_eq!(t1.await.unwrap()?, 132);
    assert_eq!(t2.await.unwrap()?, 132);
    Ok(())
}
```

Run the simulator example:

```sh
cargo run --example simulator
```

## Workspace

- `smpc-core`: IDs, errors, ring arithmetic, secret types, extension traits.
- `smpc-protocols`: Rep3 protocol over `u64`.
- `smpc-net`: in-memory transport, length-prefixed frames, TCP over rustls.
- `smpc-testing`: deterministic three-party test world and cleartext helpers.

## License

Licensed under the MIT License.
