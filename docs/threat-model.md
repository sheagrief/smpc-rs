# Threat Model

## v0.1 Security Claim

The v0.1 protocol targets exactly three parties using replicated secret sharing
over `Z / 2^64 Z`.

It aims to protect input privacy against one passively corrupted party assuming:

- all parties follow the protocol exactly
- at most one party is corrupted
- PRSS pair seeds are generated securely and only shared with the intended pair
- transport peers are mutually authenticated
- program order is identical across all parties

## Non-Goals

The v0.1 implementation does not claim:

- malicious security
- correctness against deviating parties
- fairness or guaranteed output delivery
- side-channel resistance for arbitrary deployments
- privacy against two colluding parties
- secure comparison, bit decomposition, or Boolean circuit support
- production readiness before independent audit

## Operational Assumptions

TCP deployments must use the rustls transport with explicit peer trust. Plain TCP
is intentionally not exposed as a public v0.1 transport.

Secrets should not be logged. `SecretU64`, `SecretVecU64`, and `Rep3ShareU64`
intentionally avoid `Debug`.
