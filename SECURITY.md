# Security Policy

## Supported Versions

`smpc-rs` is pre-1.0 beta software. Security fixes are provided on the `main`
branch until the project starts publishing tagged releases.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately to the maintainers before
public disclosure. Include:

- affected commit or version
- minimal reproduction or protocol transcript
- expected impact
- whether the issue affects confidentiality, correctness, availability, or API
  misuse resistance

The project will coordinate disclosure once a fix or mitigation is available.

## Current Security Posture

The v0.1 protocol is semi-honest 3PC only. It does not provide malicious
security, fairness, guaranteed output delivery, or protection against parties
that deviate from the protocol. The implementation has not yet received an
external cryptographic audit.
