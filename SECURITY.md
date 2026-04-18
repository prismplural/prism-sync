# Security Policy

`prism-sync` handles key material, authentication, and end-to-end encryption.
Security reports are taken seriously.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems. Instead,
email **security@prism.plural** (PGP key on request) with:

- A description of the issue and its impact
- Steps to reproduce (or a proof-of-concept)
- Which crate or component is affected
- Your name/handle if you'd like to be credited

You should get an acknowledgement within 72 hours. We aim to triage and respond
with a plan within 7 days.

## Scope

In scope:

- `prism-sync-crypto` — key derivation, AEAD, signatures, KEM
- `prism-sync-core` — CRDT merge, pairing, device identity, epoch rotation, relay client
- `prism-sync-ffi` — FFI surface and memory safety at the boundary
- `prism-sync-relay` — authentication, authorization, quota enforcement, WebSocket handling
- The Dart bindings and Flutter integration packages in `dart/packages/`

Out of scope:

- Bugs that require a compromised host or OS
- DoS against a relay you don't operate
- Cryptographic weaknesses in upstream dependencies (report those to the upstream project and let us know)

## What we care about most

- **Key material leakage** — anything that exposes the DEK, DeviceSecret, or derived keys outside of `Zeroizing` buffers or across FFI without clearing
- **Signature / authentication bypass** — forged batches, session tokens, pairing messages
- **CRDT soundness** — tombstone resurrection, HLC ordering bugs that enable rollback, merge states the relay can force
- **Relay server flaws** — authz/quota bypass, cross-tenant data access, SQL injection, protocol confusion

## Coordinated disclosure

We'll work with you on a fix and a disclosure timeline. Please give us a
reasonable window (typically 90 days) before any public writeup.
