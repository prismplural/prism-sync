# Security Policy

`prism-sync` handles key material, authentication, and end-to-end encryption.
Security reports are taken seriously.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems. Instead,
email **security@prismplural.com** (PGP key on request) with:

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

## Known limitations

These are properties we do **not** currently defend against. They are accepted
tradeoffs, not bugs — reports of them are welcome but won't be treated as
vulnerabilities unless paired with a break of confidentiality or authenticity.

- **No fork / selective-withholding detection (SUNDR fork-consistency gap).**
  Batch signatures give authenticity of every batch that *is* delivered, but
  there is no per-(device, epoch) sequence chain or signed receipt, so they say
  nothing about *completeness*. An untrusted relay can therefore selectively
  withhold, reorder, or censor specific signed batches to a target device
  **undetectably** — e.g. hiding a delete/tombstone, a member update, or a
  device revocation from one device while still delivering it to others. The
  result is silent state divergence between devices. Because pruning makes
  sequence gaps legitimate, a censorship gap is indistinguishable from a prune
  gap, and no client-side signal is raised. This is a consistency/availability
  limitation, **not** a confidentiality or authenticity break: the relay can
  always censor or deny service, and per-batch authenticity and end-to-end
  confidentiality are unaffected. We do not yet implement fork detection (e.g. a
  signed per-(device, epoch) sequence or periodic signed high-water statements
  that peers cross-check).

## Coordinated disclosure

We'll work with you on a fix and a disclosure timeline. Please give us a
reasonable window (typically 90 days) before any public writeup.
