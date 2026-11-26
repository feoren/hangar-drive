---
title: Threat model and crypto design for version 1 (security review)
type: source
tags: [security, threat-model, e2e, crypto, key-hierarchy, pairing, recovery, rollback, retention]
sources: []
raw: raw/2026-11-26-threat-model-and-crypto-design.md
url:
retrieved: 2026-11-26
created: 2026-11-26
updated: 2026-11-26
---

# Threat model and crypto design

Security review and design proposal for [[0001-foundation]], written against the repository at
commit `fdc2c8b` and the sister desktop app's team crypto crate. Design only, no code.

## Key points
- **Scope:** one person with several devices is right for version 1, but the server operator may
  be a different person, and a compromised client is in scope for the integrity of the history
  (not for confidentiality).
- **Key hierarchy:** device identities (Ed25519 and X25519) in a signed account device log with
  one member, HPKE-wrapped epoch secrets, and per-folder random keys in a generational key ring
  sealed under the account epoch. Folder keys stay independent of epochs, so sharing later needs
  no re-encryption.
- **Content:** no convergent encryption; object IDs are HMAC-SHA-256 keyed hashes, so dedup works
  only inside one folder and key generation; fixed 4 MiB chunks (CDC leaks, see Truong et al.
  2025); Padmé padding; XChaCha20-Poly1305 with random nonces and the recomputed keyed ID as a key
  commitment check.
- **Names:** the server sees no tree; names live in encrypted directory nodes with an NFC
  comparison key.
- **Versions:** a signed, hash-chained commit DAG per folder; each device keeps a frontier and
  refuses a server answer that does not descend from it (rollback), per-device counters and a
  seen vector expose forks; a freeze cannot be detected without a second channel (accepted, with
  a folder safety number).
- **Backup:** retention set only by the operator, no client delete API, a collection rule a
  lying client cannot shorten, anomaly pinning from metadata, quotas.
- **Pairing and recovery:** QR offer with a 128 bit secret and the log head as trust anchor, no
  short codes without a PAKE; a 128 bit recovery code with a printed sheet, no password recovery.
- **Transport:** TLS 1.3, SPKI pinning for self-signed setups, invite-only account creation,
  challenge proof per device, hashed short-lived tokens, trusted-proxy configuration for client
  IPs.
- **Reuse:** extract a shared core from the team crypto crate with a label domain parameter and
  build `hangar-drive-crypto` here (option B); age only for exports, Cryptomator only as ideas.
- **Risks:** hand-built and unreviewed protocol (high, release blocker), one compromised device
  reads everything and can lock others out (high, inherent), server freeze (medium).

> [!warning] Contradiction
> Chunking differs from [[sync-prior-art-research]] (FastCDC with 1 MiB average). Resolved in
> [[0001-foundation]] in favour of this report.

## Significance for Hangar Drive
- Supplies the security part of [[0001-foundation]] almost one to one: decisions 1 to 18 of the
  report map to the ADR's scope, crypto, backup and transport sections.
- Names the external review list that blocks the first release.
