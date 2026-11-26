---
title: Overview
type: overview
tags: []
sources: ["[[llm-wiki-pattern]]", "[[sync-prior-art-research]]", "[[threat-model-and-crypto-design]]"]
created: 2026-11-25
updated: 2026-11-26
---

# Overview

Hangar Drive keeps folders in sync across devices through a self-hosted server that also keeps
every version as a backup, end-to-end encrypted. The foundation is decided in [[0001-foundation]]:
central server, plain folders, fixed 4 MiB chunks with keyed IDs, an encrypted tree, a signed
commit DAG per folder with one head on the server and merge commits made by devices, retention
that only the operator sets, and an account quota that counts only live data.

## State of knowledge
- Prior art, change detection, placeholders, storage, transport and Windows pitfalls:
  [[sync-prior-art-research]].
- Threat model, key hierarchy, formats, backup rules and reuse of the sister app's crypto:
  [[threat-model-and-crypto-design]].

## Open risks
- The protocol is built by hand and not reviewed externally; the review blocks the first release.
- One compromised device can read everything and lock out the others (inherent).
- A server can freeze a folder's state without being detected unless devices compare state.
- The single head per folder, its merge rules, the kept commit bodies, the change feed and the
  quota rules are conclusions of [[0001-foundation]], not taken from the sources; they need the
  external review.

## Open questions
> [!question] Unverified
> - `notify` on Windows under bulk copies of 100k files (buffer overflow, rename pairing).
> - Minimum Rust version of the dependency set (raised to 1.91 with `notify` 9, unmeasured).
> - nginx defaults that affect 4 MiB uploads and long-lived SSE connections.
