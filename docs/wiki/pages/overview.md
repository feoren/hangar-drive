---
title: Overview
type: overview
tags: []
sources: ["[[llm-wiki-pattern]]", "[[sync-prior-art-research]]", "[[threat-model-and-crypto-design]]", "[[version-number-wikipedia]]", "[[tauri-version-handling-code-reading]]", "[[tauri-nsis-uninstall-code-reading]]", "[[transfer-responsiveness-measurement]]"]
created: 2026-11-25
updated: 2026-11-28
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
- Version scheme X.Y.Z-B and how Tauri treats build metadata: [[0002-version-scheme]],
  [[version-number-wikipedia]], [[tauri-version-handling-code-reading]].
- Windows installer on upgrade and uninstall: the device keys go only with the ticked "delete app
  data" box, [[tauri-nsis-uninstall-code-reading]] and the amendment in [[0001-foundation]].
- Responsiveness under load: transfers on detached lanes, commands that interrupt a pass,
  parallel downloads in parts with a check before they land, live progress, the HTTP client's
  limits and the server's writer queue: amendment "transfers that never hold the engine thread"
  in [[0001-foundation]], measured in [[transfer-responsiveness-measurement]].

## Open risks
- The protocol is built by hand and not reviewed externally; the review blocks the first release.
- One compromised device can read everything and lock out the others (inherent).
- A server can freeze a folder's state without being detected unless devices compare state.
- The single head per folder, its merge rules, the kept commit bodies, the change feed and the
  quota rules are conclusions of [[0001-foundation]], not taken from the sources; they need the
  external review.
- The installer flow (upgrade, downgrade, uninstall with and without the tick) is verified only
  in a makensis harness, not with a real installer; it is a manual check of the release checklist
  in [[0002-version-scheme]].
- Transfer speed is measured only against the in-memory server with simulated delays; uploads
  and downloads per second against a real server over a network are not measured yet.

## Open questions
> [!question] Unverified
> - `notify` on Windows under bulk copies of 100k files (buffer overflow, rename pairing).
> - Minimum Rust version of the dependency set (raised to 1.91 with `notify` 9, unmeasured).
> - nginx defaults that affect 4 MiB uploads and long-lived SSE connections.
