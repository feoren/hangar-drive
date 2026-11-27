<p align="center">
  <img src="src-tauri/icons/128x128.png" alt="Hangar Drive logo" width="96" height="96">
</p>

<h1 align="center">Hangar Drive</h1>

<p align="center"><strong>Your files on all your computers, on your own server. Only your devices can read them.</strong></p>

<p align="center">
  <a href="#how-it-works">How it works</a> ·
  <a href="#getting-started">Getting started</a> ·
  <a href="#what-the-server-sees">What the server sees</a> ·
  <a href="#faq">FAQ</a> ·
  <a href="docs/self-hosting.md">Self-hosting</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

<p align="center">
  <a href="https://github.com/feoren/hangar-drive/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/feoren/hangar-drive/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue"></a>
  <img alt="Status: early development" src="https://img.shields.io/badge/status-early%20development-orange">
</p>

Cloud drives are convenient, but the company behind them can read every file you put there.
**Hangar Drive keeps your folders in sync across your computers the way OneDrive or Google Drive
does, with a server you run yourself, and encrypts every file on your device before it leaves.**

The server is a single Docker container. It stores your files only in encrypted form, hands every
change to your other devices and keeps earlier versions, so a deleted or overwritten file can come
back. Neither the server nor anyone who runs it can read your contents, file names or folder
structure.

Hangar Drive is part of the [Hangar](https://github.com/feoren/hangar) family of desktop apps. The
app, the sync server and the protocol are open source under the MIT license.

> [!WARNING]
> **Early development, not yet released.** The desktop app, the sync engine and the server work
> together end to end, and the code has been through an internal security review, but the
> cryptography has **not been reviewed externally** yet. Do not use Hangar Drive for files you have
> no other copy of.

## Features

### Sync that stays out of your way

- **Plain folders, kept in sync.** Pick a folder on each computer; Hangar Drive keeps them the same.
  Your files stay ordinary files that every program can open, also offline.
- **Lives in the tray.** The app starts with your computer and stays quiet while everything is fine.
  The tray icon shows when it is working, when it needs you and when the server is out of reach;
  being offline on a laptop is normal and shown in grey, not as an error.
- **Only what changed travels.** Files are split into encrypted chunks, and a chunk your folder
  already holds is not uploaded again. Interrupted transfers resume where they stopped.
- **One window to look, not to work.** Folders with their size, the devices of your account, recent
  activity and, only when needed, one clear question with a safe default.

### Nothing is ever lost silently

- **Earlier versions.** The server keeps every replaced version for 30 days (the operator can choose
  another period). Pick a point in time for a folder, see what differs from now and restore single
  files or everything.
- **A trash you can trust.** Deleted files stay restorable for the retention period. The app never
  pretends to delete for good what only the server's operator can delete.
- **Conflicts keep both versions.** When two devices change the same file, both versions stay, the
  second one named after its device and the date. A change always beats a delete.
- **Mass deletions ask first.** When many files disappear at once, on this computer or coming from
  another device, Hangar Drive holds the deletions and asks you. The question names the device and
  since when it belongs to your account, so a stolen or compromised device cannot pass for another.
- **Ransomware protection on the server.** A sudden burst of replaced files makes the server pin the
  last good state for up to 90 days and warn every device.
- **A missing folder pauses.** An unplugged drive or a renamed folder never looks like "delete
  everything".

### Your devices, your keys

- **Start with one link.** The server's operator creates an invite link; you paste it, keep a
  recovery code and choose a folder. That is the whole setup.
- **Add a device by pairing.** Your existing device shows a pairing link, the new one pastes it, and
  you confirm the new device on the old one. No password is involved anywhere.
- **Remove a lost device.** Removing a device rotates the account's keys, so it cannot read anything
  that changes afterwards.
- **A recovery sheet for the worst case.** Lost every device? The recovery sheet brings your account
  back on a new computer. You choose which old devices to remove at the same time, and the recovery
  either happens completely or not at all.

### Made for people, not for admins

- **Twelve languages.** English, German, Spanish, French, Italian, Portuguese, Polish, Russian,
  Turkish, Greek, Japanese and Chinese.
- **Accessible.** Every action works by keyboard and screen reader, down to a window of 640 × 420.
- **Two settings.** Start at sign-in and language. Everything else has a good default instead of a
  switch.
- **Light and dark** following your system, in the look of the Hangar family.

## How it works

```text
  Laptop                         Your server                      Desktop
  ┌─────────────────┐           ┌──────────────────┐           ┌─────────────────┐
  │ folder (plain)  │  encrypt  │ encrypted chunks │  decrypt  │ folder (plain)  │
  │ Hangar Drive  ──┼──────────>│ signed history   │──────────>┼── Hangar Drive  │
  │ device key      │   HTTPS   │ versions, trash  │   HTTPS   │ device key      │
  └─────────────────┘           └──────────────────┘           └─────────────────┘
```

- **Every device has its own key pair**, created on the device and kept in the operating system's
  credential store. The server never sees a private key.
- **Every change is signed** by the device that made it. The server cannot forge or reorder
  changes, a device notices when the server shows it an older state, and comparing the folder
  number on two devices shows whether the server hides changes from one of them.
- **Folder keys are sealed under an account key that is wrapped for each device.** Removing a
  device rotates the keys, so a removed device reads nothing that changes later.
- **Building blocks:** Ed25519 signatures, HPKE with X25519 for key wrapping, XChaCha20-Poly1305 for
  contents and records, HKDF-SHA256 and HMAC-SHA-256. The reasons for every choice, and the threat
  model they follow, are in [ADR 0001](docs/wiki/pages/decisions/0001-foundation.md).

## Getting started

Hangar Drive has no official installer yet. Until the first release you build the app yourself
(see [Build from source](#build-from-source)) and run your own server.

1. **Run the server.** On a Linux host with Docker:

   ```sh
   git clone https://github.com/feoren/hangar-drive.git
   cd hangar-drive
   cp .env.example .env          # then set HANGAR_DRIVE_PUBLIC_URL
   docker compose up -d --build
   curl http://localhost:8080/api/v1/health
   ```

   Put a reverse proxy with TLS in front of it. [docs/self-hosting.md](docs/self-hosting.md) walks
   through Caddy or nginx, every setting, backups and updates.

2. **Create an invite.** On the server:

   ```sh
   docker compose exec server hangar-drive-server invite
   ```

   It prints a link that creates exactly one account and stays valid for 7 days. No terminal on
   the host? Until the first account exists, the server prints such a link in its log at every
   start.

3. **Set up your first computer.** Open the link, or start Hangar Drive, choose _Start with an
   invite link_ and paste it. Keep the recovery sheet somewhere safe and pick the folder to sync.

4. **Add your other computers.** On the first one open _Devices > Add device_, and on the new one
   choose _I already use Hangar Drive on another device_ and paste the pairing link.

## What the server sees

The server has to store and route your data, so it learns some metadata. It never learns what is
inside.

| The server sees                                                             | The server never sees                 |
| --------------------------------------------------------------------------- | ------------------------------------- |
| How many objects an account stores, and their sizes rounded up by padding   | File contents                         |
| When objects are uploaded, replaced and fetched                             | File and folder names, paths          |
| Which device made a change, and how many devices and folders an account has | Folder structure                      |
| The IP addresses devices connect from                                       | Keys, the recovery code, device names |

Your synced files lie unencrypted on your own computers, like any other file. Turn on your system's
drive encryption (BitLocker, FileVault, LUKS) to protect them there.

## Requirements

|             |                                                                                                                       |
| ----------- | --------------------------------------------------------------------------------------------------------------------- |
| Desktop app | Windows 10 version 1809 or later, or Windows 11 (x64). macOS 13+ and Linux x64 are planned.                           |
| Server      | A Linux host with Docker and Docker Compose 2.24 or newer, or the server binary built from source.                    |
| Network     | A domain name pointing to the server for TLS, or a self-signed certificate the devices pin.                           |
| Disk        | More than the size of your files, because old versions are kept; see [Disk sizing](docs/self-hosting.md#disk-sizing). |

## FAQ

**How is this different from OneDrive, Google Drive or Dropbox?**
The server is yours, and it cannot read your files. Hangar Drive also never asks for an account at a
company: an invite from your own server is enough.

**Can the person who runs the server read my files?**
No. Contents, names and paths are encrypted on your device with keys the server never has. The
operator can see the metadata listed in [What the server sees](#what-the-server-sees), and can delete
data on their own server.

**What happens if I lose all my devices?**
Use the recovery sheet on a new computer. Without the sheet and without any device left, nobody can
decrypt your files, not even the server's operator. Keep the sheet safe.

**What if my server breaks?**
Your devices still hold all current files. Back up the server's data folder as described in
[Backups](docs/self-hosting.md#backups-3-2-1) to keep earlier versions as well.

**Can I share a folder with other people?**
Not yet. Version 1 syncs one person's devices. The formats are prepared for sharing, so adding it
later will not need re-encryption.

**Why does Windows show a SmartScreen warning?**
Installers are not signed with a code signing certificate yet, so Windows warns about one that was
downloaded. Choose _More info_ and _Run anyway_.

**What does Hangar Drive not sync?**
Symbolic links, junctions, network drives as sync folders, alternate data streams, ACLs and Windows
attributes such as hidden or read-only. Files on demand (placeholders) are not part of version 1.
The full list is in [ADR 0001](docs/wiki/pages/decisions/0001-foundation.md).

## Build from source

You need [Git](https://git-scm.com), [Rust](https://rustup.rs) (the version pinned in
`rust-toolchain.toml` is installed automatically), [Node.js](https://nodejs.org) 24,
[pnpm](https://pnpm.io) and the [Tauri 2 prerequisites](https://v2.tauri.app/start/prerequisites/)
for your platform.

```sh
git clone https://github.com/feoren/hangar-drive.git
cd hangar-drive
pnpm install

# Run in development mode with hot reload
pnpm tauri dev

# Build your own Windows installer
pnpm tauri build --bundles nsis
```

The installer lands in `target/release/bundle/nsis/`.

To run the server without Docker:

```sh
HANGAR_DRIVE_PUBLIC_URL=http://localhost:8080/ cargo run -p hangar-drive-server
```

| Variable                      | Default     | Meaning                                                       |
| ----------------------------- | ----------- | ------------------------------------------------------------- |
| `HANGAR_DRIVE_PUBLIC_URL`     | none        | Address devices reach the server under; required              |
| `HANGAR_DRIVE_BIND`           | `127.0.0.1` | Address to listen on; the Docker image sets `0.0.0.0`         |
| `HANGAR_DRIVE_PORT`           | `8080`      | TCP port                                                      |
| `HANGAR_DRIVE_DATA_DIR`       | `data`      | Folder for the server's data; `/data` in the image            |
| `HANGAR_DRIVE_RETENTION_DAYS` | `30`        | How long a replaced version stays restorable                  |
| `HANGAR_DRIVE_QUOTA`          | `100GiB`    | Bytes of current files per account; old versions do not count |
| `RUST_LOG`                    | `info`      | Log level                                                     |

Rate limits, TLS, trusted proxies and every other setting are described in
[docs/self-hosting.md](docs/self-hosting.md#configuration).

### Repository layout

| Path                           | What it is                                                          |
| ------------------------------ | ------------------------------------------------------------------- |
| `src/`                         | Frontend: React 19 and TypeScript, rendered by Tauri                |
| `src-tauri/`                   | Desktop app shell: Tauri 2 (Rust)                                   |
| `crates/hangar-drive-sync`     | Sync engine: scanning, planning, applying, conflicts, recovery      |
| `crates/hangar-drive-crypto`   | End-to-end cryptography: device keys, account log, objects, commits |
| `crates/hangar-drive-protocol` | Wire types and protocol version shared by the app and the server    |
| `server/`                      | Sync server (Rust, axum, SQLite) and its Dockerfile                 |
| `docs/wiki/`                   | Design notes, the threat model and every decision with its reasons  |

All Rust packages form one Cargo workspace at the repository root.

## Contributing

Bug reports, ideas and pull requests are welcome. Before a pull request the check suite must pass;
its core is:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
pnpm format:check && pnpm lint && pnpm test && pnpm build
```

[CONTRIBUTING.md](CONTRIBUTING.md) lists the full suite with its Python checks and explains the
guidelines, and [`docs/wiki`](docs/wiki/index.md) records how things work and why.

## Security

Hangar Drive exists to keep your files private, so security reports matter most. Please report
vulnerabilities privately as described in [SECURITY.md](SECURITY.md), never in a public issue.

## License

Hangar Drive is licensed under the [MIT License](LICENSE). Third-party components and their licenses
are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
