<p align="center">
  <img src="src-tauri/icons/128x128@2x.png" alt="Hangar Drive logo" width="96" height="96">
</p>

<h1 align="center">Hangar Drive</h1>

<p align="center"><strong>Your files on all your computers, on your own server. Only your devices can read them.</strong></p>

<p align="center">
  <a href="https://hangar.feoren.com">Website</a> ·
  <a href="https://github.com/feoren/hangar-drive/releases/latest">Download</a> ·
  <a href="#getting-started">Getting started</a> ·
  <a href="#security-and-privacy">Security and privacy</a> ·
  <a href="#run-your-own-server">Run your own server</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

<p align="center">
  <a href="https://github.com/feoren/hangar-drive/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/feoren/hangar-drive/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/feoren/hangar-drive/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/feoren/hangar-drive"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue"></a>
  <img alt="Platform: Windows 10 and 11" src="https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D4">
  <img alt="Built with Tauri 2" src="https://img.shields.io/badge/built%20with-Tauri%202-24C8DB?logo=tauri&logoColor=white">
  <a href="https://buymeacoffee.com/feoren"><img alt="Buy me a coffee" src="https://img.shields.io/badge/buy%20me%20a%20coffee-support-ffdd00?logo=buymeacoffee&logoColor=black"></a>
</p>

Hangar Drive keeps folders in sync across your computers, like OneDrive or Google Drive, but with a
server you run yourself. Every file is encrypted on your device before it leaves, so the server
stores your data without being able to read it. **Your files stay yours, and so does the server.**

It is made for people who want the convenience of a cloud drive without handing their files to a
company, and for the person in a family or small office who runs the server for them. The desktop
app, the sync server and the protocol are open source under the MIT license. Hangar Drive is part
of the [Hangar](https://github.com/feoren/hangar) family of desktop apps.

<picture>
  <source media="(prefers-color-scheme: light)" srcset="docs/images/hangar-drive-light.png">
  <img alt="The Hangar Drive window with four synced folders: Documents with 1,234 files and 2.4 GB, up to date; Photos with 18,406 files, uploading 117; Projects with 5,912 files, downloading 3; and Music with 4,870 files, up to date. Each row shows the folder's path, and Add folder sits below the list. The header shows the version 0.1.0 with a beta badge, the upload at 4.1 MB/s and the download at 1.5 MB/s as small graphs of the last minute, and the status Syncing 120 files" src="docs/images/hangar-drive-dark.png">
</picture>

**Status:** beta. Version 0.1.0 is out for Windows 10 and 11 (x64) on the
[releases page](https://github.com/feoren/hangar-drive/releases); macOS and Linux are planned. The
code has been through internal security reviews, but the cryptography has **not been reviewed
externally**. Do not use Hangar Drive for files you have no other copy of. What is built and what is
planned is listed below.

## Features

### Sync that stays out of your way

- **Plain folders.** Pick a folder on each computer and Hangar Drive keeps them the same. Your
  files stay ordinary files that every program can open, also offline.
- **Lives in the tray.** The app starts with your computer and stays quiet while all is well. The
  tray icon shows when it is working, when it needs you and when the server is out of reach. Being
  offline on a laptop is normal and shown in grey, not as an error.
- **Only what changed travels.** Files are split into encrypted chunks, and a chunk the folder
  already holds is not uploaded again.
- **A fast first sync.** Each device sends up to four uploads at once. A large first upload is
  committed in steps, so your other devices see the folder grow instead of waiting for the end.
- **Interrupted uploads resume.** Objects the server already holds are never sent again, and the
  server keeps uploads that are not yet part of a version for 24 hours.
- **You see what is happening.** Each folder shows its size and number of files. While data moves,
  the header shows upload and download rates of the last minute, with the totals since start in
  its tooltip. The window stays responsive during a long first sync.

### Nothing is lost silently

- **Earlier versions.** The server keeps every replaced version for 30 days by default. Pick a
  point in time for a folder, see what differs from now, and restore single files or everything.
- **A trash you can trust.** Deleted files stay restorable for the same period. The app never
  pretends to delete for good what only the server's operator can delete.
- **Conflicts keep both versions.** When two devices change the same file, both versions stay; the
  second is named after its device and the date. A change always wins over a delete.
- **Mass deletions ask first.** When many files disappear at once, on this computer or from another
  device, Hangar Drive holds the deletions and asks you. The question names the device and since
  when it belongs to your account, so a stolen device cannot pass for another one.
- **Ransomware protection on the server.** A sudden burst of replaced files makes the server pin the
  last good state for up to 90 days and warn every device.
- **A missing folder pauses.** An unplugged drive or a renamed folder never looks like "delete
  everything".

### Your devices, your keys

- **Start with one link.** The server's operator creates an invite link. You paste it, keep the
  recovery sheet and choose a folder. That is the whole setup.
- **Add a device by pairing.** Your existing device shows a pairing link, the new one pastes it, and
  you confirm the new device on the old one. There is no password anywhere.
- **Remove a lost device.** Removing a device rotates the account's keys, so it cannot read anything
  that changes afterwards.
- **A recovery sheet for the worst case.** Lost every device? The recovery sheet brings your account
  back on a new computer. You choose which old devices to remove, and the recovery either completes
  or changes nothing.

### Made for people, not for admins

- **Twelve languages.** English, German, Spanish, French, Italian, Portuguese, Polish, Russian,
  Turkish, Greek, Japanese and Chinese.
- **Accessible.** Every action works by keyboard and screen reader, down to a window of 640 × 420.
- **Two settings.** Start at sign-in, and language. Everything else has a sensible default.
- **Light and dark**, following your system, in the look of the Hangar family.

## Screenshots

<table>
  <tr>
    <td width="50%" valign="top">
      <picture>
        <source media="(prefers-color-scheme: light)" srcset="docs/images/hangar-drive-invite-light.png">
        <img alt="Step 1 of 3 of the setup, Connect to your server: the invite link https://drive.example.org/join#k7Qm2xR9 pasted into the Invite link field next to a Paste button, the line Connected to drive.example.org with a check mark below it, the field Name of this device filled with Work laptop, and the buttons Back and Continue" src="docs/images/hangar-drive-invite-dark.png">
      </picture>
      <br><sub>The whole setup starts with one invite link from the server's operator.</sub>
    </td>
    <td width="50%" valign="top">
      <picture>
        <source media="(prefers-color-scheme: light)" srcset="docs/images/hangar-drive-add-device-light.png">
        <img alt="The dialog Add a new device with three numbered steps: install Hangar Drive on the new device, choose I already use Hangar Drive on another device there, and scan this code or paste the link there; below them a QR code, the button Copy link, the note Valid until 02:40 PM, for one device only, the server drive.example.org with the account number, the link Cannot copy? Show a code to type, and Cancel" src="docs/images/hangar-drive-add-device-dark.png">
      </picture>
      <br><sub>A new device joins with a pairing link or QR code from one you already use.</sub>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <picture>
        <source media="(prefers-color-scheme: light)" srcset="docs/images/hangar-drive-devices-light.png">
        <img alt="The dialog Your devices with the button Add device: Work laptop marked as This device, Office PC last seen 5 min. ago, and Old laptop last seen 3 mo. ago with the note Not seen for a long time. Remove it if you no longer have it, and a Remove button; below them the recovery code, created on Oct 28, with the button Create new" src="docs/images/hangar-drive-devices-dark.png">
      </picture>
      <br><sub>Your devices at a glance; one that has been gone for months is offered for removal.</sub>
    </td>
    <td width="50%" valign="top">
      <picture>
        <source media="(prefers-color-scheme: light)" srcset="docs/images/hangar-drive-versions-light.png">
        <img alt="The dialog Earlier versions of Documents with the tabs Versions and Trash: on the left a timeline with four versions from today and yesterday, each with its time, its device and what changed, such as 02:05 PM Work laptop, 3 files changed; on the right the chosen state compared to now, Report.docx different and Notes.txt missing now, each with a Restore button, and the button Reset the whole folder to this state" src="docs/images/hangar-drive-versions-dark.png">
      </picture>
      <br><sub>Pick a point in time, see what differs from now and restore single files or everything.</sub>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <picture>
        <source media="(prefers-color-scheme: light)" srcset="docs/images/hangar-drive-conflicts-light.png">
        <img alt="The dialog Files in two versions for Report.docx in the folder Projects: the version from Office PC, 40 min. ago, 48.2 kB, and the version named Report (conflict Work laptop 2026-11-27).docx from Work laptop, 35 min. ago, 51.9 kB, each with Keep this one, and the buttons Open both and Keep both" src="docs/images/hangar-drive-conflicts-dark.png">
      </picture>
      <br><sub>When two devices change the same file, both versions stay until you choose.</sub>
    </td>
    <td width="50%" valign="top">
      <picture>
        <source media="(prefers-color-scheme: light)" srcset="docs/images/hangar-drive-mass-delete-light.png">
        <img alt="The question 342 files deleted over the main window: 342 files were deleted in Photos, should they disappear from your other devices too, with the first names Holiday 001.jpg to Holiday 003.jpg and 339 more, the link Show list, the note They stay in the trash for 30 days, and the buttons Yes, delete and Restore; the header says Needs your help" src="docs/images/hangar-drive-mass-delete-dark.png">
      </picture>
      <br><sub>Many files gone at once? The deletions wait until you say yes.</sub>
    </td>
  </tr>
</table>

## Getting started

### Install

Download `Hangar Drive_<version>_x64-setup.exe` and `SHA256SUMS.txt` from the
[releases page](https://github.com/feoren/hangar-drive/releases) and run the installer. It installs
for your user only. The installer is not code-signed yet, so Windows SmartScreen warns on the first
start; check the file against `SHA256SUMS.txt` first, for example with `Get-FileHash` in PowerShell.
You can also [build Hangar Drive from source](#build-from-source).

New versions are not delivered automatically yet: download them from the releases page. The app
installs an update only with a valid signature.

### First steps

You need a server that you or someone you trust runs (see
[Run your own server](#run-your-own-server)).

1. **Get an invite link** from the server's operator. It creates exactly one account and is valid
   for 7 days by default.
2. **Set up your first computer.** Open the link, or start Hangar Drive, choose _Start with an
   invite link_ and paste it. Keep the recovery sheet somewhere safe and pick the folder to sync.
3. **Add your other computers.** On the first one open _Devices > Add device_. On the new one choose
   _I already use Hangar Drive on another device_ and paste the pairing link.

Lost every device? Choose _No device left? Use your recovery sheet_ on a new computer.

## Security and privacy

Your files leave your computer only encrypted: the server stores and forwards them, but it cannot
read them.

```text
  Laptop                         Your server                      Desktop
  +-----------------+           +------------------+           +-----------------+
  | folder (plain)  |  encrypt  | encrypted chunks |  decrypt  | folder (plain)  |
  | Hangar Drive    |---------->| signed history   |---------->| Hangar Drive    |
  | device key      |   HTTPS   | versions, trash  |   HTTPS   | device key      |
  +-----------------+           +------------------+           +-----------------+
```

- **Every device has its own key pair.** It is created on the device and kept in the operating
  system's credential store. The server never sees a private key.
- **Every change is signed** by the device that made it. The server cannot forge or reorder
  changes, and a device notices when the server shows it an older state. Comparing a folder's
  safety number on two devices shows whether the server hides changes from one of them.
- **Folder keys are sealed under an account key** that is wrapped for each device. Removing a device
  rotates the keys.
- **A compromised device cannot erase history.** It can rewrite or delete current files, but no
  client call deletes old versions. Quotas and daily budgets keep it from filling the server's disk.
- **Building blocks:** Ed25519 signatures, HPKE with X25519 for key wrapping, XChaCha20-Poly1305
  for contents and records, HKDF-SHA256 and HMAC-SHA-256. The threat model and the reason for every
  choice are in [ADR 0001](docs/wiki/pages/decisions/0001-foundation.md).

### What the server sees

The server has to store and route your data, so it learns some metadata. It never learns what is
inside.

| The server sees                                                             | The server never sees                 |
| --------------------------------------------------------------------------- | ------------------------------------- |
| How many objects an account stores, and their sizes rounded up by padding   | File contents                         |
| When objects are uploaded, replaced and fetched                             | File and folder names, paths          |
| Which device made a change, and how many devices and folders an account has | Folder structure                      |
| The IP addresses devices connect from                                       | Keys, the recovery code, device names |

### What it does not protect

- **Files on your computers.** Synced files lie unencrypted on your own disks, like any other file.
  Turn on drive encryption (BitLocker, FileVault, LUKS) to protect them there.
- **Your user account.** Anyone who can run programs as your user can use the app's device keys.
  [SECURITY.md](SECURITY.md#installation-per-user) explains what the installation keeps where.
- **Availability.** The operator can delete data on their own server. Keep backups of the server
  ([Backups](docs/self-hosting.md#backups-3-2-1)).

## Run your own server

On a Linux host with Docker and Docker Compose 2.24 or newer:

```sh
git clone https://github.com/feoren/hangar-drive.git
cd hangar-drive
cp .env.example .env          # set HANGAR_DRIVE_PUBLIC_URL, for example https://drive.example.org/
docker compose up -d --build
curl http://localhost:8080/api/v1/health
docker compose exec server hangar-drive-server invite
```

The last command prints the invite link for the first account. The server listens on `127.0.0.1`
only; devices reach it through a reverse proxy with TLS. The image is a static binary on a
distroless base, running as an unprivileged user. The Compose file adds a read-only root file
system, drops all capabilities and sets memory and process limits.

The [self-hosting guide](docs/self-hosting.md) covers the rest:

- [Reverse proxy](docs/self-hosting.md#reverse-proxy) with Caddy, nginx or
  [Nginx Proxy Manager](docs/self-hosting.md#nginx-proxy-manager), or
  [TLS in the server](docs/self-hosting.md#tls-in-the-server-instead-of-a-proxy)
- [Install on a NAS](docs/self-hosting.md#on-a-nas-bind-mount-and-your-own-user) without a
  terminal: until the first account exists, the server prints an invite link in its log at every
  start
- [Configuration](docs/self-hosting.md#configuration) with every variable, budget and rate limit
- [Backups](docs/self-hosting.md#backups-3-2-1), [updates](docs/self-hosting.md#updates),
  [disk sizing](docs/self-hosting.md#disk-sizing) and the
  [admin commands](docs/self-hosting.md#admin-commands)

The server reads its settings from environment variables; with Compose, put them into `.env`. The
most important ones:

| Variable                          | Default  | Purpose                                                              |
| --------------------------------- | -------- | -------------------------------------------------------------------- |
| `HANGAR_DRIVE_PUBLIC_URL`         | required | Address devices reach the server under; every sign-in is bound to it |
| `HANGAR_DRIVE_RETENTION_DAYS`     | `30`     | Days an old version stays restorable                                 |
| `HANGAR_DRIVE_QUOTA`              | `100GiB` | Bytes of current files per account; old versions do not count        |
| `HANGAR_DRIVE_UPLOADS_PER_MINUTE` | `1200`   | Uploads per account and minute (`60` to `12000`)                     |
| `HANGAR_DRIVE_TRUSTED_PROXIES`    | empty    | Exact address of your reverse proxy; never a whole range             |
| `HANGAR_DRIVE_HOST_PORT`          | `8080`   | Port Compose publishes on the host's `127.0.0.1`                     |
| `RUST_LOG`                        | `info`   | Log level                                                            |

Every file is at least two uploads, so the default upload rate allows about ten small files a
second.

## Requirements

|             |                                                                                                                       |
| ----------- | --------------------------------------------------------------------------------------------------------------------- |
| Desktop app | Windows 10 version 1809 or later, or Windows 11 (x64). macOS 13+ and Linux x64 are planned.                           |
| Server      | A Linux host with Docker and Docker Compose 2.24 or newer, or the server binary built from source.                    |
| Network     | A domain name pointing to the server for TLS, or a self-signed certificate the devices pin.                           |
| Disk        | More than the size of your files, because old versions are kept; see [Disk sizing](docs/self-hosting.md#disk-sizing). |

## Planned

These parts are not built yet. Design decisions and their reasons are recorded in
[`docs/wiki`](docs/wiki/index.md).

- **macOS 13 or later and Linux x64.** CI already builds and tests the code on both.
- **A code-signed installer and update delivery.** The app already installs an update only with a
  valid signature.
- **An external review of the cryptography.**

Not in version 1: sharing folders with other people (the formats are ready for it) and files on
demand.

## FAQ

**How is this different from OneDrive, Google Drive or Dropbox?**
The server is yours, and it cannot read your files. Hangar Drive never asks for an account at a
company: an invite from your own server is enough.

**Can the person who runs the server read my files?**
No. Contents, names and paths are encrypted on your device with keys the server never has. The
operator sees the metadata listed in [What the server sees](#what-the-server-sees) and can delete
data on their own server.

**What happens if I lose all my devices?**
Use the recovery sheet on a new computer. Without the sheet and without any device left, nobody can
decrypt your files, not even the server's operator.

**What if my server breaks?**
Your devices still hold all current files. Back up the server's data folder as described in
[Backups](docs/self-hosting.md#backups-3-2-1) to keep earlier versions as well.

**Can I share a folder with other people?**
Not yet. Version 1 syncs one person's devices.

**Why does Windows show a SmartScreen warning when I install?**
The installer is not yet signed with a code signing certificate, so Windows does not know it.
Check the file against `SHA256SUMS.txt`, then choose _More info_ and _Run anyway_.

**What does Hangar Drive not sync?**
Symbolic links, junctions, network drives as sync folders, alternate data streams, ACLs and Windows
attributes such as hidden or read-only. The full list is in
[ADR 0001](docs/wiki/pages/decisions/0001-foundation.md).

## Build from source

You need [Git](https://git-scm.com), [Rust](https://rustup.rs) (the toolchain pinned in
`rust-toolchain.toml` installs itself), [Node.js](https://nodejs.org) 24, [pnpm](https://pnpm.io)
and the [Tauri 2 prerequisites](https://v2.tauri.app/start/prerequisites/) for your platform.
Python 3.14 runs the crypto test vectors, and Docker builds the server image.

```sh
git clone https://github.com/feoren/hangar-drive.git
cd hangar-drive
pnpm install

# Run the app in development mode with hot reload
pnpm tauri dev

# Build a Windows installer (lands in target/release/bundle/nsis/)
pnpm tauri build --bundles nsis

# Run the server without Docker
HANGAR_DRIVE_PUBLIC_URL=http://localhost:8080/ cargo run -p hangar-drive-server
```

Without Docker the server listens on `127.0.0.1:8080` and keeps its data in `./data`.

**Check suite.** Everything must pass before a pull request is merged. Run `pnpm build` before the
first Cargo build, because the app embeds the built frontend:

```sh
pnpm format:check && pnpm lint && pnpm test && pnpm build
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

[CONTRIBUTING.md](CONTRIBUTING.md) lists the full suite with its Python checks. CI runs it on
Windows, macOS and Linux, builds and starts the server image, and audits the dependencies and
their licenses.

**Screenshots.** `pnpm readme:shots` renders the images in `docs/images/` from the real interface
with the mock backend and made-up example data, in a headless Microsoft Edge, Google Chrome or
Chromium.

## Architecture

```text
Desktop app
|  src/                   React 19 UI: renders state, calls approved backend commands only
|  src-tauri/             Tauri 2 shell: window, tray, OS credential store, settings
|  hangar-drive-sync      sync engine: scan, plan, upload, download, conflicts, recovery
|  hangar-drive-crypto    device keys, account log, encrypted objects, signed commits
|  hangar-drive-protocol  wire types and protocol version
|
|  HTTPS through your reverse proxy
v
Sync server (Docker image)
   server/                axum HTTP API and event stream, SQLite metadata, encrypted
                          objects on disk; shares the protocol and crypto crates
```

The app and the server share the protocol crate, and the server checks signatures with the same
crypto crate as the app. All Rust packages form one Cargo workspace at the repository root.

| Path                           | What it is                                                          |
| ------------------------------ | ------------------------------------------------------------------- |
| `src/`                         | Frontend: React 19 and TypeScript, rendered by Tauri                |
| `src-tauri/`                   | Desktop app shell: Tauri 2 (Rust)                                   |
| `crates/hangar-drive-sync`     | Sync engine: scanning, planning, applying, conflicts, recovery      |
| `crates/hangar-drive-crypto`   | End-to-end cryptography: device keys, account log, objects, commits |
| `crates/hangar-drive-protocol` | Wire types and protocol version shared by the app and the server    |
| `server/`                      | Sync server (Rust, axum, SQLite) and its Dockerfile                 |
| `tools/readme-shots/`          | Renders the README screenshots                                      |
| `docs/wiki/`                   | Design notes, the threat model and every decision with its reasons  |

## Contributing

Bug reports, ideas and pull requests are welcome. For larger changes, please open an issue first.
[CONTRIBUTING.md](CONTRIBUTING.md) explains the setup and the guidelines, and everyone taking part
follows the [Code of Conduct](CODE_OF_CONDUCT.md). Hangar Drive exists to keep your files private,
so security reports matter most: please report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md), never in a public issue.

Related projects: [Hangar](https://github.com/feoren/hangar), the desktop app for running AI coding
agents as a team, and [Hangar Note](https://github.com/feoren/hangar-note), the desktop notes app
that can keep its notes on your server with Hangar Drive.

## Support

Hangar Drive is made in spare time, without investors, ads or tracking. If it saves you time, you
can [buy me a coffee](https://buymeacoffee.com/feoren). Thank you! More about the Hangar family is
on [hangar.feoren.com](https://hangar.feoren.com).

## License

Hangar Drive is licensed under the [MIT License](LICENSE). Third-party components and their licenses
are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
