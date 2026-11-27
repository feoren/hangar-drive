# Hangar Drive

**End-to-end encrypted file sync on your own server.**

Hangar Drive will keep your folders in sync across all your computers, like OneDrive or Google
Drive, but with a server you run yourself. Files are encrypted on your device before they leave it:
the server stores contents, file names and paths only in encrypted form. What it can see is
metadata: padded object sizes, how many objects there are and when they change. The server, a
single Docker container, distributes every change to your other devices and keeps earlier versions
as a backup.

Hangar Drive is part of the Hangar family of desktop apps and is open source under the
[MIT License](LICENSE).

> **Status: early development, not yet released.** The desktop app, the sync engine, the shared
> protocol crate, the crypto crate and the sync server work together end to end: accounts by invite,
> pairing further devices, syncing folders, earlier versions, a trash and recovery with a recovery
> code. The cryptography has not been reviewed externally yet. Do not use it for data you have no
> other copy of.

## Repository layout

| Path                           | What it is                                                          |
| ------------------------------ | ------------------------------------------------------------------- |
| `src/`                         | Frontend: React and TypeScript, rendered by Tauri                   |
| `src-tauri/`                   | Desktop app: Tauri 2 (Rust)                                         |
| `crates/hangar-drive-protocol` | Wire types and protocol version shared by the app and the server    |
| `crates/hangar-drive-crypto`   | End-to-end cryptography: device keys, account log, objects, commits |
| `server/`                      | Sync server (Rust, axum) and its Dockerfile                         |
| `docs/wiki/`                   | Design notes and decisions                                          |

All Rust packages form one Cargo workspace at the repository root.

## Development

You need Rust (stable), Node.js 24, pnpm and the
[Tauri prerequisites](https://v2.tauri.app/start/prerequisites/) for your platform.

```sh
pnpm install
pnpm tauri dev
```

Before a pull request, the whole check suite must pass:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
pnpm format:check && pnpm lint && pnpm test && pnpm build
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the guidelines.

## Running the server

With Docker, from the repository root:

```sh
docker compose up -d --build
curl http://localhost:8080/api/v1/health
```

Compose needs `HANGAR_DRIVE_PUBLIC_URL`, the address devices reach the server under, in a `.env`
file next to `docker-compose.yml` (for a first test on this machine, `http://localhost:8080/`). The
health endpoint answers with the server version and the protocol version, for example
`{"version":"0.1.0","protocol_version":1}`. Data lives in the Docker volume `drive-data`. The
Compose file binds the port to localhost only; devices reach the server through a reverse proxy
with TLS in front of it, and sign in with keys from an invite link that
`hangar-drive-server invite` prints. [docs/self-hosting.md](docs/self-hosting.md) covers the
reverse proxy, invites, every setting, backups and updates.

Without Docker:

```sh
cargo run -p hangar-drive-server
```

| Variable                  | Default     | Meaning                                                                          |
| ------------------------- | ----------- | -------------------------------------------------------------------------------- |
| `HANGAR_DRIVE_PUBLIC_URL` | none        | Address devices reach the server under, for invite links (required for `invite`) |
| `HANGAR_DRIVE_BIND`       | `127.0.0.1` | Address to listen on; the Docker image sets `0.0.0.0`                            |
| `HANGAR_DRIVE_PORT`       | `8080`      | TCP port the server uses                                                         |
| `HANGAR_DRIVE_DATA_DIR`   | `data`      | Folder for the server's data                                                     |
| `RUST_LOG`                | `info`      | Log level                                                                        |

The other settings (retention, quotas, rate limits, TLS, trusted proxies) are listed in
[docs/self-hosting.md](docs/self-hosting.md).

The server stops cleanly on Ctrl+C and on SIGTERM (`docker stop`).

## Security

Please report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
