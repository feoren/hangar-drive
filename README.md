# Hangar Drive

**End-to-end encrypted file sync on your own server.**

Hangar Drive will keep your folders in sync across all your computers, like OneDrive or Google
Drive, but with a server you run yourself. Files are encrypted on your device before they leave it,
so the server only ever stores data it cannot read. The server, a single Docker container,
distributes every change to your other devices and keeps earlier versions as a backup.

Hangar Drive is part of the Hangar family of desktop apps and is open source under the
[MIT License](LICENSE).

> **Status: early development.** This repository holds the project skeleton: the desktop app shell,
> the shared protocol crate and a server that only answers a health check. There is no sync and no
> encryption yet. Do not use it for real data.

## Repository layout

| Path                           | What it is                                                       |
| ------------------------------ | ---------------------------------------------------------------- |
| `src/`                         | Frontend: React and TypeScript, rendered by Tauri                |
| `src-tauri/`                   | Desktop app: Tauri 2 (Rust)                                      |
| `crates/hangar-drive-protocol` | Wire types and protocol version shared by the app and the server |
| `server/`                      | Sync server (Rust, axum) and its Dockerfile                      |
| `docs/wiki/`                   | Design notes and decisions                                       |

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

The health endpoint answers with the server version and the protocol version, for example
`{"version":"0.1.0","protocol_version":1}`. Data lives in the Docker volume `drive-data`. The
Compose file binds the port to localhost only: the server has no TLS and no sign-in yet.

Without Docker:

```sh
cargo run -p hangar-drive-server
```

| Variable                | Default | Meaning                      |
| ----------------------- | ------- | ---------------------------- |
| `HANGAR_DRIVE_PORT`     | `8080`  | TCP port the server uses     |
| `HANGAR_DRIVE_DATA_DIR` | `data`  | Folder for the server's data |
| `RUST_LOG`              | `info`  | Log level                    |

The server stops cleanly on Ctrl+C and on SIGTERM (`docker stop`).

## Security

Please report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
