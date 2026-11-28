# Hangar Drive server: static musl binary in a distroless image, running as an unprivileged user.
#
# Build from the repository root (the server needs the protocol and crypto crates under crates/):
#   docker build -f server/Dockerfile -t hangar-drive-server .
# or with Compose:
#   docker compose up -d --build
# For amd64 and arm64 at once (both are cross-compiled on the build machine, no emulation):
#   docker buildx build -f server/Dockerfile --platform linux/amd64,linux/arm64 \
#     --build-arg VERSION=<version> --build-arg REVISION=$(git rev-parse HEAD) \
#     --build-arg SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) \
#     -t <registry>/hangar-drive-server:<version> --push .
# VERSION and REVISION fill the image labels below; SOURCE_DATE_EPOCH is read by BuildKit
# itself and dates the image by the last commit instead of the build time.
#
# The base images are pinned by digest (multi-platform index) so that a build is reproducible;
# Dependabot proposes new digests. The Rust tag names the exact toolchain of
# `rust-toolchain.toml`, so the image builds with the compiler the check suite ran with; raise
# both together. To update by hand, take the first "Digest:" line of
#   docker buildx imagetools inspect <image>:<tag>

# Cross-compilation helpers (xx-cargo, xx-apk, xx-verify): compiler, linker and C library of
# the target platform on the build machine's own architecture. An arm64 image builds in minutes
# instead of the hour Rust needs under emulation.
FROM --platform=$BUILDPLATFORM tonistiigi/xx:1.9.0@sha256:c64defb9ed5a91eacb37f96ccc3d4cd72521c4bd18d5442905b95e2226b0e707 AS xx

FROM --platform=$BUILDPLATFORM rust:1.100.0-alpine@sha256:8d0e82abfdf9a38071e07cabc5afba4ddbe077631a80e4e742a760c38beadc33 AS build
COPY --from=xx / /
# clang and lld cross-compile the C parts (SQLite, ring) and link for any target.
RUN apk add --no-cache clang lld
ARG TARGETPLATFORM
# The target's C library and startup files, for its static linking.
RUN xx-apk add --no-cache musl-dev gcc
WORKDIR /src

# Size and speed matter for the image only, so the release settings are set here and not in the
# workspace, where they would slow down the app's release builds as well. Full LTO with one
# codegen unit: 7 % smaller than thin LTO, and a cold build is no slower, since the dependencies
# are only compiled to bitcode. `opt-level` stays 3. `panic` stays `unwind`, because the
# workspace keeps overflow checks on in release builds so that a bad length ends one request:
# with `abort` it would end the whole server.
# The path prefixes are remapped, so the binary names neither the build folder nor the registry
# path (the same binary from the same sources on any machine).
ENV CARGO_PROFILE_RELEASE_LTO=fat \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
    CARGO_PROFILE_RELEASE_STRIP=symbols \
    RUSTFLAGS="--remap-path-prefix=/src=/build --remap-path-prefix=/usr/local/cargo=/cargo"

# 1. Dependencies alone, from the manifests and the lock file: this layer is rebuilt only when
# they change, not on every change to the server's own code. Every workspace member needs its
# manifest and a target for Cargo to read the workspace; only the server and the two crates it
# uses are compiled, and the app (src-tauri) and the sync crate never enter the build context
# with their sources (.dockerignore), so a change there leaves the image's cache alone.
COPY Cargo.toml Cargo.lock ./
COPY crates/hangar-drive-protocol/Cargo.toml crates/hangar-drive-protocol/
COPY crates/hangar-drive-crypto/Cargo.toml crates/hangar-drive-crypto/
COPY crates/hangar-drive-sync/Cargo.toml crates/hangar-drive-sync/
COPY server/Cargo.toml server/
COPY src-tauri/Cargo.toml src-tauri/
RUN for crate in crates/hangar-drive-protocol crates/hangar-drive-crypto \
        crates/hangar-drive-sync server src-tauri; do \
      mkdir -p "$crate/src" && : > "$crate/src/lib.rs"; \
    done \
 && echo 'fn main() {}' > server/src/main.rs
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    xx-cargo build --release --locked --package hangar-drive-server

# 2. The server's code. The placeholders above are newer than the copied files, so their times
# are reset: Cargo compares modification times and would otherwise keep the empty crates.
COPY crates/hangar-drive-protocol/src crates/hangar-drive-protocol/src
COPY crates/hangar-drive-crypto/src crates/hangar-drive-crypto/src
COPY server/src server/src
COPY server/migrations server/migrations
# sqlx keeps a checksum over the exact bytes of each migration: a file with CRLF (a Windows
# checkout with core.autocrlf) would not match a database migrated by an LF build, and the server
# would refuse to start on it.
RUN if grep -l "$(printf '\015')" server/migrations/*.sql; then echo 'migrations with CRLF' >&2; exit 1; fi
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    find crates/hangar-drive-protocol/src crates/hangar-drive-crypto/src server/src \
      server/migrations -type f -exec touch {} + \
 && xx-cargo build --release --locked --package hangar-drive-server \
 && cp "target/$(xx-cargo --print-target-triple)/release/hangar-drive-server" /hangar-drive-server \
 && xx-verify --static /hangar-drive-server \
 && mkdir -p /data-empty

# Only the static binary, for a native install without Docker:
#   docker buildx build -f server/Dockerfile --target binary --output type=local,dest=out .
FROM scratch AS binary
COPY --from=build /hangar-drive-server /hangar-drive-server

FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="Hangar Drive server" \
      org.opencontainers.image.description="Sync server of Hangar Drive: end-to-end encrypted file sync with versions, for your own server" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION" \
      org.opencontainers.image.source="https://github.com/feoren/hangar-drive" \
      org.opencontainers.image.documentation="https://github.com/feoren/hangar-drive/blob/main/docs/self-hosting.md" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /hangar-drive-server /usr/local/bin/hangar-drive-server
# The data volume belongs to the user nonroot (65532), so the server can write to it. With a
# bind mount and another user (`user:` in Compose), the host folder must belong to that user.
COPY --from=build --chown=65532:65532 /data-empty /data
# Every interface of the container: the port mapping decides who reaches it (outside the image
# the server listens on loopback by default). SQLite writes large temporary tables and sorts to
# files, and the read-only root file system has no writable temporary folder, so they go to the
# data volume, into the folder the server creates and empties at every start (`tmp`, mode 0700).
ENV HANGAR_DRIVE_DATA_DIR=/data \
    HANGAR_DRIVE_PORT=8080 \
    HANGAR_DRIVE_BIND=0.0.0.0 \
    SQLITE_TMPDIR=/data/tmp
VOLUME ["/data"]
EXPOSE 8080
USER nonroot:nonroot
# What `docker stop` sends: the server stops accepting, ends the event streams, lets requests in
# flight finish within HANGAR_DRIVE_SHUTDOWN_GRACE_SECS and exits with 0.
STOPSIGNAL SIGTERM
# No shell or curl in the image: the binary checks its own health endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/hangar-drive-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/hangar-drive-server"]
CMD ["serve"]
