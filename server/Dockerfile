# Hangar Drive server: static musl binary in a distroless image, running as an unprivileged user.
#
# Build from the repository root (the server needs the protocol crate under crates/):
#   docker build -f server/Dockerfile -t hangar-drive-server .
# or with Compose:
#   docker compose up -d --build
#
# The base images are pinned by digest (multi-platform index) so that a build is reproducible;
# Dependabot proposes new digests. To update by hand:
#   docker buildx imagetools inspect rust:1-alpine   (first "Digest:" line)

FROM rust:1-alpine@sha256:2cccd8b212b37dad15a555589c1b6787da4ab913fe24d8a9b2d99d3498869409 AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY server ./server
# The workspace lists the desktop app as a member, so Cargo has to read its manifest and find its
# targets. It is not compiled: the build below selects the server package only.
COPY src-tauri/Cargo.toml ./src-tauri/Cargo.toml
COPY src-tauri/src ./src-tauri/src
# Size matters for the image only, so the release settings are set here and not in the workspace,
# where they would slow down the app's release builds as well.
ENV CARGO_PROFILE_RELEASE_LTO=thin \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
    CARGO_PROFILE_RELEASE_STRIP=symbols
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --package hangar-drive-server \
 && cp target/release/hangar-drive-server /hangar-drive-server \
 && mkdir -p /data-empty

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /hangar-drive-server /usr/local/bin/hangar-drive-server
# The data volume belongs to the user nonroot (65532), so the server can write to it.
COPY --from=build --chown=65532:65532 /data-empty /data
ENV HANGAR_DRIVE_DATA_DIR=/data \
    HANGAR_DRIVE_PORT=8080
VOLUME ["/data"]
EXPOSE 8080
USER nonroot:nonroot
# No shell or curl in the image: the binary checks its own health endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/hangar-drive-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/hangar-drive-server"]
CMD ["serve"]
