# Stage 1: Build
FROM rust:1.93-slim AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
RUN cargo build --release -p prism-sync-relay

# Stage 2: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/prism-sync-relay /usr/local/bin/prism-sync-relay
# No `USER`/`chown` here on purpose. This image backs the root `docker-compose.yml`,
# which bind-mounts a host path at /data and runs the relay as root (root owns the
# mount, so a chown is neither needed nor safe). Do NOT add `chown prism:prism`
# without first creating that user — `chown` to a nonexistent user fails the build.
# The hardened drop-privileges path is `self-host/Dockerfile`, which creates the
# `prism` user and chowns /data before `USER prism`.
RUN mkdir -p /data/media
VOLUME /data
ENV DB_PATH=/data/relay.db
ENV PORT=8080
# Media and pair-time snapshot blobs live under this persistent mount. Keep it an
# explicit absolute path on the writable volume: a relative default resolves
# under the image workdir, which can be ephemeral or unwritable and would leave
# snapshot rows referencing blobs that were never durably stored.
ENV MEDIA_STORAGE_PATH=/data/media
CMD ["prism-sync-relay"]
