# Prism Relay — Self-Hosting Dockerfile
#
# Build from the sync/ directory as context:
#   docker build -f deploy/self-host/Dockerfile -t prism-relay:local sync/
#
# Or use the build.sh helper:
#   ./deploy/self-host/build.sh

FROM rust:1.93-slim AS builder
RUN apt-get update && apt-get install -y gcc && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN cargo build --release -p prism-sync-relay

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN groupadd -r prism && useradd -r -g prism -d /data -s /sbin/nologin prism
COPY --from=builder /app/target/release/prism-sync-relay /usr/local/bin/prism-sync-relay
RUN mkdir -p /data && chown prism:prism /data
VOLUME /data
ENV DB_PATH=/data/relay.db
ENV PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1
USER prism
CMD ["prism-sync-relay"]
