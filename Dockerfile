# psob-indexer — multi-stage build.
#
# Build:      docker build -t psob-indexer .
# Run:        docker run --rm -p 8080:8080 -p 9000:9000 -v psob-data:/data \
#               -e PSOB_CHAINS='JKC|8224|https://junk-api.s3na.xyz|0x1e0fffff|1095300' psob-indexer
# Compose:    docker compose up -d (see docker-compose.yml)

FROM rust:1.96-bookworm AS build
WORKDIR /app
COPY . .
RUN cargo build --release --bin psob-indexer

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/psob-indexer /usr/local/bin/psob-indexer

# Static data dir for the redb cache.
VOLUME /data

EXPOSE 8080 9000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://localhost:8080/api/v1/health || exit 1

ENTRYPOINT ["psob-indexer"]
