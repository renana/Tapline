# Tapline dataplane (Rust).
#   docker build -t tapline:0.1 -f proxy/Dockerfile proxy

FROM rust:bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo build --release && strip target/release/tapline

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 1338 tapline

COPY --from=build /src/target/release/tapline /usr/local/bin/tapline

USER 1338:1338
EXPOSE 15003 15005

ENV TAPLINE_INBOUND=0.0.0.0:15003 \
    TAPLINE_APP=127.0.0.1:8080 \
    TAPLINE_OUTBOUND=0.0.0.0:15005 \
    TAPLINE_ADMIN=127.0.0.1:15002 \
    TAPLINE_RUN_ORIGIN=0 \
    TAPLINE_PROXY_PROTOCOL=0 \
    TAPLINE_SINK=stdout

ENTRYPOINT ["/usr/local/bin/tapline"]
