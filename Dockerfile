# syntax=docker/dockerfile:1
FROM rust:1.100.0-alpine3.22 AS builder
RUN apk add --no-cache build-base
WORKDIR /opt/app
COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/opt/app/target \
    cargo build --release --locked && cp target/release/tcping /usr/local/bin/tcping

FROM scratch AS runtime
COPY --from=builder /usr/local/bin/tcping /usr/local/bin/tcping
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/tcping"]
