# Dockerfile for WebRTC test peer
#
# Builds a containerized zp WebRTC peer for cross-container testing.

FROM rust:1-slim-bookworm as builder

WORKDIR /build

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace
COPY . .

# Build test peer binary
RUN cargo build --package zp-transport --bin webrtc-test-peer --all-features

FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /build/target/debug/webrtc-test-peer /usr/local/bin/

# Environment variables (set by docker-compose or test runner)
ENV SIGNALING_URL=""
ENV SESSION_ID=""
ENV PEER_ROLE="server"
ENV STUN_SERVER="stun:stun.l.google.com:19302"

ENTRYPOINT ["/usr/local/bin/webrtc-test-peer"]
