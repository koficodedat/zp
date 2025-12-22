#!/usr/bin/env bash
#
# WebRTC Docker E2E test runner
#
# Orchestrates full WebRTC test with:
# - Embedded HTTP signaling server (on host)
# - Client peer (on host)
# - Server peer (in Docker container, different IP)
#
# This enables real WebRTC P2P connections with network signaling.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

echo "🔧 WebRTC Docker E2E Test"
echo "=========================="

# Check Docker is available
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Install Docker Desktop: https://www.docker.com/products/docker-desktop"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ docker-compose not found. Install Docker Compose."
    exit 1
fi

# Build test peer binary
echo "📦 Building WebRTC test peer binary..."
cd "$REPO_ROOT"
cargo build --package zp-transport --bin webrtc-test-peer --all-features

# Build Docker image
echo "🐳 Building Docker image..."
cd "$SCRIPT_DIR"
docker-compose build

# Run test via Rust test harness (serial execution to avoid Docker container conflicts)
echo "🧪 Running WebRTC Docker E2E tests (serial execution)..."
cd "$REPO_ROOT"
cargo test --package zp-transport --test webrtc_docker_e2e --all-features -- --ignored --nocapture --test-threads=1

echo "✅ WebRTC Docker E2E test completed!"
