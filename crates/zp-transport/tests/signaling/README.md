# WebRTC Docker Testing Infrastructure

Zero-config WebRTC testing with Docker containers.

## Overview

This directory contains infrastructure for testing WebRTC peer connections across different network IPs using Docker containers.

**Problem:** WebRTC P2P connections on localhost (127.0.0.1) have ICE limitations. Both peers report the same reflexive IP from STUN, causing asymmetric connection failures.

**Solution:** Run one peer in Docker container (IP: 172.17.0.x) and one peer on host (IP: 127.0.0.1 or host network). Different IPs → STUN sees them as separate → ICE succeeds.

## Components

```
signaling/
├── Dockerfile              # Container image for test peer
├── docker-compose.yml      # Container orchestration
├── run_docker_test.sh      # Test runner script
├── server.rs               # HTTP signaling server (session management)
├── client.rs               # HTTP signaling client (SignalingChannel impl)
├── embedded_server.rs      # Embedded warp server (auto-start)
├── test_peer.rs            # Standalone peer module (for future binary)
└── README.md               # This file
```

## Quick Start

### Prerequisites

- Docker Desktop installed and running
- Internet connection (for public STUN server)

### Run Docker E2E Test

```bash
# From repo root
cd crates/zp-transport/tests/signaling
chmod +x run_docker_test.sh
./run_docker_test.sh
```

**What happens:**
1. Builds `webrtc-test-peer` Rust binary
2. Builds Docker image
3. Runs `webrtc_docker_e2e` test:
   - Starts embedded HTTP signaling server on host (random port)
   - Creates session ID
   - Launches Docker container with server peer
   - Connects client peer from host
   - Verifies WebRTC P2P establishment
   - Exchanges frames to prove E2E works
   - Cleans up container and server

### Run Manually

```bash
# Terminal 1: Build binary
cargo build --package zp-transport --bin webrtc-test-peer --all-features

# Terminal 2: Build Docker image
cd crates/zp-transport/tests/signaling
docker-compose build

# Terminal 3: Run test
cargo test --package zp-transport --test webrtc_docker_e2e --all-features -- --nocapture
```

## Architecture

### HTTP Signaling Server (Embedded)

**Purpose:** Exchange SDP offers/answers and ICE candidates between peers.

**API:**
- `POST /session` - Create new session, returns session_id
- `POST /session/{id}/offer` - Store SDP offer
- `GET /session/{id}/offer` - Retrieve SDP offer (30s polling timeout)
- `POST /session/{id}/answer` - Store SDP answer
- `GET /session/{id}/answer` - Retrieve SDP answer (30s polling timeout)
- `POST /session/{id}/ice` - Add ICE candidate
- `GET /session/{id}/ice` - Poll for ICE candidates

**Features:**
- Auto-starts on random port (avoids conflicts)
- Zero-config (no setup required)
- Polling-based (no WebSocket needed)
- Thread-safe session storage
- Graceful shutdown

### Test Peer Binary

**Location:** `crates/zp-transport/bin/webrtc-test-peer.rs`

**Environment Variables:**
- `SIGNALING_URL` - HTTP signaling server URL (e.g., `http://host.docker.internal:8080`)
- `SESSION_ID` - Session identifier (shared between peers)
- `PEER_ROLE` - "client" or "server"
- `STUN_SERVER` - STUN server URL (default: `stun:stun.l.google.com:19302`)

**Example:**
```bash
# Run as server peer in Docker
docker run \
  -e SIGNALING_URL=http://host.docker.internal:8080 \
  -e SESSION_ID=550e8400-e29b-41d4-a716-446655440000 \
  -e PEER_ROLE=server \
  -e STUN_SERVER=stun:stun.l.google.com:19302 \
  zp-webrtc-test-peer
```

### Docker Compose

**File:** `docker-compose.yml`

**Services:**
- `webrtc-server-peer` - Server peer in container (IP: 172.17.0.x)

**Network:**
- `webrtc-test` - Bridge network for container isolation

**Usage:**
```bash
# Start container
SIGNALING_URL=http://host.docker.internal:8080 \
SESSION_ID=abc123 \
docker-compose up

# Stop container
docker-compose down
```

## Network Flow

```
┌─────────────────────────────────────────────────────────────┐
│  Host Machine (127.0.0.1)                                   │
│                                                              │
│  ┌──────────────────────┐                                   │
│  │ Embedded HTTP Server │  ← Random port (e.g., 60123)     │
│  │ (Warp)               │                                   │
│  └─────────┬────────────┘                                   │
│            │                                                 │
│            ├─────────────► Client Peer (Host)               │
│            │               IP: 127.0.0.1                     │
│            │               Role: Initiator                   │
│            │               Sends: Offer                      │
│            │                                                 │
│            └─────────────► Docker Container                 │
│                            ┌────────────────────┐            │
│                            │ Server Peer         │           │
│                            │ IP: 172.17.0.x      │           │
│                            │ Role: Responder     │           │
│                            │ Sends: Answer       │           │
│                            └────────────────────┘            │
└─────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
                          Public STUN Server
                      stun.l.google.com:19302
```

**ICE Flow:**
1. Client sends Offer → Signaling Server
2. Server polls Offer → Signaling Server
3. Server sends Answer → Signaling Server
4. Client polls Answer → Signaling Server
5. Both peers gather ICE candidates:
   - Host candidates (local IPs)
   - Server reflexive candidates (public IP from STUN)
6. Peers exchange ICE candidates → Signaling Server
7. ICE connectivity checks
8. WebRTC DataChannel established ✅

## Troubleshooting

### Docker not running
```
Error: Docker is not running
```
**Fix:** Start Docker Desktop

### Container fails to start
```
Error: Failed to start Docker container
```
**Fix:** Check Docker logs:
```bash
docker-compose logs
```

### Connection timeout
```
Error: Client connection timed out after 90s
```
**Possible causes:**
- Firewall blocking WebRTC (UDP ports)
- STUN server unreachable (check internet)
- Docker networking misconfigured

**Debug:**
```bash
# Check container is running
docker ps

# Check container logs
docker logs <container-id>

# Test STUN from container
docker exec <container-id> ping stun.l.google.com
```

### Signaling errors
```
Error: Failed to create session
```
**Fix:** Ensure embedded server started successfully. Check test output for signaling URL.

## CI Integration

**GitHub Actions Example:**

```yaml
- name: WebRTC Docker E2E Test
  run: |
    # Install Docker (if not available)
    # docker --version
    
    # Run test
    cd crates/zp-transport/tests/signaling
    chmod +x run_docker_test.sh
    ./run_docker_test.sh
```

**Notes:**
- GitHub Actions runners have Docker pre-installed
- No special setup required
- Works on ubuntu-latest, macos-latest

## Performance

**Connection Establishment Time:**
- Localhost in-memory signaling: 50-100ms (fails on localhost)
- Docker + HTTP signaling + public STUN: 3-5 seconds (succeeds)

**Breakdown:**
- Container startup: 1-2s
- STUN gathering: 1-2s
- ICE connectivity checks: 1-2s

**Overhead:** Acceptable for E2E testing (not performance benchmarks).

## Future Improvements

- [ ] Use local STUN server instead of public (faster, offline-capable)
- [ ] Binary cache for faster Docker builds
- [ ] Multi-container tests (3+ peers)
- [ ] WebSocket-based signaling (lower latency than polling)
- [ ] Record/replay for debugging

## References

- [WebRTC ICE](https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API/Connectivity)
- [STUN RFC 5389](https://tools.ietf.org/html/rfc5389)
- [Docker Networking](https://docs.docker.com/network/)
- [zp Specification §6.4](../../docs/zp_specification_v1.0.md#64-webrtc-transport)
