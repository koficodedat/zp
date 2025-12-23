# Known Test Failures

This document explains expected test failures and how to resolve them.

---

## WebRTC Localhost Tests (3 failures)

### Status
❌ **Expected to FAIL** without additional setup
⚠️ **May still FAIL even with setup** due to ICE limitations

### Failing Tests
- `test_webrtc_connection_establishment`
- `test_webrtc_datachannel_lifecycle`
- `test_webrtc_peer_connection_state_transitions`

### Root Cause

**Primary Issue:** WebRTC ICE protocol limitations on localhost (127.0.0.1)

When both peers connect from the same IP address:
1. STUN server reports identical reflexive IPs for both peers
2. ICE connectivity checks fail (asymmetric routing)
3. Connection establishment times out

**From spec documentation:**
> WebRTC P2P connections on localhost (127.0.0.1) have ICE limitations. Both peers report the same reflexive IP from STUN, causing asymmetric connection failures.

### Prerequisites (Not Sufficient Alone)

The tests reference a coturn STUN server setup:

```bash
# Install coturn
brew install coturn

# Start STUN server on port 3478
turnserver -p 3478 -L 127.0.0.1
```

**However:** Even with coturn running, these tests **may still fail** due to the localhost ICE limitation described above.

### Configuration File Issue

Tests reference `/tmp/turnserver-test.conf` which **does not exist** in the repository. No template is provided.

### Recommended Solution

**Use Docker E2E Tests instead:**

```bash
cd crates/zp-transport/tests/signaling
./run_docker_test.sh
```

**Why Docker works:**
- Host peer: IP `127.0.0.1`
- Docker peer: IP `172.17.0.x` (bridge network)
- Different IPs → STUN sees them as separate → ICE succeeds ✅

### Docker E2E Tests (6 tests, all passing)

Located in: `crates/zp-transport/tests/webrtc_docker_e2e.rs`

**Test Coverage:**
1. ✅ `test_webrtc_docker_e2e` - Basic connection establishment
2. ✅ `test_webrtc_docker_bidirectional` - Bidirectional frame exchange
3. ✅ `test_webrtc_docker_multiple_frames` - Multiple frame sequences
4. ✅ `test_webrtc_docker_datachannel_lifecycle` - Channel lifecycle
5. ✅ `test_webrtc_docker_state_transitions` - State machine validation
6. ✅ `test_webrtc_docker_ice_candidate_gathering` - ICE gathering

**Prerequisites:**
- Docker Desktop installed and running
- Internet connection (for public STUN server: `stun.l.google.com:19302`)

**Run Individual Test:**
```bash
cargo test --package zp-transport \
  --test webrtc_docker_e2e \
  test_webrtc_docker_e2e \
  --all-features -- --nocapture --ignored
```

**Run All Docker Tests:**
```bash
cd crates/zp-transport/tests/signaling
chmod +x run_docker_test.sh
./run_docker_test.sh
```

---

## CI/CD Integration

### GitHub Actions

Docker tests work out-of-the-box on GitHub runners:

```yaml
- name: WebRTC E2E Tests
  run: |
    cd crates/zp-transport/tests/signaling
    ./run_docker_test.sh
```

**Supported runners:**
- ✅ `ubuntu-latest` (Docker pre-installed)
- ✅ `macos-latest` (Docker Desktop available)

### Local Development

**Quick validation:**
```bash
# Fast: Run all non-WebRTC tests
cargo test --lib

# Full: Run all tests except Docker E2E
cargo test

# Complete: Include Docker E2E tests
cd crates/zp-transport/tests/signaling && ./run_docker_test.sh
```

---

## Test Summary

| Test Suite | Count | Status | Prerequisites |
|------------|-------|--------|---------------|
| **Localhost WebRTC** | 3 | ❌ Expected FAIL | coturn (insufficient) |
| **Docker WebRTC E2E** | 6 | ✅ PASS | Docker Desktop |
| **WebRTC Error Tests** | 25 | ✅ PASS | None |
| **WebRTC Unit Tests** | 3 | ✅ PASS | None |
| **All Other Tests** | 362 | ✅ PASS | None |

**Overall:** 399/402 passing (99.3% success rate, excluding Docker E2E)

---

## Future Improvements

### Option 1: Mark Localhost Tests as Ignored

```rust
#[tokio::test]
#[ignore = "Requires coturn + has localhost ICE limitations"]
async fn test_webrtc_connection_establishment() {
    // ...
}
```

### Option 2: Auto-detect coturn

```rust
fn is_coturn_running() -> bool {
    std::net::TcpStream::connect("127.0.0.1:3478").is_ok()
}

#[tokio::test]
async fn test_webrtc_connection_establishment() {
    if !is_coturn_running() {
        eprintln!("⏭️  Skipping: coturn not running on port 3478");
        return;
    }
    // ... test code
}
```

### Option 3: Provide coturn Config

Create `crates/zp-transport/tests/signaling/turnserver-test.conf`:

```conf
# Minimal coturn config for localhost WebRTC testing
listening-port=3478
listening-ip=127.0.0.1
realm=localhost
no-auth
```

**Note:** Even with this config, localhost ICE limitations may still cause failures.

---

## Recommendation

**For development and CI:** Use Docker E2E tests exclusively. Localhost tests provide minimal value given the ICE limitations.

**Action:** Consider removing localhost WebRTC tests or marking them `#[ignore]` to avoid confusion.
