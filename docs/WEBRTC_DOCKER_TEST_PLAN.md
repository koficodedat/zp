# WebRTC Docker E2E Test Migration Plan

## Context

WebRTC tests on localhost fail due to ICE localhost limitations - ICE cannot connect two endpoints on the same IP. We have built Docker E2E infrastructure to solve this.

## Infrastructure Status: ✅ COMPLETE

- ✅ Embedded HTTP signaling server (dynamic ports)
- ✅ Docker container for second peer (different IP: 172.17.0.x)
- ✅ Separate ICE candidate queues (client/server)
- ✅ DataChannel ready state handling (wait for open event)
- ✅ Docker build optimization (.dockerignore)
- ✅ One test passing: `test_webrtc_docker_e2e`

## Tests to Port

| Test | Status | Priority | Estimated Effort |
|------|--------|----------|------------------|
| `test_webrtc_connection_establishment` | ✅ DONE | - | Covered by `test_webrtc_docker_e2e` |
| `test_webrtc_bidirectional_frame_exchange` | 🔴 TODO | P0 | 1-2h |
| `test_webrtc_multiple_frames` | 🔴 TODO | P0 | 1h |
| `test_webrtc_datachannel_lifecycle` | 🔴 TODO | P1 | 2-3h |
| `test_webrtc_peer_connection_state_transitions` | 🔴 TODO | P1 | 1-2h |
| `test_webrtc_ice_candidate_gathering_localhost` | 🔴 TODO | P2 | 1h |

## Implementation Strategy

### 1. Create Reusable Helper Functions

**File:** `crates/zp-transport/tests/webrtc_docker_e2e.rs`

```rust
/// Helper to set up a Docker WebRTC connection for testing
async fn setup_docker_connection() -> Result<DockerTestContext, String> {
    // 1. Start embedded signaling server
    // 2. Create session
    // 3. Launch Docker container with server peer
    // 4. Connect client peer from host
    // Returns: context with both ends + cleanup handle
}

/// Helper to send frame from host client → Docker server
async fn send_frame_to_docker(
    connection: &WebRtcConnection,
    frame: Frame
) -> Result<(), Error> {
    // ...
}

/// Helper to receive frame from Docker server → host client
/// (Requires Docker binary to be modified to send frames)
async fn recv_frame_from_docker(
    connection: &WebRtcConnection
) -> Result<Frame, Error> {
    // ...
}

/// Cleanup Docker resources
async fn teardown_docker_connection(context: DockerTestContext) {
    // Stop container, shut down signaling server
}
```

### 2. Port Each Test

#### P0: Critical for Coverage

**test_webrtc_bidirectional_frame_exchange** (1-2h)
```rust
#[tokio::test]
async fn test_webrtc_docker_bidirectional() {
    let ctx = setup_docker_connection().await.unwrap();

    // Send: host → Docker
    let frame1 = Frame::Ping(vec![1, 2, 3]);
    send_frame_to_docker(&ctx.client_conn, frame1).await.unwrap();

    // Receive: Docker → host
    let frame2 = recv_frame_from_docker(&ctx.client_conn).await.unwrap();
    assert!(matches!(frame2, Frame::Pong(_)));

    teardown_docker_connection(ctx).await;
}
```

**Required Changes:**
- Modify `webrtc-test-peer.rs` binary to send a Pong frame back after receiving Ping
- Add `recv_frame()` call to host test

---

**test_webrtc_multiple_frames** (1h)
```rust
#[tokio::test]
async fn test_webrtc_docker_multiple_frames() {
    let ctx = setup_docker_connection().await.unwrap();

    // Send 10 frames
    for i in 0..10 {
        let frame = Frame::Ping(vec![i]);
        send_frame_to_docker(&ctx.client_conn, frame).await.unwrap();
    }

    // Verify all received (Docker logs or receive them back)
    // ...

    teardown_docker_connection(ctx).await;
}
```

---

#### P1: Important for Full Coverage

**test_webrtc_datachannel_lifecycle** (2-3h)
```rust
#[tokio::test]
async fn test_webrtc_docker_datachannel_lifecycle() {
    let ctx = setup_docker_connection().await.unwrap();

    // Send frame while open
    send_frame_to_docker(&ctx.client_conn, Frame::Ping(vec![1])).await.unwrap();

    // Close DataChannel
    ctx.client_conn.close().await.unwrap();

    // Verify send fails after close
    let result = send_frame_to_docker(&ctx.client_conn, Frame::Ping(vec![2])).await;
    assert!(result.is_err());

    teardown_docker_connection(ctx).await;
}
```

---

**test_webrtc_peer_connection_state_transitions** (1-2h)
```rust
#[tokio::test]
async fn test_webrtc_docker_state_transitions() {
    // Track state transitions during connection establishment
    // checking → connected → (eventually) disconnected

    // Modify setup_docker_connection() to return state change events
    // Verify: checking → connected
    // Verify: connected persists for X seconds
    // Close and verify: disconnected → closed
}
```

---

#### P2: Nice to Have

**test_webrtc_ice_candidate_gathering** (1h)
- Rename to `test_webrtc_docker_ice_candidate_gathering`
- Verify ICE candidates are gathered and exchanged correctly
- Already implicitly tested by E2E test, but explicit verification is good

---

## Coverage Impact Estimate

**Current WebRTC Coverage: 23.97%**

**Expected After Porting:**
- `test_webrtc_bidirectional_frame_exchange`: +10%
- `test_webrtc_multiple_frames`: +5%
- `test_webrtc_datachannel_lifecycle`: +15%
- `test_webrtc_peer_connection_state_transitions`: +5%
- `test_webrtc_ice_candidate_gathering`: +5%

**Estimated Final Coverage: ~65%** (webrtc.rs)

**Remaining gaps:**
- Error recovery paths (handled by `webrtc_error_tests.rs`)
- Edge cases (Phase 5B)

---

## Implementation Order

1. **Day 1** (3-4h):
   - Create helper functions in `webrtc_docker_e2e.rs`
   - Port `test_webrtc_bidirectional_frame_exchange`
   - Port `test_webrtc_multiple_frames`
   - Run coverage, verify improvement

2. **Day 2** (3-4h):
   - Port `test_webrtc_datachannel_lifecycle`
   - Port `test_webrtc_peer_connection_state_transitions`
   - Run full coverage suite
   - Update CHANGELOG

3. **Day 3** (1h):
   - Port `test_webrtc_ice_candidate_gathering` (optional)
   - Final coverage measurement
   - Document results

---

## Success Criteria

- ✅ All 6 ported tests pass consistently
- ✅ WebRTC coverage improves to >60%
- ✅ No flaky tests (run 10x to verify)
- ✅ Docker tests run in <15s each
- ✅ CI integration ready (Docker available)

---

## Alternative: Mock ICE for Localhost

**NOT RECOMMENDED** - Would require:
- Mocking WebRTC ICE layer (complex)
- Less realistic than actual network conditions
- Doesn't test STUN/TURN integration
- Doesn't catch real-world ICE issues

Docker E2E is the right approach for WebRTC testing.

---

## References

- Working test: `crates/zp-transport/tests/webrtc_docker_e2e.rs`
- Signaling infrastructure: `crates/zp-transport/tests/signaling/`
- Docker setup: `crates/zp-transport/tests/signaling/Dockerfile`
- Run script: `crates/zp-transport/tests/signaling/run_docker_test.sh`

---

**Status:** Infrastructure complete, ready for test migration
**Next Step:** Implement helper functions and port P0 tests
