# WebRTC Integration Tests - Manual Execution Guide

## Overview

The WebRTC integration tests (`test_webrtc_connection_establishment`, `test_webrtc_bidirectional_frame_exchange`, `test_webrtc_multiple_frames`) are marked with `#[ignore]` because they require:

1. Real network access for ICE candidate gathering
2. STUN server connectivity
3. Time for WebRTC peer connection establishment (timeout-based)

These tests **cannot run in standard CI/CD** environments without network access.

## Prerequisites

1. **Network Access**: Tests need internet connectivity for STUN server access
2. **STUN Server**: Default uses `stun.l.google.com:19302` (configurable)
3. **Firewall**: Ensure UDP ports are open for ICE/STUN traffic
4. **Time**: Tests can take 5-10 seconds per connection due to ICE gathering

## Running Manual Tests

### Option 1: Run All Ignored WebRTC Tests

```bash
cargo test --package zp-transport --test webrtc_integration -- --ignored --nocapture
```

### Option 2: Run Specific Ignored Test

```bash
# Connection establishment only
cargo test --package zp-transport --test webrtc_integration test_webrtc_connection_establishment -- --ignored --nocapture

# Bidirectional frame exchange
cargo test --package zp-transport --test webrtc_integration test_webrtc_bidirectional_frame_exchange -- --ignored --nocapture

# Multiple frames
cargo test --package zp-transport --test webrtc_integration test_webrtc_multiple_frames -- --ignored --nocapture
```

## Expected Behavior

### Successful Test Run

```
running 1 test
test test_webrtc_connection_establishment ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in 3.45s
```

### Test Timeout (Network Issues)

If tests hang for >30 seconds, you may have:
- No internet connectivity
- STUN server blocked by firewall
- Network issues preventing ICE gathering

**Solution**: Press Ctrl+C and check:
```bash
# Test STUN server connectivity
nc -u stun.l.google.com 19302
```

### Test Failure (ICE Failed)

If ICE negotiation fails, you'll see errors like:
```
ICE gathering timeout
```

**Solutions**:
1. Check firewall settings (UDP traffic)
2. Try alternative STUN server (see Configuration below)
3. Check network NAT type (symmetric NAT may require TURN)

## Configuration

### Custom STUN Server

Modify `webrtc_integration.rs` to use a custom STUN server:

```rust
let mut config = WebRtcConfig::default();
config.stun_servers.clear(); // Remove defaults
config.stun_servers.push("stun:your-stun-server.com:3478".to_string());

let endpoint = WebRtcEndpoint::with_config(config).unwrap();
```

### TURN Server (For Restrictive NATs)

Add TURN server if behind symmetric NAT or restrictive firewall:

```rust
use webrtc::ice_transport::ice_server::RTCIceServer;

let mut config = WebRtcConfig::default();
config.turn_servers.push(RTCIceServer {
    urls: vec!["turn:your-turn-server.com:3478".to_string()],
    username: "username".to_string(),
    credential: "password".to_string(),
    ..Default::default()
});

let endpoint = WebRtcEndpoint::with_config(config).unwrap();
```

## Test Coverage

### What's Tested (Manual)

- ✅ WebRTC peer connection establishment (ICE + DataChannel)
- ✅ P2P role assignment (Offer sender = Client, Answer sender = Server)
- ✅ Bidirectional frame exchange over DataChannel
- ✅ Multiple frame streaming
- ✅ Connection lifecycle (connect → exchange → close)

### What's Tested (Unit/Conformance)

- ✅ WebRtcConfig validation (11 unit tests)
- ✅ STUN/TURN server configuration (conformance tests)
- ✅ PeerRole assignment logic
- ✅ Signaling message handling
- ✅ DataChannel label validation
- ✅ API compliance with spec §5 and §6.4

## Debugging

### Enable Verbose WebRTC Logging

Set environment variable before running tests:

```bash
export RUST_LOG=webrtc=debug,zp_transport=debug
cargo test --package zp-transport --test webrtc_integration -- --ignored --nocapture
```

### Check ICE Candidate Gathering

The tests use `MemorySignalingChannel` which logs ICE candidates:

```bash
# Look for output like:
# ICE Candidate: candidate:1 1 UDP 2130706431 192.168.1.100 ...
```

### Timeout Adjustment

If tests timeout on slow networks, increase timeout in test code:

```rust
// In webrtc_integration.rs, increase timeout duration
tokio::time::timeout(Duration::from_secs(30), server_conn)  // Default: 10s
```

## CI/CD Integration (Future Work)

### Option A: Dedicated Test Infrastructure

Set up dedicated test machines with:
- Real network connectivity
- STUN server access
- Longer test timeouts (5-10min)

### Option B: Mock WebRTC Stack

Replace `webrtc` crate with mock implementation for CI:
- ⚠️ **Complex**: Requires significant mocking infrastructure
- ✅ **Benefit**: Tests run in isolated CI environment

### Option C: Keep Manual (Recommended)

- Keep integration tests ignored
- Run manually before releases
- CI runs unit/conformance tests only (no network required)

## Frequency of Manual Testing

Recommended schedule:
- **Before releases**: Always run full suite
- **After WebRTC code changes**: Targeted test run
- **Weekly**: Full suite validation during active development
- **Monthly**: Full suite validation during maintenance

## Known Limitations

1. **Network Dependency**: Tests require internet access (fundamental WebRTC constraint)
2. **Timing Sensitivity**: ICE gathering can take 3-10 seconds depending on network
3. **NAT Traversal**: Some NAT types may fail without TURN server
4. **Platform Differences**: Behavior may vary across OS/network configurations

## Troubleshooting Guide

| Issue | Cause | Solution |
|-------|-------|----------|
| Test hangs | No STUN server connectivity | Check firewall, try alternative STUN server |
| ICE Failed | Restrictive NAT/firewall | Add TURN server configuration |
| Timeout | Slow network | Increase test timeout duration |
| Random failures | Network flakiness | Run tests multiple times, check network stability |
| Permission denied | Firewall blocking UDP | Configure firewall to allow UDP traffic |

## Contact

For WebRTC test issues:
1. Check this README first
2. Review WebRTC spec §5 (NAT Traversal) and §6.4 (DataChannel)
3. File issue with network diagnostics:
   - STUN server connectivity test results
   - Network type (NAT configuration)
   - Operating system and network configuration
   - Test output with `RUST_LOG=debug`
