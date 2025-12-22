# ZP UI Testing Framework Proposal

## Overview

A web-based interactive testing and visualization tool for the zp protocol.

**Purpose:**
- Simulate back-and-forth protocol communication visually
- Interactive testing (send frames, observe responses)
- Protocol state visualization
- Network condition simulation (latency, packet loss)
- Educational/demo tool for zp protocol

## Architecture

### Backend (Rust)

**Framework:** Axum (async web framework)

**Components:**
1. **Protocol Simulator** - Runs zp protocol operations
2. **WebSocket Server** - Real-time updates to UI
3. **REST API** - Control operations (start/stop sessions, send frames)
4. **State Inspector** - Expose internal protocol state

**File Structure:**
```
tools/zp-simulator/
├── src/
│   ├── main.rs              # Axum server
│   ├── simulator.rs         # Protocol simulation engine
│   ├── websocket.rs         # WebSocket handler
│   ├── api.rs               # REST endpoints
│   └── state.rs             # State inspection
├── Cargo.toml
└── README.md
```

### Frontend (HTML/JS/TypeScript)

**Framework:** Vanilla JS or Svelte (lightweight, fast)

**Components:**
1. **Protocol Visualizer** - SVG/Canvas rendering of protocol flow
2. **Frame Inspector** - View/edit frame contents
3. **State Monitor** - Real-time session state display
4. **Network Simulator** - Control latency, packet loss, jitter
5. **Test Scenarios** - Pre-built test sequences

**File Structure:**
```
tools/zp-simulator/web/
├── index.html
├── css/
│   └── style.css
├── js/
│   ├── app.js               # Main app
│   ├── visualizer.js        # Protocol flow visualization
│   ├── frames.js            # Frame rendering
│   ├── state.js             # State display
│   └── websocket.js         # WebSocket client
└── scenarios/
    ├── handshake.json       # Full handshake sequence
    ├── rekey.json           # Rekeying scenario
    └── error-handling.json  # Error path scenarios
```

## Features

### 1. Interactive Protocol Simulation

**UI Elements:**
- Two peer panels (left: Client, right: Server)
- Arrow animations showing frame exchanges
- Timeline of events
- Current state indicators

**Interactions:**
- Click "Send ClientHello" → See frame travel + ServerHello response
- Adjust crypto suite → Observe handshake changes
- Inject errors → See error handling

**Example:**
```
┌─────────────────┐         ┌─────────────────┐
│  Client Peer    │         │  Server Peer    │
│  State: INIT    │         │  State: INIT    │
│                 │         │                 │
│ [Send ClientHello] ───────► [Receive]       │
│                 │         │                 │
│ [Receive]    ◄────────── [Send ServerHello]│
│                 │         │                 │
│ State: HANDSHAKE│         │ State: HANDSHAKE│
└─────────────────┘         └─────────────────┘

Timeline:
  0ms: ClientHello sent
 50ms: ServerHello received
100ms: Handshake complete
```

### 2. Frame Inspector

**Features:**
- View all frame types (ControlFrame, DataFrame, etc.)
- Edit frame fields before sending
- Hex dump view
- Binary/JSON toggle
- Syntax highlighting for encrypted data

**Example UI:**
```
┌─────────────────────────────────────┐
│ Frame: ClientHello                  │
│ Type: ControlFrame::ClientHello     │
│                                     │
│ ┌─────────────────────────────────┐ │
│ │ client_random: [hex editor]     │ │
│ │ supported_suites: [list editor] │ │
│ │ extensions: [json editor]       │ │
│ └─────────────────────────────────┘ │
│                                     │
│ [Send] [Save Scenario] [Reset]     │
└─────────────────────────────────────┘
```

### 3. State Visualization

**Displays:**
- Session state (init, handshaking, established, rekeying)
- Key material (epochs, derivation chain)
- Stream IDs (client vs server namespaces)
- Window sizes, sequence numbers
- Crypto parameters

**Example:**
```
┌─────────────────────────────────────┐
│ Session State: ESTABLISHED          │
│                                     │
│ Keys:                               │
│   Current Epoch: 2                  │
│   Next Rekey: 1234 seconds          │
│   Send Key: epoch_2_send [masked]   │
│   Recv Key: epoch_2_recv [masked]   │
│                                     │
│ Streams:                            │
│   Active: 3 (IDs: 2, 4, 6)          │
│   Client namespace: even (0, 2, 4..)│
│   Server namespace: odd (1, 3, 5..) │
│                                     │
│ Flow Control:                       │
│   Session window: 65536 bytes       │
│   Stream window: 16384 bytes        │
└─────────────────────────────────────┘
```

### 4. Network Condition Simulator

**Controls:**
- Latency slider (0-1000ms)
- Packet loss slider (0-50%)
- Jitter slider (0-100ms)
- Bandwidth throttle
- Connection drops

**Use Cases:**
- Test timeout handling
- Verify retransmission logic
- Stress test flow control
- Observe congestion avoidance

**Example:**
```
┌─────────────────────────────────────┐
│ Network Conditions                  │
│                                     │
│ Latency:     [====·····] 150ms     │
│ Packet Loss: [··········] 0%       │
│ Jitter:      [==········] 20ms     │
│ Bandwidth:   [========··] 10 Mbps  │
│                                     │
│ [Apply] [Reset to Ideal]            │
│                                     │
│ Presets:                            │
│ [3G Mobile] [Congested WiFi]        │
│ [Satellite] [Office LAN]            │
└─────────────────────────────────────┘
```

### 5. Test Scenario Player

**Features:**
- Load pre-built scenarios (JSON)
- Step through frame-by-frame
- Auto-play with speed control
- Pause/resume
- Assertions on state

**Example Scenario (JSON):**
```json
{
  "name": "Full Handshake (Stranger Mode)",
  "description": "Client and server establish session from scratch",
  "steps": [
    {
      "action": "send",
      "from": "client",
      "frame": {
        "type": "ClientHello",
        "client_random": "auto",
        "supported_suites": ["ZpHybrid1", "ZpHybrid2"],
        "extensions": {"alpn": ["zp/1.0"]}
      },
      "assertions": {
        "client_state": "INIT"
      }
    },
    {
      "action": "send",
      "from": "server",
      "frame": {
        "type": "ServerHello",
        "server_random": "auto",
        "selected_suite": "ZpHybrid1",
        "key_exchange": "auto"
      },
      "assertions": {
        "server_state": "HANDSHAKE",
        "client_state": "HANDSHAKE"
      }
    },
    {
      "action": "wait",
      "duration_ms": 50,
      "description": "Key derivation"
    },
    {
      "action": "assert",
      "conditions": {
        "client_state": "ESTABLISHED",
        "server_state": "ESTABLISHED",
        "session_id": "matches"
      }
    }
  ]
}
```

### 6. Multi-Transport Testing

**Tabs:**
- QUIC
- WebRTC
- WebSocket
- TCP

**Features:**
- Switch between transports
- Compare behavior across transports
- Visualize transport-specific details (QUIC streams, WebRTC ICE)

## REST API

### Endpoints

```
POST   /api/session/create       # Create new session
DELETE /api/session/:id           # Destroy session
GET    /api/session/:id/state     # Get current state
POST   /api/session/:id/send      # Send frame
GET    /api/session/:id/frames    # Get frame history
POST   /api/session/:id/scenario  # Load scenario
POST   /api/network/set           # Set network conditions

WebSocket /ws/session/:id         # Real-time updates
```

### Example Requests

**Create Session:**
```bash
curl -X POST http://localhost:8080/api/session/create \
  -H "Content-Type: application/json" \
  -d '{
    "role": "client",
    "mode": "stranger",
    "transport": "quic",
    "cipher_suite": "ZpHybrid1"
  }'

Response:
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "state": "INIT"
}
```

**Send Frame:**
```bash
curl -X POST http://localhost:8080/api/session/550e.../send \
  -H "Content-Type: application/json" \
  -d '{
    "frame_type": "ClientHello",
    "payload": {
      "client_random": "0102030405060708...",
      "supported_suites": ["ZpHybrid1", "ZpHybrid2"]
    }
  }'
```

## Implementation Plan

### Phase 1: Core Simulator (2-3 days)
- [ ] Axum server setup
- [ ] Session management (create, destroy, inspect)
- [ ] Frame sending/receiving
- [ ] State inspection API
- [ ] Basic WebSocket for real-time updates

### Phase 2: UI Foundations (2-3 days)
- [ ] HTML/CSS layout (two-peer view)
- [ ] WebSocket client
- [ ] Frame list display
- [ ] State monitor display

### Phase 3: Visualization (3-4 days)
- [ ] SVG/Canvas protocol flow (arrows, timelines)
- [ ] Frame animations
- [ ] State transitions
- [ ] Interactive frame editing

### Phase 4: Advanced Features (3-4 days)
- [ ] Network condition simulation
- [ ] Test scenario loader/player
- [ ] Multi-transport support
- [ ] Scenario library (handshake, rekey, errors)

### Phase 5: Polish (1-2 days)
- [ ] UI/UX improvements
- [ ] Documentation
- [ ] Example scenarios
- [ ] Demo video

**Total Estimate:** 11-16 days

## Usage Examples

### Example 1: Test Handshake with Packet Loss

```bash
# Start simulator
cd tools/zp-simulator
cargo run --release

# Open browser
open http://localhost:8080

# In UI:
1. Click "New Session" (creates Client + Server)
2. Set network conditions: Packet Loss = 10%
3. Click "Run Scenario" → "Full Handshake"
4. Observe retransmissions, timeout handling
5. Verify handshake completes despite packet loss
```

### Example 2: Visualize Rekeying

```bash
# In UI:
1. Load scenario: "Established Session with Rekey"
2. Step through frames:
   - Initial session established
   - KeyUpdate sent at epoch boundary
   - New keys derived
   - Traffic continues with new epoch
3. Inspect key material at each step
4. Verify old keys zeroized
```

### Example 3: Compare Transport Behaviors

```bash
# In UI:
1. Create 3 sessions:
   - Session 1: QUIC
   - Session 2: WebRTC
   - Session 3: WebSocket
2. Send same DataFrame to all
3. Compare:
   - Latency
   - Frame overhead
   - Connection establishment time
   - Resilience to packet loss
```

## Benefits

### For Development
- **Rapid prototyping**: Test protocol changes visually
- **Debugging**: Inspect state at any point
- **Integration testing**: Full E2E scenarios

### For Testing
- **Manual exploratory testing**: Click around, find edge cases
- **Regression testing**: Load scenarios, verify behavior
- **Performance testing**: Network simulation

### For Documentation/Demos
- **Educational**: Show how zp protocol works
- **Marketing**: Interactive demo for users
- **Onboarding**: New contributors understand protocol flow

## Future Extensions

- **Fuzzing Integration**: Visualize fuzzer-generated inputs
- **CI Integration**: Headless scenario runner
- **Multi-Peer**: More than 2 peers (mesh testing)
- **Record/Replay**: Capture real sessions, replay them
- **Wireshark Plugin**: Export to .pcap format
- **Performance Profiling**: Flame graphs, bottleneck analysis

## Technology Stack

**Backend:**
- Rust + Axum (web framework)
- tokio (async runtime)
- serde_json (JSON serialization)
- zp-core, zp-crypto, zp-transport (protocol implementation)

**Frontend:**
- HTML5 + CSS3
- Vanilla JavaScript or Svelte (decision based on complexity)
- WebSocket API
- SVG for protocol visualization
- Monaco Editor for frame editing (optional)

**Deployment:**
- Single binary (embed static files in Rust binary)
- Cross-platform (macOS, Linux, Windows)
- Zero external dependencies

## Conclusion

A UI testing framework for zp would:
1. **Accelerate development** - Visual feedback loop
2. **Improve quality** - Interactive testing catches bugs
3. **Enhance understanding** - See protocol in action
4. **Enable demos** - Show off zp capabilities

**Recommendation:** Start with Phase 1-2 (core + basic UI) as a proof-of-concept.
If valuable, expand to full visualization and scenario player.

**Estimated ROI:**
- Initial investment: 2 weeks
- Long-term value: Faster debugging, better testing, improved onboarding
- Could save weeks of blind debugging over project lifetime
