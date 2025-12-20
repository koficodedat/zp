# zp: Transport Protocol Specification

**Version:** 1.0  
**Status:** Final  
**Last Updated:** December 2025  
**Companion Documents:** [CHANGELOG.md](./CHANGELOG.md) | [TEST_VECTORS.md](./TEST_VECTORS.md)

---

## 1. Overview

zp is a metadata-minimized transport protocol for unreliable networks. It provides post-quantum security, automatic transport adaptation, and cross-platform persistence.

### 1.1 Design Goals

| Goal | Mechanism |
|------|-----------|
| Survive dirty networks | QUIC + automatic TCP fallback with byte-level sync |
| Post-quantum security | Hybrid X25519 + ML-KEM from first data packet |
| Mobile persistence | OS-native handoff (HTTP/3 on iOS, Foreground Service on Android) |
| Browser compatibility | WebTransport → WebRTC DataChannel → WebSocket fallback chain |
| Metadata minimization | O-HTTP signaling, optional traffic shaping |

### 1.2 Deployment Tiers

**Tier 1 (zp-core):** Open-source SDK. Self-hosted infrastructure. Tree-shakable modules.

**Tier 2 (zp-cloud):** Managed global mesh. Includes relay infrastructure, TEE-attested nodes, and compliance tooling.

### 1.3 Platform Requirements

| Platform | Minimum Version | Notes |
|----------|-----------------|-------|
| iOS | 15.0 | HTTP/3 backgrounding; iOS 14 falls back to HTTP/2 |
| Android | API 26 (8.0) | Foreground Service; API 34+ requires `android:foregroundServiceType` manifest attribute |
| Chromium | 97+ | WebTransport support |
| Safari | 16.4+ | WebRTC DataChannel (no WebTransport) |
| Firefox | 114+ | WebRTC DataChannel (WebTransport behind flag) |

### 1.4 Target Use Cases

zp is optimized for **long-lived stream patterns**:
- Real-time communication (voice, video, collaboration)
- Bulk file transfer
- Persistent connections (chat, notifications)

**Not optimized for:** High-concurrency request/response patterns (HTTP/2-style multiplexing with 100+ concurrent streams). Applications using such patterns should disable hibernation or accept stream state loss during backgrounding.

### 1.5 Platform Security Boundaries

| Platform | Security Guarantee |
|----------|-------------------|
| iOS/macOS | Full cipher pinning integrity via Secure Enclave |
| Android | Full cipher pinning integrity via hardware-backed KeyStore |
| **Browser** | Transport encryption only. Cipher pinning NOT guaranteed against same-origin XSS. |

**Browser deployments cannot provide security guarantees equivalent to native platforms.** High-assurance use cases MUST use native SDKs.

---

## 2. Protocol Versioning

### 2.1 Version Format

```
Major.Minor (e.g., 1.0)
```

- **Major:** Breaking wire protocol changes
- **Minor:** Backward-compatible feature additions

### 2.2 Version Negotiation

```
ClientHello {
  supported_versions: [1.1, 1.0]  // Descending preference
  min_version: 1.0                // Will not accept below this
  ...
}

ServerHello {
  selected_version: 1.0
  ...
}
```

**Rules:**
- Server selects highest mutually-supported version
- If `selected_version < client.min_version`: client MUST abort with `ERR_VERSION_MISMATCH`
- Servers MUST support current major version and previous major version

**Abort Behavior:** To abort, implementations SHOULD send ErrorFrame (§3.3.12) with the appropriate error code before closing. Implementations MAY close immediately without ErrorFrame if sending is not possible (e.g., transport already failed).

---

## 3. Transport Layer

### 3.1 Primary Engine

QUIC over UDP with BBR v2 congestion control.

### 3.2 Chameleon Racing

When initiating a connection, zp races QUIC (UDP) and TLS 1.3 (TCP/443) in parallel.

```
┌─────────────────────────────────────────────────────┐
│                   Connection Start                   │
└─────────────────────────────────────────────────────┘
                          │
          ┌───────────────┴───────────────┐
          ▼                               ▼
    ┌──────────┐                    ┌──────────┐
    │   QUIC   │                    │ TLS 1.3  │
    │   UDP    │                    │   TCP    │
    └──────────┘                    └──────────┘
          │                               │
          └───────────┬───────────────────┘
                      ▼
              First to complete
              handshake wins
```

**Racing Parameters:**

| Parameter | Default | Range | Notes |
|-----------|---------|-------|-------|
| `ZP_RACING_THRESHOLD` | 200ms | 50ms–2000ms | TCP race starts after this delay |
| `ZP_RACING_ADAPTIVE` | true | — | Adjusts threshold to 1.5× observed RTT |
| `ZP_RACING_MAX_WAIT` | 5000ms | — | Absolute timeout |

### 3.3 Transport Migration Protocol

**Byte Order:** All multi-byte integers in wire formats use little-endian byte order unless otherwise specified.

#### 3.3.1 Stream State Model

```
StreamState {
  stream_id:        u32          // Unique stream identifier
  global_seq:       u64          // Monotonic byte counter
  last_acked:       u64          // Highest acknowledged byte
  pending_buffer:   Vec<u8>      // Unacknowledged data (in-memory only)
  flow_window:      u32          // Current flow control window
}
```

**Stream ID Allocation:**
- Client-initiated streams use even IDs (0, 2, 4, ...)
- Server-initiated streams use odd IDs (1, 3, 5, ...)
- Stream ID 0xFFFFFFFF is reserved (invalid)
- IDs MUST NOT be reused within a session
- Stream 0 is reserved for control frames on QUIC (see §3.4)

#### 3.3.2 Degradation Detection

**RTO Definition:** Retransmission Timeout = `smoothed_RTT + 4 × RTT_variance`, with minimum floor of 200ms.

Migration triggers when ANY of:
- **3 consecutive RTO expirations** without acknowledgment
- **ICMP Destination Unreachable** received
- **5-second send stall** (no bytes acknowledged despite pending data)
- **Explicit path failure** (e.g., interface down notification from OS)

#### 3.3.3 Migration State Machine

```
                    ┌──────────────┐
                    │    ACTIVE    │
                    └──────┬───────┘
                           │ degradation detected (§3.3.2)
                           ▼
                    ┌──────────────┐
                    │  MIGRATING   │
                    └──────┬───────┘
                           │ new transport connected
                           ▼
                    ┌──────────────┐
         ┌─────────│  SYNC_SENT   │──────────┐
         │ timeout └──────┬───────┘           │ Sync-Ack received
         ▼                │                   ▼
  ┌─────────────┐        │            ┌──────────────┐
  │   RETRY     │◀───────┘            │  SYNC_ACKED  │
  │ (max 3)     │                     └──────┬───────┘
  └──────┬──────┘                            │
         │ exhausted                         ▼
         ▼                            ┌──────────────┐
  ┌─────────────┐                     │    ACTIVE    │
  │   FAILED    │                     └──────────────┘
  └─────────────┘
```

**Timeouts:** `ZP_SYNC_TIMEOUT` default 2000ms. Backoff: 2s → 4s → 8s.

**Buffer Preservation:** During migration, implementations MUST preserve all data in receive buffers that has not yet been delivered to the application. This data is not retransmitted by the sender; loss results in permanent data loss for the application.

#### 3.3.4 Migration During Key Rotation

If key rotation is in progress when migration triggers:
1. Complete or abort the pending rekey before migrating
2. If KeyUpdate sent but no Ack: abort rekey, revert to previous epoch
3. Sync-Frame uses the current confirmed key epoch
4. After migration completes, initiator may restart key rotation

#### 3.3.5 Sync-Frame Format

```
Sync-Frame (28 bytes per stream + 24 byte header)
┌────────────────────────────────────────────────────┐
│ magic: 0x5A50_4D49 ("ZPMI")           [4 bytes]   │
│ frame_type: 0x01 (SYNC)               [1 byte]    │
│ session_id: [u8; 16]                  [16 bytes]  │
│ stream_count: u16                     [2 bytes]   │
│ flags: u8                             [1 byte]    │
│   bit 0: URGENT - prioritize processing           │
│   bit 1: FINAL - no more migrations expected      │
│   bits 2-7: reserved (must be 0)                  │
├────────────────────────────────────────────────────┤
│ For each stream:                                   │
│   stream_id: u32                      [4 bytes]   │
│   global_seq: u64                     [8 bytes]   │
│   last_acked: u64                     [8 bytes]   │
│   integrity: u64 (XXH64)              [8 bytes]   │
└────────────────────────────────────────────────────┘
```

**Session Identification:** The `session_id` links this migration to an existing session. Receiver MUST match against active sessions; reject with ERR_SYNC_REJECTED if no match.

**Integrity Hash:** `integrity = XXH64(stream_id || global_seq || last_acked)` where each field is serialized exactly as on wire (u32/u64 little-endian) before concatenation. The integrity input is exactly: stream_id (4 bytes LE) || global_seq (8 bytes LE) || last_acked (8 bytes LE), totaling 20 bytes. This detects corruption only; authentication is provided by the enclosing TLS/QUIC AEAD.

**Integrity Failure:** If integrity verification fails for any stream entry, the receiver MUST treat that stream as `MISMATCH` in the Sync-Ack response.

#### 3.3.6 Sync-Ack Format

```
Sync-Ack (21 bytes per stream + 8 byte header)
┌────────────────────────────────────────────────────┐
│ magic: 0x5A50_4D49 ("ZPMI")           [4 bytes]   │
│ frame_type: 0x02 (SYNC_ACK)           [1 byte]    │
│ stream_count: u16                     [2 bytes]   │
│ status: u8                            [1 byte]    │
│   0x00: OK - all streams synchronized              │
│   0x01: PARTIAL - some streams unknown             │
│   0x02: REJECT - version/state mismatch            │
├────────────────────────────────────────────────────┤
│ For each stream:                                   │
│   stream_id: u32                      [4 bytes]   │
│   stream_status: u8                   [1 byte]    │
│     0x00: OK - stream synchronized                 │
│     0x01: UNKNOWN - stream not found               │
│     0x02: MISMATCH - sequence inconsistency        │
│   receiver_last_acked: u64            [8 bytes]   │
│   receiver_seq: u64                   [8 bytes]   │
└────────────────────────────────────────────────────┘
```

**Status Handling:**
- `OK`: Proceed with data sync
- `PARTIAL`: Check per-stream `stream_status`; sync OK streams, reset UNKNOWN/MISMATCH streams
- `REJECT`: Abort migration with `ERR_SYNC_REJECTED` (0x0C); attempt fresh connection

**Status Invariant:** Frame-level `status=OK` implies all per-stream `stream_status` fields are OK. Implementations MUST NOT send `status=OK` if any stream has non-OK status.

**Per-Stream Status:**
- `OK`: Resume from indicated sequence numbers
- `UNKNOWN`: Receiver has no record; treat as new stream
- `MISMATCH`: Sequence numbers inconsistent; receiver MUST discard all buffered data for that stream, then reset stream and retransmit from zero

**Sequence Number Semantics:**
- `receiver_last_acked`: Last byte offset the receiver has acknowledged to sender
- `receiver_seq`: Next expected byte offset—the first byte the receiver has NOT yet received. Sender resumes transmission from this offset.

**MISMATCH Rationale:** Reset is mandatory because MISMATCH indicates corrupted state—neither side's sequence numbers can be trusted. Partial recovery risks data duplication, gaps, or security issues. See Appendix V, Note 1.

#### 3.3.7 Multiplexing Degradation

On TCP fallback, streams interleaved into single pipe. Head-of-line blocking acknowledged.

```
StreamChunk {
  stream_id: u32      [4 bytes]
  length: u32         [4 bytes]  
  payload: [u8; length]
}
```

**Length Field:** The `length` field specifies payload size in bytes, not including the 8-byte StreamChunk header (stream_id + length fields).

**StreamChunk Usage:** StreamChunk describes the logical structure of multiplexed data within DataFrame payload. On TCP fallback with multiple active streams, DataFrame.stream_id is set to 0xFFFFFFFF (sentinel) and payload MUST contain one or more StreamChunks, each identifying its target stream. Receivers detect multiplexed mode by checking DataFrame.stream_id == 0xFFFFFFFF; if not sentinel, payload is raw data for the specified stream. For single-stream connections, DataFrame uses actual stream_id with raw payload; StreamChunk wrapper is not required.

#### 3.3.8 Stream Priority

`ZP_STREAM_PRIORITY` controls interleaving order:

| Mode | Behavior |
|------|----------|
| `FIFO` | Streams served in order of first byte arrival (default) |
| `ROUND_ROBIN` | Equal chunks from each stream in rotation |
| `WEIGHTED` | Proportional bandwidth per stream weight |

**Weighted Mode:**

Each stream has `priority: u8` (1-255, default 128). Bandwidth share = `stream.priority / sum(all priorities)`.

**Priority Zero Handling:** If application provides priority=0, implementation MUST clamp to 1 before use. This avoids division-by-zero when computing bandwidth shares.

Example: Stream A (priority=200), Stream B (priority=50). A gets 80% of bandwidth, B gets 20%.

#### 3.3.9 Flow Control

Flow control prevents fast senders from overwhelming slow receivers.

**Control Frame Exemption:** Control frames (WindowUpdate, KeyUpdate, Sync-Frame, AckFrame, ErrorFrame) are EXEMPT from flow control. Flow control applies only to DataFrame payloads. This prevents deadlock where exhausted windows block the WindowUpdate needed to replenish them.

**Window Initialization:**
- Connection-level window: `ZP_INITIAL_CONN_WINDOW` (default: 1MB)
- Per-stream window: `ZP_INITIAL_STREAM_WINDOW` (default: 256KB)

**Window Update Frame:**

```
WindowUpdate (17 bytes)
┌────────────────────────────────────────────────────┐
│ magic: 0x5A50_5755 ("ZPWU")           [4 bytes]   │
│ frame_type: 0x30                      [1 byte]    │
│ stream_id: u32                        [4 bytes]   │
│   (0x00000000 = connection-level)                  │
│ window_increment: u64                 [8 bytes]   │
└────────────────────────────────────────────────────┘
```

**Sender Behavior:**
1. Track `available_window` per stream AND per connection
2. Before sending N bytes: check `min(conn_window, stream_window) >= N`
3. If insufficient window on either level: block until WindowUpdate received
4. After sending N bytes: decrement BOTH `conn_window -= N` and `stream_window -= N`

**Note:** Senders track two windows (connection and per-stream) and decrement both when sending. A WindowUpdate frame affects only the specified stream_id; it does not simultaneously update both levels.

**Receiver Behavior:**
1. Track `consumed` bytes per stream and connection
2. After delivering data to application: increment `consumed`
3. When `consumed >= initial_window / 2` (where `initial_window` is `ZP_INITIAL_STREAM_WINDOW` for streams or `ZP_INITIAL_CONN_WINDOW` for connection-level): send WindowUpdate with `window_increment = consumed`, reset `consumed = 0`

**Window Increment Limits:** Receivers MUST NOT send `window_increment` values exceeding 2^32-1. Senders MUST use saturating addition: `new_window = min(current_window + increment, 2^32-1)`. Window state MUST NOT exceed 2^32-1.

**Stall Prevention:** If no WindowUpdate received within `ZP_FLOW_TIMEOUT` (default: 30s) while blocked, abort with `ERR_FLOW_STALL` (0x0D).

#### 3.3.10 Data Frame Format

On non-QUIC transports (TCP, WebSocket, WebRTC DataChannel), zp frames data explicitly:

```
DataFrame (variable size)
┌────────────────────────────────────────────────────┐
│ magic: 0x5A50_4446 ("ZPDF")           [4 bytes]   │
│ frame_type: 0x40                      [1 byte]    │
│ stream_id: u32                        [4 bytes]   │
│ seq: u64                              [8 bytes]   │
│   (same as global_seq in StreamState)             │
│ flags: u8                             [1 byte]    │
│   bit 0: FIN - last frame for this stream         │
│   bit 1: RST - reset stream                       │
│   bits 2-7: reserved (must be 0)                  │
│ length: u32                           [4 bytes]   │
│ payload: [u8; length]                 [variable]  │
└────────────────────────────────────────────────────┘
Header: 22 bytes + payload
```

**Sequence Numbers:** `seq` in DataFrame is the `global_seq` byte offset for the first byte of payload. After sending, `global_seq += length`.

**Monotonicity:** `global_seq` MUST be strictly monotonically increasing for the lifetime of the connection. Each byte sent increments global_seq exactly once; values MUST NOT be reused or rolled back.

**Frame Dispatch:** Receivers distinguish frame types by magic number:

*Handshake frames:*
- `0x5A50_4348` ("ZPCH"): ClientHello
- `0x5A50_5348` ("ZPSH"): ServerHello
- `0x5A50_4346` ("ZPCF"): ClientFinish
- `0x5A50_4B48` ("ZPKH"): KnownHello
- `0x5A50_4B52` ("ZPKR"): KnownResponse
- `0x5A50_4B46` ("ZPKF"): KnownFinish

*Control frames:*
- `0x5A50_4D49` ("ZPMI"): Sync-Frame or Sync-Ack
- `0x5A50_4B55` ("ZPKU"): KeyUpdate or KeyUpdate-Ack
- `0x5A50_414B` ("ZPAK"): AckFrame
- `0x5A50_5755` ("ZPWU"): WindowUpdate
- `0x5A50_4552` ("ZPER"): ErrorFrame

*Data frames:*
- `0x5A50_4446` ("ZPDF"): DataFrame

**On QUIC:** Native QUIC streams provide framing, sequencing, and flow control. DataFrame format is NOT used; data is sent directly on QUIC streams. Control frames (Sync, KeyUpdate, Ack, WindowUpdate) are sent on stream 0.

**AckFrame Usage:** AckFrame is only used when the underlying transport is unreliable (WebRTC DataChannel with maxRetransmits:0). On TCP, WebSocket, and QUIC, AckFrame is neither sent nor processed—the transport provides reliability.

#### 3.3.11 Stream Lifecycle

**FIN (graceful close):**
1. Sender sets `FIN` flag on last DataFrame
2. Sender enters `HALF_CLOSED_LOCAL` state; may still receive
3. Receiver delivers final data, sends ACK covering the FIN sequence
4. Receiver enters `HALF_CLOSED_REMOTE` state; may still send
5. When both sides have sent FIN and received ACK: stream is `CLOSED`
6. Stream resources released after `ZP_STREAM_LINGER` (default: 30s)

**RST (abrupt termination):**
1. Sender sets `RST` flag on DataFrame (payload typically empty)
2. Sender immediately considers stream `CLOSED`; discards pending data
3. Receiver discards any buffered data for this stream
4. Receiver sends ACK for RST frame
5. Receiver considers stream `CLOSED`; no response frame required
6. In-flight data for this stream is ignored by both sides

**State transitions:**
```
OPEN ──FIN sent──▶ HALF_CLOSED_LOCAL ──FIN recv'd──▶ CLOSED
OPEN ──FIN recv'd─▶ HALF_CLOSED_REMOTE ─FIN sent───▶ CLOSED
OPEN ──RST sent/recv──▶ CLOSED (immediate)
```

#### 3.3.12 ErrorFrame Format

```
ErrorFrame (9 bytes)
┌────────────────────────────────────────────────────┐
│ magic: 0x5A50_4552 ("ZPER")           [4 bytes]   │
│ frame_type: 0x60                      [1 byte]    │
│ error_code: u8                        [1 byte]    │
│ reserved: [u8; 3]                     [3 bytes]   │
└────────────────────────────────────────────────────┘
```

Error codes are defined in Appendix B. After sending ErrorFrame, the sender SHOULD close the transport connection.

**Plaintext Transmission:** ErrorFrame is always transmitted in plaintext (not wrapped in EncryptedRecord). This ensures delivery during cryptographic failures. Receivers MUST accept ErrorFrame outside EncryptedRecord at any protocol phase after initial framing is established, until the connection enters a terminal closed state.

**Termination Ordering:** When both ErrorFrame and connection termination occur, their relative ordering is implementation-defined. Implementations MAY send ErrorFrame before, after, or concurrently with transport-level connection close.

#### 3.3.13 Encrypted Record Format (Non-QUIC)

On non-QUIC transports (TCP, WebSocket, WebRTC DataChannel), all post-handshake frames are wrapped in an encrypted record, except for ErrorFrame (§3.3.12) which is always transmitted in plaintext.

**Frame Disambiguation:** On stream transports, receivers read the first 4 bytes and check if they equal ErrorFrame magic (0x5A50_4552). If match, process as ErrorFrame (§3.3.12). Otherwise, interpret as EncryptedRecord length field.

**Maximum Record Size:** Receivers MUST reject records with length exceeding `ZP_MAX_RECORD_SIZE` (default: 16,777,216 bytes / 16MB). This ensures disambiguation—ErrorFrame magic (1,515,210,066) exceeds the maximum valid length—and prevents memory exhaustion attacks. Future increases to ZP_MAX_RECORD_SIZE MUST remain below ErrorFrame magic value (1,515,210,066) to maintain disambiguation.

```
EncryptedRecord (variable size)
┌────────────────────────────────────────────────────┐
│ length: u32                          [4 bytes]    │
│ epoch: u8                            [1 byte]     │
│ counter: u64                         [8 bytes]    │
│ ciphertext: [u8; length - 29]        [variable]   │
│ tag: [u8; 16]                        [16 bytes]   │
└────────────────────────────────────────────────────┘
Total: length bytes (minimum 29 for empty payload)
```

**Fields:**
- `length`: Total record size including all fields
- `epoch`: Lower 8 bits of `key_epoch`; used to select decryption key during grace period
- `counter`: Nonce counter for this record (see §6.5.1 for nonce construction)
- `ciphertext`: AEAD-encrypted frame (DataFrame, AckFrame, WindowUpdate, etc.)
- `tag`: 16-byte AEAD authentication tag

**Encryption:** The entire inner frame (including magic number) is encrypted. The `length`, `epoch`, and `counter` fields are plaintext but authenticated via AEAD's associated data.

**AAD Construction:** AAD is constructed by concatenating: length (4 bytes, little-endian), epoch (1 byte), counter (8 bytes, little-endian), in wire order (13 bytes total).

**Decryption:** Receiver reads `length`, then reads remaining `length - 4` bytes. Uses `epoch` to select key (current or previous during grace period). Constructs nonce from `counter`. Decrypts ciphertext with AAD verification.

**On QUIC:** This format is NOT used. QUIC provides its own encryption and framing.

### 3.4 QUIC Stream Mapping

On QUIC transport, zp leverages native QUIC streams. This section defines the mapping between QUIC stream IDs and zp stream_ids.

**Stream ID Derivation:**
```
zp_stream_id = QUIC_stream_id
```

QUIC stream IDs are used directly as zp stream_ids. This preserves QUIC's built-in uniqueness and even/odd partitioning (RFC 9000 §2.1):
- Client-initiated bidirectional: 0, 4, 8, 12, ... (even, matching §3.3.1 client rule)
- Server-initiated bidirectional: 1, 5, 9, 13, ... (odd, matching §3.3.1 server rule)

**Mapping Examples:**

| QUIC Stream ID | zp stream_id | Initiator |
|----------------|--------------|-----------|
| 0 | 0 | Client (control) |
| 4 | 4 | Client (first data) |
| 8 | 8 | Client |
| 5 | 5 | Server (first data) |
| 9 | 9 | Server |

**Control Stream:** QUIC stream 0 (zp_stream_id 0) is reserved for zp control frames (KeyUpdate, WindowUpdate, Sync-Frame, AckFrame). Data MUST NOT be sent on stream 0. QUIC stream 0 is exclusively for control frames and is NOT available as a client-initiated data stream. Both endpoints send control frames on this stream; the client opens it, and both sides transmit on it bidirectionally.

**Control Stream Initialization:** Client MUST open QUIC stream 0 immediately after QUIC handshake completes by sending a connection-level WindowUpdate (stream_id=0, window_increment=ZP_INITIAL_CONN_WINDOW). This advertises the client's receive window capacity, informing the server how much data the client can initially accept. Server MUST NOT send control frames on stream 0 until the client has opened it.

**Control Stream Enforcement:** Receipt of DataFrame or any non-control frame on stream 0 MUST result in ERR_PROTOCOL_VIOLATION (0x0E) and connection termination.

**Control Frame Framing:** Control frames on QUIC stream 0 use the same magic-prefixed format as on other transports. Receivers dispatch by magic number (§3.3.10). No EncryptedRecord wrapper is used on QUIC—QUIC provides native encryption.

**Data Streams:** Applications open QUIC streams starting at 4 (client) or 5 (server). The QUIC stream ID is used directly as the zp_stream_id in all control frames (WindowUpdate, Sync-Frame, State Token).

**Unidirectional Streams:** zp does not use QUIC unidirectional streams. Implementations MUST reject incoming unidirectional streams with a QUIC STREAM_STATE_ERROR.

**Migration to QUIC:** When migrating from non-QUIC transport to QUIC, the Sync-Frame carries zp stream_ids. After sync, the initiator opens QUIC streams with IDs equal to the zp stream_ids. Stream 0 is control; data streams use IDs 4, 8, 12... (client) or 5, 9, 13... (server).

---

## 4. Security Architecture

### 4.1 Connection Modes

| Mode | When to Use | Authentication | PQC | MITM Protection |
|------|-------------|----------------|-----|-----------------|
| **Stranger** | First contact | None (TOFU) | ✓ | ✗ |
| **Known** | Pre-shared secret | SPAKE2+ | ✓ | ✓ |
| **Verified** | High-assurance | SPAKE2+ + TEE | ✓ | ✓ |

### 4.2 Stranger Mode (Default)

Security equivalent to SSH first-connection.

```
Client                                    Server
   │                                         │
   │─── ClientHello ────────────────────────▶│
   │                                         │
   │◀── ServerHello ────────────────────────│
   │                                         │
   │─── ClientFinish ───────────────────────▶│
   │                                         │
   │◀══════ Encrypted Data Flow ════════════▶│
```

**Handshake Timing:** If no ServerHello received within `ZP_HANDSHAKE_TIMEOUT` (default: 5000ms), retransmit ClientHello. After `ZP_HANDSHAKE_RETRIES` (default: 3) failures, abort with `ERR_HANDSHAKE_TIMEOUT` (0x01).

#### 4.2.1 ClientHello Format

```
ClientHello (variable size)
┌────────────────────────────────────────────────────┐
│ magic: 0x5A50_4348 ("ZPCH")           [4 bytes]   │
│ frame_type: 0x50                      [1 byte]    │
│ version_count: u8                     [1 byte]    │
│ supported_versions: [u16; version_count] [var]    │
│ min_version: u16                      [2 bytes]   │
│ cipher_count: u8                      [1 byte]    │
│ supported_ciphers: [u8; cipher_count] [variable]  │
│ x25519_pubkey: [u8; 32]               [32 bytes]  │
│ random: [u8; 32]                      [32 bytes]  │
└────────────────────────────────────────────────────┘
```

#### 4.2.2 ServerHello Format

```
ServerHello (variable size)
┌────────────────────────────────────────────────────┐
│ magic: 0x5A50_5348 ("ZPSH")           [4 bytes]   │
│ frame_type: 0x51                      [1 byte]    │
│ selected_version: u16                 [2 bytes]   │
│ selected_cipher: u8                   [1 byte]    │
│ x25519_pubkey: [u8; 32]               [32 bytes]  │
│ mlkem_pubkey_len: u16                 [2 bytes]   │
│ mlkem_pubkey: [u8; mlkem_pubkey_len]  [variable]  │
│   ML-KEM-768: 1184 bytes                          │
│   ML-KEM-1024: 1568 bytes                         │
│ random: [u8; 32]                      [32 bytes]  │
└────────────────────────────────────────────────────┘
```

**Size by cipher suite:**
- ZP_PQC_1 (ML-KEM-768): 4+1+2+1+32+2+1184+32 = **1258 bytes**
- ZP_PQC_2 (ML-KEM-1024): 4+1+2+1+32+2+1568+32 = **1642 bytes**
- ZP_CLASSICAL_1: mlkem_pubkey_len=0, **74 bytes**

#### 4.2.3 ClientFinish Format

```
ClientFinish (variable size)
┌────────────────────────────────────────────────────┐
│ magic: 0x5A50_4346 ("ZPCF")           [4 bytes]   │
│ frame_type: 0x52                      [1 byte]    │
│ mlkem_ciphertext_len: u16             [2 bytes]   │
│ mlkem_ciphertext: [u8; mlkem_ciphertext_len] [var]│
│   ML-KEM-768: 1088 bytes                          │
│   ML-KEM-1024: 1568 bytes                         │
└────────────────────────────────────────────────────┘
```

**Size by cipher suite:**
- ZP_PQC_1 (ML-KEM-768): 4+1+2+1088 = **1095 bytes**
- ZP_PQC_2 (ML-KEM-1024): 4+1+2+1568 = **1575 bytes**
- ZP_CLASSICAL_1: mlkem_ciphertext_len=0, **7 bytes**

#### 4.2.4 Key Derivation

After handshake:
```
// For PQC cipher suites (ZP_PQC_1, ZP_PQC_2):
shared_secret = X25519(client_priv, server_pub) || ML-KEM-Decap(ciphertext)

// For ZP_CLASSICAL_1:
shared_secret = X25519(client_priv, server_pub)

// For ZP_CLASSICAL_2 (FIPS):
shared_secret = ECDH-P256(client_priv, server_pub)

session_id = SHA-256(client_random || server_random || shared_secret)[0:16]
session_secret = HKDF-SHA256(
  ikm:  shared_secret,
  salt: client_random || server_random,
  info: "zp-session-secret",
  len:  32
)
session_keys = HKDF-SHA256(
  ikm:  shared_secret,
  salt: client_random || server_random,
  info: "zp-session-keys",
  len:  64  // 32 bytes client_to_server + 32 bytes server_to_client
)
```

**Key Assignment:**
- `client_to_server_key = session_keys[0:32]` — Client uses for sending, Server uses for receiving
- `server_to_client_key = session_keys[32:64]` — Server uses for sending, Client uses for receiving

From Client's perspective: `send_key = client_to_server_key`, `recv_key = server_to_client_key`
From Server's perspective: `send_key = server_to_client_key`, `recv_key = client_to_server_key`

**Classical Mode:** When `mlkem_ciphertext_len=0` (ZP_CLASSICAL_1 or ZP_CLASSICAL_2), the shared_secret is the key exchange output only (32 bytes). ZP_CLASSICAL_1 uses X25519; ZP_CLASSICAL_2 uses ECDH-P256 for FIPS compliance. Classical modes provide no post-quantum security but remain useful for constrained environments or regulatory requirements.

**session_id** is a 16-byte identifier used in key rotation (§4.6.3). It is derived deterministically from handshake material.

**session_secret** is a 32-byte value stored in State Token (§6.5) and used as `current_secret` for key rotation (§4.6.3).

**Properties:** Forward secrecy ✓, PQC ✓, Mutual auth ✗, MITM protection ✗

**For high-value targets:** Use Known Mode with out-of-band secret.

### 4.3 Known Mode

**Random Freshness:** Both parties MUST generate cryptographically random values for the `random` field in each handshake. Reusing random values across handshakes enables catastrophic nonce reuse attacks on the AEAD-encrypted ML-KEM exchange.

```
Client                                    Server
   │                                         │
   │─── KnownHello (SPAKE2+ Message A) ─────▶│
   │◀── KnownResponse (SPAKE2+ Message B) ──│
   │    (Both derive K)                      │
   │─── KnownFinish (ML-KEM encrypted) ─────▶│
   │◀══════ PQC Encrypted Data Flow ════════▶│
```

#### 4.3.1 KnownHello Format

```
KnownHello (variable size)
┌────────────────────────────────────────────────────┐
│ magic: 0x5A50_4B48 ("ZPKH")           [4 bytes]   │
│ frame_type: 0x53                      [1 byte]    │
│ version_count: u8                     [1 byte]    │
│ supported_versions: [u16; version_count] [var]    │
│ min_version: u16                      [2 bytes]   │
│ cipher_count: u8                      [1 byte]    │
│ supported_ciphers: [u8; cipher_count] [variable]  │
│ spake2_message_a: [u8; 32]            [32 bytes]  │
│ random: [u8; 32]                      [32 bytes]  │
└────────────────────────────────────────────────────┘
```

#### 4.3.2 KnownResponse Format

```
KnownResponse (variable size)
┌────────────────────────────────────────────────────┐
│ magic: 0x5A50_4B52 ("ZPKR")           [4 bytes]   │
│ frame_type: 0x54                      [1 byte]    │
│ selected_version: u16                 [2 bytes]   │
│ selected_cipher: u8                   [1 byte]    │
│ spake2_message_b: [u8; 32]            [32 bytes]  │
│ random: [u8; 32]                      [32 bytes]  │
│ mlkem_pubkey_encrypted_len: u16       [2 bytes]   │
│ mlkem_pubkey_encrypted: [u8; len]     [variable]  │
│   ML-KEM-768: 1184 + 16 (tag) = 1200 bytes        │
│   ML-KEM-1024: 1568 + 16 (tag) = 1584 bytes       │
└────────────────────────────────────────────────────┘
```

**Size by cipher suite:**
- ZP_PQC_1 (ML-KEM-768): 4+1+2+1+32+32+2+1200 = **1274 bytes**
- ZP_PQC_2 (ML-KEM-1024): 4+1+2+1+32+32+2+1584 = **1658 bytes**

#### 4.3.3 KnownFinish Format

```
KnownFinish (variable size)
┌────────────────────────────────────────────────────┐
│ magic: 0x5A50_4B46 ("ZPKF")           [4 bytes]   │
│ frame_type: 0x55                      [1 byte]    │
│ mlkem_ciphertext_encrypted_len: u16   [2 bytes]   │
│ mlkem_ciphertext_encrypted: [u8; len] [variable]  │
│   ML-KEM-768: 1088 + 16 (tag) = 1104 bytes        │
│   ML-KEM-1024: 1568 + 16 (tag) = 1584 bytes       │
└────────────────────────────────────────────────────┘
```

**Size by cipher suite:**
- ZP_PQC_1 (ML-KEM-768): 4+1+2+1104 = **1111 bytes**
- ZP_PQC_2 (ML-KEM-1024): 4+1+2+1584 = **1591 bytes**

#### 4.3.4 Key Derivation

**Handshake Encryption Nonces:**
- `mlkem_pubkey_encrypted` nonce: first 12 bytes of SHA-256(server_random)
- `mlkem_ciphertext_encrypted` nonce: first 12 bytes of SHA-256(client_random)

The nonce is taken in the order produced by the hash function (bytes at indices 0 through 11 of the 32-byte hash output). These are single-use per handshake, making fixed derivation safe. Deriving nonces via SHA-256 truncation from fresh random values is cryptographically safe: the hash provides uniform distribution, and freshness guarantees uniqueness per handshake.

**Session Key Derivation:**

*Both parties:*
```
// client_random from KnownHello, server_random from KnownResponse
spake2_key = SPAKE2+(password, message_a, message_b)
nonce_server = SHA-256(server_random)[0:12]
nonce_client = SHA-256(client_random)[0:12]
```

*Server:*
```
// Server generates ML-KEM keypair, encrypts pubkey
(mlkem_pubkey, mlkem_privkey) = ML-KEM-KeyGen()
mlkem_pubkey_encrypted = AES-256-GCM-Encrypt(spake2_key, nonce_server, mlkem_pubkey)
// Server sends mlkem_pubkey_encrypted in KnownResponse
// Server receives mlkem_ciphertext_encrypted in KnownFinish
mlkem_ciphertext = AES-256-GCM-Decrypt(spake2_key, nonce_client, mlkem_ciphertext_encrypted)
shared_secret = ML-KEM-Decap(mlkem_ciphertext, mlkem_privkey)
```

*Client:*
```
// Client receives mlkem_pubkey_encrypted in KnownResponse
mlkem_pubkey = AES-256-GCM-Decrypt(spake2_key, nonce_server, mlkem_pubkey_encrypted)
(mlkem_ciphertext, shared_secret) = ML-KEM-Encap(mlkem_pubkey)
mlkem_ciphertext_encrypted = AES-256-GCM-Encrypt(spake2_key, nonce_client, mlkem_ciphertext)
// Client sends mlkem_ciphertext_encrypted in KnownFinish
```

*Both parties (with identical shared_secret):*
```
session_id = SHA-256(client_random || server_random || spake2_key)[0:16]
session_secret = HKDF-SHA256(
  ikm:  spake2_key || shared_secret,
  salt: client_random || server_random,
  info: "zp-session-secret",
  len:  32
)
session_keys = HKDF-SHA256(
  ikm:  spake2_key || shared_secret,
  salt: client_random || server_random,
  info: "zp-known-session-keys",
  len:  64  // 32 bytes client_to_server + 32 bytes server_to_client
)
```

**Key Assignment:** Same as Stranger Mode (§4.2.4):
- `client_to_server_key = session_keys[0:32]`
- `server_to_client_key = session_keys[32:64]`

**session_secret** is stored in State Token and used as `current_secret` for key rotation (§4.6.3).

**Classical Vulnerability Window:** 1-2 RTT (proportional to path latency, not wall-clock).

### 4.4 Verified Mode

Extends Known Mode with TEE attestation (SGX, Nitro, TrustZone).

### 4.5 Cipher Pinning

#### 4.5.1 Capability Store

```
CapabilityEntry {
  peer_id:          [u8; 32]
  pqc_supported:    bool
  min_cipher_suite: CipherSuite
  first_seen:       Timestamp
  last_seen:        Timestamp
  pin_policy:       PinPolicy
  signature:        [u8; 64]    // Browser only
}
```

#### 4.5.2 Platform Storage

| Platform | Storage | Protection |
|----------|---------|------------|
| iOS | Keychain | Secure Enclave |
| Android | AndroidKeyStore | Hardware-backed |
| Browser | IndexedDB | WebCrypto + signatures |

**Browser Signature Threat Model:** Signatures protect against offline tampering (malware editing IndexedDB files directly), NOT same-origin XSS. XSS can invoke the signing key to create malicious entries. For XSS-resistant deployments, use server-distributed Manifests with out-of-band verification (e.g., certificate pinning in native wrapper).

#### 4.5.3 Pinning Behavior

| Scenario | Action |
|----------|--------|
| First contact | Store capability |
| Returning peer offers PQC | Accept |
| Returning peer downgrades | **REJECT** |
| Key change | Warn user |

#### 4.5.4 Discovery Manifests (Tier 2)

Administrators distribute signed capability manifests for enterprise deployments:

```
Manifest {
  version:          u32
  issued_at:        u64          // Unix timestamp
  expires_at:       u64          // Unix timestamp
  min_cipher_suite: CipherSuite
  pinned_peers:     Vec<PinnedPeer>
  revocations:      Vec<[u8; 32]>  // peer_ids
}

PinnedPeer {
  peer_id:          [u8; 32]
  public_key:       [u8; 32]
  min_cipher_suite: CipherSuite
}

// Signed with Ed25519
ManifestEnvelope {
  manifest:         Manifest
  signature:        [u8; 64]
  signer_pubkey:    [u8; 32]
}
```

Distribution: HTTPS endpoint or embedded in app bundle. Clients verify signature before applying.

**Trust Anchor:** The `signer_pubkey` must be trusted via one of:
1. **Hardcoded root:** SDK ships with embedded root public key(s)
2. **App-pinned:** Application embeds allowed signer keys at build time
3. **HTTPS bootstrap:** First manifest fetched over TLS from pinned domain; subsequent manifests signed by key in first manifest

Option 1 or 2 recommended for high-security deployments. Option 3 acceptable for convenience but inherits TLS PKI trust model.

### 4.6 Key Rotation

Long-lived sessions rotate keys periodically to limit exposure.

#### 4.6.1 Parameters

| Setting | Default | Notes |
|---------|---------|-------|
| `ZP_REKEY_INTERVAL_BYTES` | 1GB | Trigger after data volume |
| `ZP_REKEY_INTERVAL_SECS` | 3600 | Trigger after duration |
| `ZP_REKEY_ENABLED` | true | — |

#### 4.6.2 KeyUpdate Frame

```
KeyUpdate (16 bytes)
┌────────────────────────────────────────────────────┐
│ magic: 0x5A50_4B55 ("ZPKU")           [4 bytes]   │
│ frame_type: 0x10                      [1 byte]    │
│ key_epoch: u32                        [4 bytes]   │
│ direction: u8                         [1 byte]    │
│   0x01: rotate client-to-server key               │
│   0x02: rotate server-to-client key               │
│   0x03: both                                      │
│ reserved: [u8; 6]                     [6 bytes]   │
└────────────────────────────────────────────────────┘
```

#### 4.6.3 Key Derivation

```
new_key = HKDF-SHA256(
  ikm:  current_secret,                    // session_secret from handshake (§4.2.4/§4.3.4)
  salt: session_id || key_epoch,           // key_epoch as 4 bytes little-endian
  info: "zp-traffic-key-" || direction,    // Direction as ASCII string
  len:  32
)
```

**Direction Encoding:** The `direction` in info string uses absolute labels (not relative to sender):
- `0x01` → `"c2s"` (info = `"zp-traffic-key-c2s"`) — client-to-server
- `0x02` → `"s2c"` (info = `"zp-traffic-key-s2c"`) — server-to-client
- `0x03` → derive both keys separately: perform two HKDF-SHA256 calls, first with info=`"zp-traffic-key-c2s"`, then with info=`"zp-traffic-key-s2c"`

**Info String Encoding:** The info string consists only of ASCII characters and is encoded as UTF-8 (byte-identical to ASCII for this character set). For example, `"zp-traffic-key-c2s"` is exactly 18 bytes: `7A 70 2D 74 72 61 66 66 69 63 2D 6B 65 79 2D 63 32 73`.

**Key Usage:** After derivation:
- Client: `send_key = c2s_key`, `recv_key = s2c_key`
- Server: `send_key = s2c_key`, `recv_key = c2s_key`

Either party may initiate key rotation for either direction.

**Byte Order:** All multi-byte integers in key derivation (key_epoch, etc.) use little-endian encoding.

After rotation, update `current_secret` for forward secrecy:
```
current_secret = HKDF-SHA256(
  ikm:  current_secret,
  salt: session_id || key_epoch,
  info: "zp-secret-update",
  len:  32
)
```

**Nonce Counter Reset:** After key rotation completes, nonce counters for the rotated direction(s) reset to 0. Each key has its own counter namespace; reuse across different keys is cryptographically safe but counters reset for simplicity. When rotating a single direction (0x01 or 0x02), the nonce counter for the non-rotated direction remains unchanged.

#### 4.6.4 Rotation Protocol

```
1. Initiator increments key_epoch
2. Initiator derives new key(s) for specified direction(s)
3. Initiator sends KeyUpdate with new epoch
4. Initiator MUST wait for KeyUpdate-Ack before using new key
5. Receiver processes KeyUpdate, derives same new key(s)
6. Receiver sends KeyUpdate-Ack with matching epoch
7. Upon receiving Ack, initiator begins using new key
8. Both sides retain old keys for grace period (ZP_REKEY_GRACE = 5s)
9. After grace period: old keys securely erased
```

**Critical:** Initiator MUST NOT send data encrypted with the new key until KeyUpdate-Ack is received. This prevents race conditions where data arrives before the receiver has processed the KeyUpdate.

**Lost KeyUpdate:** If no KeyUpdate-Ack within 2×RTT, retransmit. After 3 retries, abort connection with `ERR_REKEY_FAILED`.

**Retry Idempotency:** Retransmitted KeyUpdate frames MUST use identical key_epoch and derive the same keys. Each logical rotation attempt uses a single epoch value; fresh derivation only occurs for new rotation attempts after failure.

#### 4.6.5 KeyUpdate-Ack Frame

```
KeyUpdate-Ack (9 bytes)
┌────────────────────────────────────────────────────┐
│ magic: 0x5A50_4B55 ("ZPKU")           [4 bytes]   │
│ frame_type: 0x11                      [1 byte]    │
│ acked_epoch: u32                      [4 bytes]   │
└────────────────────────────────────────────────────┘
```

---

## 5. Discovery & NAT Traversal

### 5.1 Connection Establishment Flow

```
┌─────────┐         ┌───────────┐         ┌─────────┐
│ Client  │         │ Signaling │         │  Peer   │
└────┬────┘         └─────┬─────┘         └────┬────┘
     │── Register ───────▶│◀── Register ───────│
     │── Find Peer ──────▶│                    │
     │◀── Peer Candidates─│                    │
     │──── SDP Offer ────▶│───── SDP Offer ───▶│
     │◀─── SDP Answer ────│◀──── SDP Answer ───│
     │════════ ICE / Hole Punch ══════════════│
     │════ Relay (if ICE fails) ══════════════│
```

**P2P Role Assignment:** In peer-to-peer scenarios, the peer that initiates the SDP Offer adopts the Client role (even stream IDs per §3.3.1); the peer that sends SDP Answer adopts the Server role (odd stream IDs). If simultaneous offers occur (glare condition), the peer with the lexicographically higher `random` value in the subsequent zp handshake becomes Client.

**Note:** WebRTC always requires signaling before P2P.

### 5.2 NAT Traversal Stack

| Method | Success Rate | Tier |
|--------|--------------|------|
| Direct | ~20% | 1 |
| UDP Hole Punch | ~65% | 1 |
| TURN Relay | ~100% | 1 (self-hosted) |
| zp-Mesh Relay | ~100% | 2 |

### 5.3 Tier 1 Requirements

- **STUN:** Included client; users provide server URLs
- **TURN:** Self-hosted (e.g., coturn) or upgrade to Tier 2

---

## 6. Platform Adaptation

### 6.1 Persistence Model

| Platform | Foreground | Background | Suspended |
|----------|------------|------------|-----------|
| iOS 15+ | QUIC | HTTP/3 via NSURLSession | State Token |
| Android | QUIC | Foreground Service | WorkManager |
| Chromium | WebTransport | Background Fetch | — |
| Safari/Firefox | WebRTC | None | — |

### 6.2 iOS Backgrounding

NSURLSession manages transfer when backgrounded. Limitations:
- Downloads/uploads only, not bidirectional streaming
- System quotas may throttle heavy use

### 6.3 Android Persistence

**Active:** Foreground Service with notification. Android 14+ requires:
```xml
<service android:foregroundServiceType="dataSync" ... />
```

**Deferred:** WorkManager for non-real-time.

### 6.4 Browser Adaptation

#### 6.4.1 Fallback Chain

WebTransport → WebRTC DataChannel → WebSocket

#### 6.4.2 WebRTC Security Layering

When using WebRTC DataChannel as transport:
- WebRTC provides mandatory DTLS-SRTP encryption (browser-enforced)
- zp runs its own handshake INSIDE the DataChannel
- Result: Double encryption (DTLS outer, zp inner)
- zp's PQC layer provides quantum resistance that DTLS lacks

**Connection mode mapping:**
- Stranger Mode: zp X25519+ML-KEM inside DTLS tunnel
- Known Mode: zp SPAKE2++ML-KEM inside DTLS tunnel
- Verified Mode: Not supported on WebRTC (no TEE access in browser)

**Rationale:** Browser APIs do not expose raw UDP. WebRTC's DTLS is unavoidable. The overhead is acceptable for the transport flexibility gained.

#### 6.4.3 WebRTC DataChannel Configuration

DataChannel MUST be created with:

```javascript
peerConnection.createDataChannel("zp", {
  ordered: false,        // Allow out-of-order delivery
  maxRetransmits: 0      // No automatic retransmits (zp handles reliability)
});
```

**Rationale:** zp implements its own reliability and ordering. Using reliable/ordered DataChannel would add redundant overhead and latency. The unreliable/unordered mode provides UDP-like semantics that zp expects.

#### 6.4.4 zp Reliability Layer

When running over unreliable transports (WebRTC DataChannel with `maxRetransmits:0`), zp provides its own reliability:

**Acknowledgment:** Receiver sends ACK frames for received sequence ranges.

**Retransmission:** Sender retransmits unacknowledged data after RTO expiration (§3.3.2).

**Ordering:** Receiver buffers out-of-order packets and delivers in `global_seq` order.

```
AckFrame (variable size)
┌────────────────────────────────────────────────────┐
│ magic: 0x5A50_414B ("ZPAK")           [4 bytes]   │  offset 0
│ frame_type: 0x20                      [1 byte]    │  offset 4
│ stream_id: u32                        [4 bytes]   │  offset 5
│ ack_range_count: u8                   [1 byte]    │  offset 9
├────────────────────────────────────────────────────┤
│ For each range (starting at offset 10):           │
│   start_seq: u64                      [8 bytes]   │
│   end_seq: u64                        [8 bytes]   │
└────────────────────────────────────────────────────┘
Header: 10 bytes + (16 bytes × ack_range_count)
```

**Range Semantics:** `[start_seq, end_seq]` is inclusive on both ends. A range acknowledges all bytes from `start_seq` through `end_seq` inclusive.

**ACK Frequency:** Send ACK after every 2 packets or 50ms, whichever comes first.

**ACK Loss Recovery:** ACKs are cumulative—each ACK reports all received ranges, not just new ones. If an ACK is lost, the next ACK recovers the information. Senders MUST NOT assume data is lost solely because an expected ACK didn't arrive; wait for RTO before retransmitting.

**Retransmit Buffer:** Sender buffers unacknowledged data for potential retransmission. Buffer size is bounded by `ZP_RETRANSMIT_BUFFER_MAX` (default: 4MB). If buffer is full, sender blocks until space is available via ACKs. This provides natural backpressure on slow/lossy links.

This mechanism is **only active** for unreliable transports. On QUIC and TCP, the underlying transport handles reliability.

#### 6.4.5 Background Limitations

**Background Fetch (Chromium only):** Requires user gesture (click/tap) to initiate. Cannot be triggered programmatically. Max ~1GB per fetch. **Automatic background sync not possible via this API.**

**Safari/Firefox:** Foreground only. UI should warn users that leaving tab pauses transfer.

### 6.5 State Token Format

```
StateToken (≤1024 bytes)
┌─────────────────────────────────────────────────────┐
│ Header (16 bytes)                                   │
│   magic: 0x5A505354 ("ZPST")          [4 bytes]    │
│   version: u8                          [1 byte]    │
│   flags: u8                            [1 byte]    │
│   stream_count: u8 (max 12)            [1 byte]    │
│   reserved: u8                         [1 byte]    │
│   created_at: u64                      [8 bytes]   │
├─────────────────────────────────────────────────────┤
│ Crypto Context (136 bytes)                          │
│   session_id: [u8; 16]                 [16 bytes]  │
│   session_secret: [u8; 32]             [32 bytes]  │
│   send_key: [u8; 32]                   [32 bytes]  │
│   recv_key: [u8; 32]                   [32 bytes]  │
│   send_nonce: u64                      [8 bytes]   │
│   recv_nonce: u64                      [8 bytes]   │
│   key_epoch: u32                       [4 bytes]   │
│   reserved: [u8; 4]                    [4 bytes]   │
├─────────────────────────────────────────────────────┤
│ Connection Context (50 bytes)                       │
│   connection_id: [u8; 20]              [20 bytes]  │
│   peer_address: [u8; 18]               [18 bytes]  │
│   rtt_estimate: u32                    [4 bytes]   │
│   congestion_window: u32               [4 bytes]   │
│   bind_ip_hash: [u8; 4]                [4 bytes]   │
├─────────────────────────────────────────────────────┤
│ Stream States (≤756 bytes, max 12 × 63 bytes)       │
│ Per stream (63 bytes):                              │
│   stream_id: u32                       [4 bytes]   │
│   global_seq: u64                      [8 bytes]   │
│   last_acked: u64                      [8 bytes]   │
│   send_offset: u64                     [8 bytes]   │
│   recv_offset: u64                     [8 bytes]   │
│   flow_window: u32                     [4 bytes]   │
│   state_flags: u8                      [1 byte]    │
│   priority: u8                         [1 byte]    │
│   reserved: [u8; 21]                   [21 bytes]  │
└────────────────────────────────────────────────────┘
Total maximum: 16 + 136 + 50 + 756 = 958 bytes
```

**Stream Offset Fields:**
- `send_offset`: Application's write position—the next byte to be generated by the application for this stream
- `recv_offset`: Application's read position—the next byte to be delivered to the application

These differ from wire-level fields: `global_seq` tracks bytes sent on wire; `last_acked` tracks bytes acknowledged by peer. On resume, `send_offset` indicates where new application data starts; `recv_offset` indicates what has been delivered (and thus need not be buffered for redelivery).

**Token Encryption:** AES-256-GCM with device-bound key (§6.6). The Header (16 bytes) is Additional Authenticated Data (AAD); the remaining bytes (Crypto Context, Connection Context, Stream States) are encrypted.

**Header Flags:** The `flags` field in the Header is reserved for future use. All bits MUST be 0. Receivers SHOULD ignore unknown flag bits for forward compatibility.

**Stream Count Validation:** Receivers MUST reject tokens with `stream_count > 12` or `stream_count == 0` (a valid session has at least one stream). Values 13-255 are reserved and MUST NOT be sent.

**Token Nonce:** Each save generates a fresh random 12-byte nonce for token encryption. This nonce is distinct from session traffic nonces (send_nonce/recv_nonce).

**Token Persistence:** The Storage Format describes the encrypted container written to disk, not the token's logical structure. The token (Header through Stream States) is encrypted as a unit; the stored blob prepends the encryption nonce:

```
token_nonce:  [u8; 12]     // Random nonce for this save
header:       [u8; 16]     // Plaintext (AAD)
ciphertext:   [u8; N]      // Encrypted token body
tag:          [u8; 16]     // AEAD authentication tag
```
Total stored size = 12 + 16 + encrypted_length + 16 = 44 + encrypted_length bytes.

**Timestamp:** `created_at` is u64 Unix timestamp (seconds since 1970-01-01 UTC). No Y2038 issue.

**Nonce Safety:** On resume, implementations MUST skip ahead by `ZP_NONCE_SKIP` (default: 1000) to account for potential sends that occurred after the last token persist but before crash. This wastes some nonce space but prevents catastrophic nonce reuse. For maximum safety, persist token after every send (performance tradeoff).

**High-Throughput Guidance:** Deployments exceeding 1Gbps SHOULD increase `ZP_NONCE_SKIP` proportionally to: `peak_packet_rate × maximum_persist_interval`. For example, at 10Gbps with 1200-byte packets and 100ms persist interval: skip ≥ 100,000.

**Hibernation During Key Rotation:** Implementations SHOULD NOT hibernate during `ZP_REKEY_GRACE` period. The State Token stores only current keys; if hibernation occurs during key rotation grace period, the peer may send packets with the old key that the resumed session cannot decrypt. In this case, re-establish a fresh connection.

#### 6.5.1 AEAD Nonce Construction

Both ChaCha20-Poly1305 and AES-256-GCM require 12-byte (96-bit) nonces. Construct from the 8-byte counter:

```
nonce[0:4]  = 0x00000000              // 4 bytes of zeros (fixed)
nonce[4:12] = counter (little-endian) // 8 bytes from send_nonce or recv_nonce
```

**Fixed Prefix Safety:** The fixed zero prefix is safe because each key (send_key/recv_key per epoch) forms a unique cryptographic context. Nonce uniqueness depends solely on counter monotonicity within each key's lifetime.

**Counter Increment:** After encrypting each message, increment the counter by 1. The counter MUST NOT wrap; if it reaches `2^64 - 1`, trigger key rotation before sending the next message.

**Separate Counters:** `send_nonce` and `recv_nonce` are independent. Each direction maintains its own counter starting from 0 after key derivation or rotation.

#### 6.5.2 Stream State Flags

`state_flags: u8` bit definitions:

| Bit | Name | Meaning |
|-----|------|---------|
| 0 | `OPEN` | Stream is open for data |
| 1 | `HALF_CLOSED_LOCAL` | Local side finished sending |
| 2 | `HALF_CLOSED_REMOTE` | Remote side finished sending |
| 3 | `RESET_PENDING` | Stream reset requested |
| 4-7 | Reserved | Must be 0 |

**Note on pending_buffer:** The `pending_buffer` (unacknowledged data) is NOT stored in the State Token. On resume:
- **Graceful backgrounding** (app still in memory): Buffer survives; resume from `global_seq`
- **App termination/crash:** Buffer lost; resume from `last_acked` (retransmit unacked data)

**Stream Limit:** Max 12 streams. `ZP_TOKEN_OVERFLOW` behavior:
- `REJECT`: Refuse hibernation
- `LRU`: Evict least-recently-used (default)
- `PRIORITY`: Evict lowest-priority

**REJECT Fallback:** If REJECT policy cannot be honored (e.g., OS-forced backgrounding on iOS/Android), implementations SHOULD fall back to LRU behavior and log a warning.

**Priority Persistence:** On resume, streams restore the priority value saved in the token. Applications that dynamically change priority should update priority before hibernation, or re-apply desired priority after resume.

**Lifetime:** 24 hours. `ZP_TOKEN_BIND_IP=true` blocks resumption from different IP.

### 6.6 Device-Bound Key

| Platform | Method |
|----------|--------|
| iOS | Keychain, Secure Enclave if available |
| Android | AndroidKeyStore, StrongBox if available |
| Browser | WebCrypto non-extractable key |

**Key Singularity:** Each device (or app installation) maintains exactly one device-bound key for State Token encryption. No key ID is stored alongside the token; the single key is used for all token operations on that device.

**Key Failure Handling:** If device-bound key generation or retrieval fails (e.g., Secure Enclave unavailable, hardware error), implementations MUST disable State Token persistence and proceed with normal connection establishment without resume capability.

---

## 7. Privacy & Compliance

### 7.1 Oblivious Signaling (O-HTTP)

**Protects:** Client IP hidden from Coordinator.

**Does NOT protect:** Relay sees timing; network observers see client→Relay. Single relay can collude with Coordinator.

**High anonymity:** Use Tier 2 multi-hop.

### 7.2 Traffic Shaping

`ZP_STEALTH_MODE=true` enables constant-rate padding.

| Setting | Default |
|---------|---------|
| `ZP_CHAFF_INTERVAL` | 100ms |
| `ZP_CHAFF_SIZE` | 1200 bytes |
| `ZP_CHAFF_JITTER` | 10ms |

---

## 8. Operational Considerations

### 8.1 Rate Limiting

| Resource | Limit | Notes |
|----------|-------|-------|
| Handshakes per IPv4 | 10/min | Per address |
| Handshakes per IPv6 | 10/min | Per /64 prefix |
| Sync-Frames per connection | 5/min | |
| Signaling per user | 60/min | |
| Token resumptions per IP | 20/min | |

**IPv6 Note:** Rate limiting by individual IPv6 address is ineffective. Limit by /64 prefix (the typical allocation unit). The /64 prefix is a default recommendation; operators may implement finer granularity (e.g., /112 for individual hosts) based on their network topology and abuse patterns. See Appendix V, Note 2 for rationale.

### 8.2 Observability

Expose: `zp_connections_total`, `zp_handshake_duration_ms`, `zp_transport_migrations`, `zp_migration_failures`, `zp_bytes_sent/received`, `zp_active_streams`.

---

## 9. Implementation Notes

### 9.1 Minimum Viable Implementation

1. QUIC + TLS 1.3
2. Stranger Mode (X25519 + ML-KEM-768)
3. Version negotiation
4. Chameleon Racing
5. Transport Migration (Sync-Frame/Sync-Ack)
6. Platform backgrounding
7. Capability Store
8. Rate limiting

### 9.2 Test Vectors

Comprehensive test vectors are provided in [TEST_VECTORS.md](./TEST_VECTORS.md), covering:

- Key exchange (X25519, ML-KEM-768, ML-KEM-1024, ECDH-P256)
- HKDF-SHA256 derivations (session secrets, session keys, key rotation)
- Session ID derivation (Stranger and Known modes)
- AEAD operations (ChaCha20-Poly1305, AES-256-GCM)
- Sync-Frame integrity hash (XXH64)
- State Token encryption
- Nonce construction
- All frame wire formats

**Required conformance tests:** `test_version_negotiation`, `test_stranger_handshake`, `test_known_handshake`, `test_transport_migration`, `test_migration_retry`, `test_chameleon_racing`, `test_state_token`, `test_key_rotation`, `test_key_rotation_lost_ack`, `test_migration_during_rekey`, `test_sync_ack_partial`, `test_sync_ack_reject`, `test_webrtc_ack_frame`, `test_webrtc_retransmit`, `test_flow_control`, `test_flow_stall`, `test_data_frame`, `test_websocket_framing`, `test_stream_fin`, `test_stream_rst`, `test_handshake_stranger_wire`, `test_handshake_known_wire`.

### 9.3 Known Limitations

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| Browser XSS | Pinning bypass | Native SDK for high-assurance |
| iOS background HTTP-only | No bidirectional streaming | Chunk streams |
| SPAKE2+ classical window | 1-2 RTT vulnerability | Pre-position ML-KEM keys |
| HOL blocking on TCP | Latency spikes | Stream priority |
| 12-stream token limit | Not for HTTP/2-style mux | LRU eviction; disable hibernation |
| WebRTC double encryption | ~5% overhead | Acceptable for transport flexibility |

---

## 10. Glossary

| Term | Definition |
|------|------------|
| **BAAP** | Buffer-Aware Application Pacing |
| **ML-KEM** | Module-Lattice KEM (NIST PQC) |
| **O-HTTP** | Oblivious HTTP (RFC 9458) |
| **RTO** | Retransmission Timeout = smoothed_RTT + 4×variance |
| **SPAKE2+** | PAKE protocol (RFC 9383) |
| **TOFU** | Trust On First Use |

---

## Appendix A: Cipher Suites

| Suite | Wire Value | Key Exchange | Symmetric | AEAD Hash |
|-------|------------|--------------|-----------|-----------|
| `ZP_PQC_1` | `0x01` | X25519 + ML-KEM-768 | ChaCha20-Poly1305 | — |
| `ZP_PQC_2` | `0x02` | X25519 + ML-KEM-1024 | AES-256-GCM | — |
| `ZP_CLASSICAL_1` | `0x10` | X25519 | ChaCha20-Poly1305 | — |
| `ZP_CLASSICAL_2` | `0x11` | ECDH-P256 | AES-256-GCM | — |

**Wire Value:** The `u8` value used in `supported_ciphers` and `selected_cipher` fields.

**Note:** Key derivation (§4.2.4, §4.3.4, §4.6.3) always uses **HKDF-SHA256** regardless of cipher suite. The cipher suite only affects key exchange algorithm and symmetric encryption algorithm selection.

**ZP_CLASSICAL_2 (FIPS Mode):** For deployments requiring FIPS 140-3 compliance, ZP_CLASSICAL_2 uses NIST-approved algorithms exclusively. ECDH uses the P-256 curve (secp256r1) per NIST SP 800-56A. This suite provides no post-quantum security but satisfies regulatory requirements in certain environments.

**Reserved Values:** `0x00` is reserved (invalid). Values `0x03-0x0F` reserved for future PQC suites. Values `0x12-0x1F` reserved for future classical suites. Values `0xF0-0xFF` reserved for experimental/private use.

---

## Appendix B: Error Codes

| Code | Name |
|------|------|
| `0x01` | `ERR_HANDSHAKE_TIMEOUT` |
| `0x02` | `ERR_CIPHER_DOWNGRADE` |
| `0x03` | `ERR_MIGRATION_FAILED` |
| `0x04` | `ERR_TOKEN_EXPIRED` |
| `0x05` | `ERR_TEE_ATTESTATION` |
| `0x06` | `ERR_RELAY_UNAVAILABLE` |
| `0x07` | `ERR_VERSION_MISMATCH` |
| `0x08` | `ERR_RATE_LIMITED` |
| `0x09` | `ERR_TOKEN_IP_MISMATCH` |
| `0x0A` | `ERR_STREAM_LIMIT` |
| `0x0B` | `ERR_REKEY_FAILED` |
| `0x0C` | `ERR_SYNC_REJECTED` |
| `0x0D` | `ERR_FLOW_STALL` |
| `0x0E` | `ERR_PROTOCOL_VIOLATION` |

---

## Appendix C: Configuration Reference

| Parameter | Default | Description |
|-----------|---------|-------------|
| `ZP_RACING_THRESHOLD` | 200ms | TCP race delay |
| `ZP_RACING_ADAPTIVE` | true | RTT-adaptive |
| `ZP_RACING_MAX_WAIT` | 5000ms | Connection timeout |
| `ZP_SYNC_TIMEOUT` | 2000ms | Sync-Frame timeout |
| `ZP_HANDSHAKE_TIMEOUT` | 5000ms | Initial handshake timeout |
| `ZP_HANDSHAKE_RETRIES` | 3 | Max handshake retransmissions |
| `ZP_BUFFER_THRESHOLD` | 64KB | BAAP trigger |
| `ZP_PACING_INTERVAL` | 20ms | BAAP interval |
| `ZP_CHAFF_INTERVAL` | 100ms | Stealth interval |
| `ZP_CHAFF_SIZE` | 1200 bytes | Stealth packet size |
| `ZP_CHAFF_JITTER` | 10ms | Stealth jitter |
| `ZP_TOKEN_LIFETIME` | 86400s | Token expiry |
| `ZP_TOKEN_BIND_IP` | false | IP binding |
| `ZP_TOKEN_OVERFLOW` | LRU | Stream overflow |
| `ZP_STREAM_PRIORITY` | FIFO | Interleaving |
| `ZP_REKEY_INTERVAL_BYTES` | 1GB | Rekey trigger |
| `ZP_REKEY_INTERVAL_SECS` | 3600s | Rekey trigger |
| `ZP_REKEY_GRACE` | 5s | Old key retention |
| `ZP_RETRANSMIT_BUFFER_MAX` | 4MB | Max unacked data buffered (WebRTC only) |
| `ZP_INITIAL_CONN_WINDOW` | 1MB | Initial connection flow window |
| `ZP_INITIAL_STREAM_WINDOW` | 256KB | Initial per-stream flow window |
| `ZP_FLOW_TIMEOUT` | 30s | Flow control stall timeout |
| `ZP_NONCE_SKIP` | 1000 | Nonces to skip on resume |
| `ZP_STREAM_LINGER` | 30s | Time before closed stream resources released |
| `ZP_MAX_RECORD_SIZE` | 16MB | Maximum EncryptedRecord length |

**Racing vs Handshake Timing:** `ZP_RACING_MAX_WAIT` applies during transport selection phase; `ZP_HANDSHAKE_TIMEOUT` and `ZP_HANDSHAKE_RETRIES` apply after transport commitment. Racing may intentionally abort before handshake retries exhaust to explore alternative transports faster.

**High-Latency Environments:** For satellite links or congested cellular networks, operators SHOULD increase `ZP_REKEY_GRACE` to at least 3×max_observed_RTT to accommodate retransmissions of old-epoch packets.

---

## Appendix D: WebSocket Subprotocol

Identifier: `zp.v1`

**Message Format:**
- All messages are **binary** WebSocket frames
- Each WebSocket message contains exactly **one** zp frame
- During handshake: frame type determined by magic number (§3.3.10)
- Post-handshake: messages contain EncryptedRecord (§3.3.13) or plaintext ErrorFrame; decrypted payload uses magic number dispatch
- Frame disambiguation per §3.3.13

**Connection Lifecycle:**
1. Client initiates WebSocket with `Sec-WebSocket-Protocol: zp.v1`
2. Server confirms with same header
3. Client sends ClientHello as first binary message
4. Handshake proceeds as per §4.2/§4.3
5. Data and control frames exchanged per §3.3.10

**Fragmentation:** Large DataFrames may be split across multiple WebSocket frames using WebSocket fragmentation. Receiver reassembles before processing.


---

## Appendix E: Design Rationale

This appendix documents key design decisions made during protocol development. Full change history is available in [CHANGELOG.md](./CHANGELOG.md).

### E.1 Protocol Architecture

**MISMATCH Reset Behavior (Note 1)**

MISMATCH on Sync-Ack mandates full stream reset rather than partial recovery. MISMATCH indicates sequence number inconsistency—neither side's state can be trusted. Attempting partial recovery risks data duplication, gaps, or security issues if the inconsistency stems from corruption or attack. Full reset is the only safe option.

**IPv6 Rate Limiting by /64 Prefix (Note 2)**

Rate limiting IPv6 by /64 prefix follows RFC 6177's recommendation that /64 is the standard end-user allocation. Smaller prefixes (e.g., /56) would unfairly penalize legitimate users behind carrier-grade NAT. Larger prefixes provide minimal benefit since attackers can easily obtain multiple /64 allocations. Operators with specific deployment needs may implement custom prefix lengths.

**Session ID Derivation Differences (Note 3)**

Stranger Mode uses `session_id = SHA-256(client_random || server_random || shared_secret)[0:16]`. Known Mode uses `session_id = SHA-256(client_random || server_random || spake2_key)[0:16]`. This difference is intentional: session_id serves as an identifier for key rotation context, not a security parameter. In Known Mode, SPAKE2+ provides mutual authentication; the spake2_key is the authenticated material, making inclusion of shared_secret redundant.

### E.2 Frame Design

**Handshake Frame Parsing (Note 8)**

Handshake frames use field-by-field parsing with explicit length fields for variable portions (version_count, cipher_count, mlkem_pubkey_len). This is standard TLS-style parsing. The EncryptedRecord format with length prefix covers the performance-critical post-handshake data path. Handshake is a one-time operation per connection.

**QUIC Stream 0 Is Not Reserved for Crypto (Note 16)**

Per RFC 9000 §2.1, QUIC stream 0 is the first client-initiated bidirectional stream. QUIC handshake uses CRYPTO frames (separate from streams). QUIC ACK/PATH_CHALLENGE are frame types, not stream data. zp correctly uses QUIC stream 0 for control frames.

**QUIC Stream ID Direct Mapping (Note 25)**

RC19-RC22 used formula `zp_stream_id = QUIC_stream_id / 4` which caused QUIC streams 4 (client) and 5 (server) to both map to zp_stream_id 1, breaking uniqueness. v1.0 uses direct mapping `zp_stream_id = QUIC_stream_id`, preserving QUIC's built-in uniqueness and even/odd partitioning.

**Maximum Record Size Ensures Disambiguation (Note 26)**

Frame disambiguation relies on ErrorFrame magic (1,515,210,066) exceeding maximum valid record length. ZP_MAX_RECORD_SIZE (16MB) ensures the magic value is always invalid as a length, making disambiguation bulletproof. Also prevents DoS via massive allocation.

### E.3 Flow Control

**Control Frame Exemption (Note 29)**

Control frames (WindowUpdate, KeyUpdate, Sync-Frame, AckFrame, ErrorFrame) must be exempt from flow control. Otherwise, an exhausted window blocks the WindowUpdate needed to replenish it—classic deadlock. Data payloads remain flow-controlled.

**Saturating Addition (Note 35)**

Flow control window updates use saturating addition: `new_window = min(current_window + increment, 2^32-1)`. This prevents integer overflow when adding large increments to existing windows.

### E.4 Cryptographic Design

**SPAKE2+ Direct Key Use (Note 27)**

SPAKE2+ outputs are already uniformly random 32-byte keys suitable for direct use with AES-256-GCM. Additional HKDF adds complexity without security benefit for single-use encryption. Implementation may optionally derive for "conceptual clarity" but protocol does not require it.

**Nonce Zero Prefix Safety (Note in §6.5.1)**

The fixed zero prefix in nonce construction is safe because each key (send_key/recv_key per epoch) forms a unique cryptographic context. Nonce uniqueness depends solely on counter monotonicity within each key's lifetime.

### E.5 State Management

**State Token Grace Period Trade-off (Note 33)**

State Token stores only current keys, not previous-epoch keys retained during ZP_REKEY_GRACE. The 5-second grace period handles in-flight packets during active sessions, not hibernation recovery. Storing previous keys would add 64 bytes to every token for a rare edge case. Mitigation: avoid hibernation during rekey; if forced, re-establish connection.

**Stream Count Validation (Note in §6.5)**

Receivers must reject tokens with `stream_count > 12` or `stream_count == 0`. A valid session has at least one stream, and the maximum is capped at 12 for the State Token format.

### E.6 P2P and NAT Traversal

**P2P Role Determination via SDP (Note 30)**

In peer-to-peer scenarios, SDP Offer/Answer naturally determines roles: Offer initiator becomes Client (even stream IDs), Answer responder becomes Server (odd stream IDs). For glare (simultaneous offers), lexicographic comparison of handshake random values breaks tie.

**Glare Stream ID Handling (Note 34)**

Glare resolution occurs during signaling/handshake phase BEFORE data streams can be opened. Protocol sequence: (1) ICE/signaling with glare detection, (2) zp handshake with role assignment, (3) only then can data streams open. No streams exist before role assignment, so no parity conflicts can occur.

### E.7 Platform Considerations

**Android foregroundServiceType (Notes 24, 28, 31)**

The specification provides "dataSync" as a working example. Correct service type depends on app category, not protocol. Spec provides example; Android documentation is authoritative source. This has been consistently rejected as out-of-scope for the protocol specification.

**Device Key Lifecycle (Note 12)**

Device key rotation, migration, and recovery are implementation guide scope, not protocol specification. When device-bound keys are unavailable (reinstall, new device), re-authentication from scratch is the only option—there is no protocol-level recovery mechanism.

---

## Appendix F: Version History

This specification reached v1.0 after 25 release candidates and 7 rounds of external review.

**Development Summary:**
- RC1-RC18: Initial development, core protocol design
- RC19-RC25: External review hardening (86 findings addressed)
- v1.0: Final release with FIPS cipher suite and comprehensive test vectors

**Key Milestones:**
- RC19: First external review (3 blocking issues)
- RC21: First clean external review (0 blocking)
- RC23: QUIC stream ID collision fixed
- RC24: Flow control deadlock fixed
- RC25: Error code conflict resolved
- v1.0: Added ZP_CLASSICAL_2 (FIPS), test vectors, consolidated appendices

**Full Changelog:** See [CHANGELOG.md](./CHANGELOG.md) for complete RC-by-RC change history.

**Convergence Metrics:**

| Round | Blocking | Total Findings |
|-------|----------|----------------|
| RC18→RC19 | 3 | 13 |
| RC19→RC20 | 2 | 13 |
| RC20→RC21 | 0 | 5 |
| RC21→RC22 | 1 | 10 |
| RC22→RC23 | 2 | 12 |
| RC23→RC24 | 1 | 12 |
| RC24→RC25 | 1 | 8 |

---

*End of Specification*
