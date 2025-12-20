# zp Project Bootstrap Summary

**Date:** 2025-12-19
**Status:** Phase 1 Complete - Foundation Ready

---

## Completed Tasks

### Infrastructure
- [x] Created `docs/decisions/` and `docs/decisions/pending/` for Design Authority workflow
- [x] Created Cargo workspace with 5 crates
- [x] Set up approved dependencies per crypto-impl agent
- [x] Workspace builds successfully (`cargo check --workspace`)

### Crates Created

#### 1. zp-crypto (Cryptographic Primitives)
**Status:** Scaffolded
**Modules:**
- `kex/` - Key exchange (X25519, ML-KEM-768/1024, ECDH-P256)
- `aead/` - AEAD encryption (ChaCha20-Poly1305, AES-256-GCM)
- `kdf/` - HKDF-based key derivation
- `suite.rs` - Cipher suite definitions (4 suites per spec §4.1)
- `error.rs` - Error types

**Test vectors:** Stubs reference TEST_VECTORS.md §1-3
**Security:** All secrets use `Zeroizing<>`, constant-time comparisons via `subtle`

#### 2. zp-core (Protocol Engine)
**Status:** Scaffolded
**Modules:**
- `frame.rs` - 12 frame types per spec §3.3
- `session.rs` - Handshake state machine (Stranger/Friend/Family modes)
- `stream.rs` - Flow control and multiplexing per spec §3.3.9
- `error.rs` - Protocol errors matching spec Appendix B

**Features:** no_std compatible core

#### 3. zp-transport (Transport Layer)
**Status:** Scaffolded
**Modules:**
- `quic.rs` - QUIC over UDP (primary transport)
- `tcp.rs` - TCP with byte-level sync (fallback)
- `websocket.rs` - Browser fallback
- `webrtc.rs` - Browser P2P

**Features:** Automatic fallback chain per spec §3.1-3.6

#### 4. zp-platform (Platform Integration)
**Status:** Scaffolded
**Modules:**
- `ios.rs` - Secure Enclave, Network.framework
- `android.rs` - Hardware KeyStore, Foreground Services
- `browser.rs` - WebCrypto, IndexedDB (security-limited per spec §1.5)

#### 5. zp-ffi (Foreign Function Interface)
**Status:** Scaffolded
**Bindings:** UniFFI for C/Swift/Kotlin
**Note:** Awaiting zp.udl definition

### Test Structure

```
tests/
├── conformance/        # Spec compliance (TEST_VECTORS.md)
│   └── crypto_test.rs  # Crypto primitive tests (TODO)
├── integration/        # Cross-component tests
├── interop/            # Cross-platform compatibility
└── fuzz/               # Fuzzing harnesses
```

---

## Project Statistics

- **Total Rust files:** 33
- **Total crates:** 5
- **Cipher suites defined:** 4 (ZP_HYBRID_1/2/3, ZP_CLASSICAL_2)
- **Frame types defined:** 12
- **Error codes defined:** 10
- **Build status:** ✅ Clean (minor warnings expected for stubs)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  zp-ffi (C/Swift/Kotlin bindings via UniFFI)               │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  zp-platform (iOS/Android/Browser integrations)            │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  zp-transport (QUIC/TCP/WebSocket/WebRTC)                  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  zp-core (Protocol engine: frames, sessions, streams)      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  zp-crypto (X25519, ML-KEM, AEAD, KDF)                     │
└─────────────────────────────────────────────────────────────┘
```

---

## Next Steps (Recommended Order)

### Phase 2: Core Crypto Implementation
**Goal:** Working cryptographic primitives with test vectors

1. **Implement X25519 key exchange** (zp-crypto/src/kex/x25519.rs)
   - Use `x25519-dalek` or `ring`
   - Add RFC 7748 test vectors from TEST_VECTORS.md §1.1
   - Command: `/new-feature "X25519 key exchange"`

2. **Implement ML-KEM-768** (zp-crypto/src/kex/ml_kem.rs)
   - Use `ml-kem` crate
   - Add NIST test vectors from TEST_VECTORS.md §1.2
   - Verify key/ciphertext sizes

3. **Implement ChaCha20-Poly1305** (zp-crypto/src/aead.rs)
   - Use `chacha20poly1305` crate
   - Add RFC 8439 test vectors from TEST_VECTORS.md §2.1

4. **Implement HKDF-SHA256** (zp-crypto/src/kdf.rs)
   - Use `hkdf` crate
   - Implement session ID and traffic key derivation
   - Add test vectors from TEST_VECTORS.md §3

**Quality gate:** Run `/check` and `/coverage zp-crypto` before moving to Phase 3

### Phase 3: Protocol Engine
**Goal:** Frame parsing and session state machine

1. Implement frame serialization/deserialization (zp-core/src/frame.rs)
2. Implement handshake state machine (zp-core/src/session.rs)
3. Implement flow control (zp-core/src/stream.rs)
4. Add conformance tests for all frame types

**Quality gate:** All conformance tests pass

### Phase 4: Transport Layer
**Goal:** QUIC and TCP transports working

1. Implement QUIC transport using `quinn`
2. Implement TCP fallback with byte-level sync
3. Add integration tests for transport switching

### Phase 5: Platform Integration
**Goal:** Platform-specific features working

1. iOS Secure Enclave integration
2. Android KeyStore integration
3. Browser WASM bindings
4. Cross-platform interop tests

### Phase 6: Release Preparation
**Goal:** Production-ready v1.0

1. Run fuzzing for 1+ hours on all parsers (`/fuzz all 3600`)
2. Security self-audit (`/audit zp-crypto`, `/audit zp-core`)
3. Performance benchmarking (`/bench`)
4. Cross-platform interop validation
5. Update CHANGELOG.md
6. Create release (`/release major`)

---

## Available Workflow Commands

| Command | Purpose | Example |
|---------|---------|---------|
| `/spec [section]` | Look up spec section | `/spec 4.2.4` |
| `/vector [name]` | Look up test vector | `/vector x25519` |
| `/decision [id]` | Look up DA decision | `/decision DA-0001` |
| `/check` | Run full test suite | `/check` |
| `/bench [target]` | Run benchmarks | `/bench kex` |
| `/fuzz [target]` | Run fuzzer | `/fuzz frame_parser 3600` |
| `/audit [crate]` | Security self-audit | `/audit zp-crypto` |
| `/coverage [crate]` | Show test coverage | `/coverage zp-crypto` |
| `/escalate` | Create DA escalation | `/escalate` |
| `/new-feature [name]` | Guided feature workflow | `/new-feature "X25519"` |
| `/fix-bug [desc]` | Guided bugfix workflow | `/fix-bug "nonce collision"` |

---

## Agent Availability

Specialized agents will be automatically invoked when needed:

- **crypto-impl** - Crypto code review (auto-invoked for crypto code)
- **fuzz-gen** - Fuzzing harness generation (use `/fuzz`)
- **bench-runner** - Performance analysis (use `/bench`)
- **platform-ios** - iOS-specific implementation
- **platform-android** - Android-specific implementation
- **platform-browser** - Browser/WASM implementation

---

## Quality Standards Enforced

Per CLAUDE.md:

- ✅ Zero `unsafe` without `SAFETY:` comments
- ✅ All crypto uses approved crates
- ✅ No panics in library code (use `Result`)
- ✅ Secrets zeroed on drop (`zeroize`)
- ✅ No logging of key material
- ✅ Zero-copy where possible (`bytes` crate)
- ✅ Async I/O (`tokio`)
- ⏳ Zero clippy warnings (currently 2 minor warnings for stub code)
- ⏳ All tests pass (tests are stubs)
- ⏳ Conformance tests cover new code paths (to be implemented)

---

## Bootstrap Complete ✅

The zp project foundation is ready for implementation. Start with Phase 2 (Core Crypto) using the `/new-feature` command for guided development.

**Next action:** `/new-feature "X25519 key exchange"`
