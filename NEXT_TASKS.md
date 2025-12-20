# Immediate Next Tasks

This document outlines the next micro-tasks to continue zp development after bootstrap.

---

## Phase 2: Core Cryptography Implementation

### Task 2.1: X25519 Key Exchange ✅ COMPLETED
**Priority:** P0 (foundation for all cipher suites)
**File:** `crates/zp-crypto/src/kex/x25519.rs`
**Status:** ✅ Complete

**Acceptance criteria:**
- [x] `X25519KeyPair::generate()` creates valid keypair
- [x] `exchange()` produces correct shared secret
- [x] RFC 7748 test vectors pass (TEST_VECTORS.md §1.1)
- [x] All secrets use `Zeroizing<>` wrapper
- [x] No clippy warnings
- [x] Agent: crypto-impl reviews implementation (APPROVED)

**Actual LOC:** ~80 lines + tests

---

### Task 2.2: ML-KEM-768 Implementation ✅ COMPLETED
**Priority:** P0 (required for ZP_HYBRID_1, default cipher suite)
**File:** `crates/zp-crypto/src/kex/ml_kem.rs`
**Status:** ✅ Complete

**Acceptance criteria:**
- [x] `MlKem768KeyPair::generate()` creates 1184-byte public key
- [x] `encapsulate()` produces 1088-byte ciphertext + 32-byte secret
- [x] `decapsulate()` recovers matching secret
- [x] Size verification test passes (TEST_VECTORS.md §1.2)
- [x] Secrets zeroed on drop
- [x] Agent: crypto-impl reviews implementation (APPROVED)

**Actual LOC:** ~232 lines + tests

---

### Task 2.3: ChaCha20-Poly1305 AEAD ✅ COMPLETED
**Priority:** P0 (required for ZP_HYBRID_1/2)
**File:** `crates/zp-crypto/src/aead.rs`
**Status:** ✅ Complete

**Acceptance criteria:**
- [x] `chacha20poly1305_encrypt()` works with 32-byte key, 12-byte nonce
- [x] `decrypt()` verifies authentication tag
- [x] RFC 8439 test vectors pass (TEST_VECTORS.md §4.1)
- [x] No key material in error messages
- [x] Constant-time operations where required
- [x] Agent: crypto-impl reviews implementation (APPROVED WITH NOTES)

**Actual LOC:** ~84 lines + 170 lines of tests

---

### Task 2.4: HKDF-SHA256 Key Derivation ✅ COMPLETED
**Priority:** P0 (required for all handshakes)
**File:** `crates/zp-crypto/src/kdf.rs`
**Status:** ✅ Complete

**Acceptance criteria:**
- [x] `hkdf_sha256()` implements RFC 5869
- [x] `derive_session_secret_stranger()` / `derive_session_keys_stranger()` matches spec §4.2.4
- [x] `derive_session_secret_known()` / `derive_session_keys_known()` matches spec §4.3.4
- [x] `derive_traffic_key()` / `update_current_secret()` for key rotation per spec §4.6.3
- [x] RFC 5869 test vectors pass (TEST_VECTORS.md §2.1)
- [x] zp-specific test vectors pass (TEST_VECTORS.md §2.2-2.5)
- [x] All derived keys use `Zeroizing<>`
- [x] Agent: crypto-impl reviews implementation (APPROVED)

**Actual LOC:** ~268 lines + tests

---

### Task 2.5: Crypto Conformance Test Suite ✅ COMPLETED
**Priority:** P0 (quality gate)
**File:** `tests/conformance/crypto_test.rs`
**Status:** ✅ Complete

**Acceptance criteria:**
- [x] All test vectors from TEST_VECTORS.md §1-4 implemented
- [x] X25519, ML-KEM-768, ChaCha20-Poly1305, HKDF all tested
- [x] Property tests for invariants (e.g., encapsulate/decapsulate roundtrip)
- [x] `cargo test --test crypto` passes (18/20, 2 ignored for unimplemented)
- [x] Coverage >80% for zp-crypto (84.1% achieved)

**Actual LOC:** ~440 lines of tests (18 conformance + 7 property tests)

---

### Task 2.6: AES-256-GCM AEAD ✅ COMPLETED
**Priority:** P1 (required for ZP_HYBRID_3 and ZP_CLASSICAL_2)
**File:** `crates/zp-crypto/src/aead.rs`
**Status:** ✅ Complete

**Acceptance criteria:**
- [x] `aes256gcm_encrypt()` works with 32-byte key, 12-byte nonce
- [x] `decrypt()` verifies authentication tag
- [x] NIST test vectors pass (TEST_VECTORS.md §4.2)
- [x] No key material in error messages
- [x] Constant-time operations where required
- [x] Agent: crypto-impl reviews implementation (APPROVED)

**Actual LOC:** ~96 lines (implementation) + 92 lines (unit tests)

**Cipher Suite Impact:** Enables ZpHybrid3 (1 of 4 suites), partially enables ZpClassical2

---

### Task 2.7: ECDH-P256 Key Exchange ✅ COMPLETED
**Priority:** P1 (required for ZP_CLASSICAL_2 FIPS compliance)
**File:** `crates/zp-crypto/src/kex/ecdh_p256.rs`
**Status:** ✅ Complete

**Acceptance criteria:**
- [x] `EcdhP256KeyPair::generate()` creates valid keypair
- [x] `exchange()` produces correct shared secret (32 bytes)
- [x] RFC 5903 test vectors pass (TEST_VECTORS.md §1.4)
- [x] All secrets use `Zeroizing<>` wrapper
- [x] Use FIPS-approved implementation (RustCrypto p256 v0.11.1, NIST SP 800-56A compliant)
- [x] No clippy warnings
- [x] Agent: crypto-impl reviews implementation (APPROVED)

**Actual LOC:** ~204 lines + tests (8 unit tests + 1 RFC 5903 conformance test)

**Cipher Suite Impact:** Enables ZpClassical2 (FIPS mode)

---

### Task 2.8: ML-KEM-1024 Implementation ✅ COMPLETED
**Priority:** P2 (higher security parameter)
**File:** `crates/zp-crypto/src/kex/ml_kem.rs`
**Status:** ✅ Complete

**Acceptance criteria:**
- [x] `MlKem1024KeyPair::generate()` creates valid keypair
- [x] `encapsulate()` produces correct ciphertext/secret (1568 bytes / 32 bytes)
- [x] `decapsulate()` recovers matching secret
- [x] Size verification test passes (TEST_VECTORS.md §1.3)
- [x] Secrets zeroed on drop
- [x] Agent: crypto-impl reviews implementation (APPROVED)

**Actual LOC:** ~194 lines (implementation) + ~129 lines (8 unit tests + 1 conformance test)

**Cipher Suite Impact:** Enables ZpHybrid2 (high security mode with NIST Level 5)

---

## Workflow Recommendations

### Before Starting Each Task
1. Read the spec section referenced in the task
2. Check TEST_VECTORS.md for test cases
3. Run `/spec [section]` to look up details
4. Run `/vector [name]` to get test vectors

### During Implementation
1. Use crypto-impl agent for review (`/audit zp-crypto`)
2. Write tests alongside implementation (TDD)
3. Run `cargo clippy` frequently
4. Use `Zeroizing<>` for all secrets

### After Completing Each Task
1. Run `/check` to verify all tests pass
2. Run `/coverage zp-crypto` to check coverage
3. Run crypto-impl agent for security review
4. Update CHANGELOG.md if user-visible

### If You Encounter Ambiguity
1. Search existing DA decisions: `/decision [keyword]`
2. Check spec carefully with `/spec [section]`
3. If still unclear, escalate: `/escalate`

---

## Parallel Work Opportunities

While working on crypto primitives, you can parallelize:

### Secondary Tasks (Can run concurrently)
- **Frame parsing:** Implement basic frame serialization in zp-core
- **Error handling:** Flesh out error types and conversions
- **Documentation:** Add rustdoc examples
- **Benches:** Set up criterion benchmarks for crypto operations

### Use Task Tool for Parallelization
```bash
# Example: Launch crypto implementation while benchmarking existing code
# (Though most crypto is TODO, this shows the pattern)
```

---

## Quality Gates

Before moving to Phase 3 (Protocol Engine):

### Minimum Requirements (Core Functionality)
- [x] Tasks 2.1-2.5 completed (X25519, ML-KEM-768, ChaCha20, HKDF, Tests)
- [x] `/check` passes with zero failures
- [x] `/coverage zp-crypto` shows >80% coverage (84.1% achieved)
- [x] crypto-impl agent approval (`/audit zp-crypto`)
- [x] Zero clippy warnings in zp-crypto
- [x] All conformance tests pass

**Status:** ✅ ZpHybrid1 (default cipher suite) fully functional

### Full Cipher Suite Support (Recommended)
- [x] Task 2.6 completed (AES-256-GCM)
- [x] Task 2.7 completed (ECDH-P256)
- [x] Task 2.8 completed (ML-KEM-1024)
- [x] 4 of 4 cipher suites fully supported ✅
- [x] Conformance tests updated for AES-256-GCM
- [x] Conformance tests updated for ECDH-P256
- [x] Conformance tests updated for ML-KEM-1024

**Current Cipher Suite Support:**
- ✅ **ZpHybrid1** (X25519 + ML-KEM-768 + ChaCha20-Poly1305) - DEFAULT, COMPLETE
- ✅ **ZpHybrid2** (X25519 + ML-KEM-1024 + ChaCha20-Poly1305) - High security, COMPLETE
- ✅ **ZpHybrid3** (X25519 + ML-KEM-768 + AES-256-GCM) - COMPLETE
- ✅ **ZpClassical2** (ECDH-P256 + AES-256-GCM) - FIPS mode, COMPLETE

---

## Progress Summary

**Completed (Tasks 2.1-2.8):**
- X25519 key exchange: ~80 lines
- ML-KEM-768 KEM: ~232 lines
- ML-KEM-1024 KEM: ~194 lines
- ChaCha20-Poly1305 AEAD: ~84 lines
- HKDF-SHA256: ~268 lines
- AES-256-GCM AEAD: ~96 lines
- ECDH-P256 key exchange: ~204 lines
- Conformance tests: ~440 lines (ChaCha20, HKDF) + ~60 lines (AES-256-GCM) + ~47 lines (ECDH-P256) + ~40 lines (ML-KEM-1024)
- Unit tests: ~254 lines (ChaCha20) + 92 lines (AES-256-GCM) + ~100 lines (ECDH-P256) + ~129 lines (ML-KEM-1024)
- **Total:** ~2,280 lines of crypto implementation + tests

**Phase 2 Status:** ✅ COMPLETE - ALL 4 cipher suites fully implemented 🎉

---

## Next Step

**Phase 2 (Core Cryptography) is COMPLETE! 🎉**

**Achievements:**
- ✅ **ALL 4 cipher suites fully implemented** (ZpHybrid1, ZpHybrid2, ZpHybrid3, ZpClassical2)
- ✅ All cryptographic primitives implemented and tested
- ✅ 84.1%+ test coverage in zp-crypto
- ✅ Zero clippy warnings
- ✅ All crypto-impl security audits passed (APPROVED)
- ✅ Full RFC and NIST test vector conformance
- ✅ Zero unsafe code (`#![forbid(unsafe_code)]`)
- ✅ Complete zeroization of all secrets

**Cipher Suite Coverage:**
- **ZpHybrid1** (0x01): X25519 + ML-KEM-768 + ChaCha20-Poly1305 - DEFAULT ✅
- **ZpHybrid2** (0x02): X25519 + ML-KEM-1024 + ChaCha20-Poly1305 - HIGH SECURITY ✅
- **ZpHybrid3** (0x03): X25519 + ML-KEM-768 + AES-256-GCM ✅
- **ZpClassical2** (0x11): ECDH-P256 + AES-256-GCM - FIPS MODE ✅

**Ready for Phase 3: Protocol Engine**

Recommended next tasks:
1. Frame serialization/deserialization (spec §3.3)
2. Handshake state machine (spec §4.2-4.3)
3. Session management
4. Stream multiplexing

Create `PHASE_3.md` or continue to Protocol Engine implementation.

---

## Phase 3: Protocol Engine Implementation

### Task 3.1: Frame Serialization/Deserialization ✅ COMPLETED
**Priority:** P0 (foundation for all protocol operations)
**File:** `crates/zp-core/src/frame.rs`
**Status:** ✅ Complete
**Spec Reference:** §3.3

**Acceptance criteria:**
- [x] All 16 frame types implemented per spec
- [x] Handshake frames: ClientHello, ServerHello, ClientFinish (Stranger Mode §4.2)
- [x] Handshake frames: KnownHello, KnownResponse, KnownFinish (Known Mode §4.3)
- [x] Control frames: Sync-Frame, Sync-Ack (§3.3.5-6)
- [x] Control frames: KeyUpdate, KeyUpdateAck (§4.6)
- [x] Control frames: AckFrame, WindowUpdate, ErrorFrame (§3.3.9-12)
- [x] Data frames: DataFrame, EncryptedRecord, StreamChunk
- [x] Little-endian byte order for all multi-byte integers
- [x] Magic number constants for all frame types
- [x] XXH64 integrity hashing for Sync-Frame (§3.3.5)
- [x] Frame::parse() and Frame::serialize() bidirectional conversion
- [x] All frame roundtrip tests pass
- [x] Conformance tests for all frame formats (18 tests)

**Actual LOC:** ~1127 lines implementation + ~580 lines conformance tests

**Test Coverage:**
- Frame conformance tests: 18/18 passing
- Frame unit tests: 6/6 passing
- Total: 24 frame-related tests

---

### Task 3.2: Handshake State Machine ✅ COMPLETED
**Priority:** P0 (required for session establishment)
**File:** `crates/zp-core/src/session.rs`
**Status:** ✅ Complete (Stranger Mode only)
**Spec Reference:** §4.2 (Stranger Mode), §4.3 (Known Mode - TODO)

**Acceptance criteria:**
- [x] Session struct with Role (Client/Server) and HandshakeMode (Stranger/Known)
- [x] Stranger Mode client handshake flow (§4.2)
  - [x] client_start_stranger() - Generate ClientHello
  - [x] client_process_server_hello() - Process ServerHello, derive keys
  - [x] client_build_finish() - Generate ClientFinish with ML-KEM ciphertext
- [x] Stranger Mode server handshake flow (§4.2)
  - [x] server_process_client_hello() - Validate client proposal
  - [x] server_build_hello() - Generate ServerHello with ML-KEM public key
  - [x] server_process_client_finish() - Decapsulate, derive session keys
- [x] Cipher suite negotiation (§4.2.1)
  - [x] Support all 4 cipher suites (ZP_HYBRID_1/2/3, ZP_CLASSICAL_2)
  - [x] Downgrade attack prevention
- [x] Version negotiation (§2.2)
- [x] Session key derivation (§4.2.4)
  - [x] Session ID = SHA-256(client_random || server_random || shared_secret)[0:16]
  - [x] Session secret and traffic keys via HKDF-SHA256
  - [x] All secrets wrapped in Zeroizing<>
- [x] State transitions enforced (Idle → ClientHelloSent → ClientFinishReady → Established)
- [x] Error handling for invalid state transitions
- [x] Unit tests for handshake flow (4 tests)

**Actual LOC:** ~765 lines implementation + tests

**Known Limitations:**
- Known Mode (SPAKE2+) not yet implemented (§4.3)
- Key rotation not yet implemented (§4.6)
- Only Stranger Mode fully functional

**Test Coverage:**
- Session unit tests: 4/4 passing (creation, handshake flow, version/cipher negotiation)
- **Coverage gap:** ~15% (Only Stranger Mode tested, no conformance tests for key derivation)

---

### Task 3.3: Flow Control and Stream Multiplexing ✅ COMPLETED
**Priority:** P0 (required for data transfer)
**File:** `crates/zp-core/src/stream.rs`
**Status:** ✅ Complete
**Spec Reference:** §3.3.9 (Flow Control), §3.3.11 (Stream Lifecycle)

**Acceptance criteria:**
- [x] Stream struct with dual-level flow control
  - [x] Stream-level window (ZP_INITIAL_STREAM_WINDOW = 256KB)
  - [x] Connection-level window (ZP_INITIAL_CONN_WINDOW = 1MB)
- [x] StreamMultiplexer for connection-level management
- [x] Flow control operations
  - [x] queue_send() - Respect send window constraints
  - [x] receive_data() - Respect receive window constraints
  - [x] generate_window_update() - Trigger at consumed >= initial_window / 2
  - [x] update_send_window() / update_recv_window() - Saturating addition
- [x] Stream lifecycle (§3.3.11)
  - [x] States: Open, HalfClosedLocal, HalfClosedRemote, Closed
  - [x] FIN flag handling for graceful close
  - [x] State transition enforcement
- [x] Stream ID allocation
  - [x] Even IDs for client-initiated streams
  - [x] Odd IDs for server-initiated streams
- [x] Priority scheduling (§3.3.8)
  - [x] Priority clamping (0 → 1, max 255)
- [x] WindowUpdate generation per spec §3.3.9
- [x] Dual-level window enforcement: min(stream_window, conn_window)
- [x] Unit tests for flow control (10 tests)

**Actual LOC:** ~583 lines implementation + tests

**Test Coverage:**
- Stream unit tests: 10/10 passing
- **Coverage gap:** ~22% (Missing edge case tests, no property tests for invariants)

---

### Task 3.4: Frame Conformance Test Suite ✅ COMPLETED
**Priority:** P0 (quality gate)
**File:** `tests/conformance/frame_conformance.rs`
**Status:** ✅ Complete

**Acceptance criteria:**
- [x] Conformance tests for all 16 frame types
- [x] Verify exact wire format per spec §3.3
- [x] Test magic numbers (4-byte ASCII mnemonics)
- [x] Test frame type identifiers (1-byte)
- [x] Test little-endian byte order
- [x] Test XXH64 integrity hashing (Sync-Frame)
- [x] Test all error codes roundtrip (Appendix B)
- [x] Test FIN flag handling (DataFrame)
- [x] All frame roundtrip tests (serialize → parse → equals)
- [x] All tests pass (18/18)

**Actual LOC:** ~580 lines conformance tests

**Frame Types Covered:**
1. ✅ ClientHello (Stranger Mode §4.2.1)
2. ✅ ServerHello (Stranger Mode §4.2.2)
3. ✅ ClientFinish (Stranger Mode §4.2.3)
4. ✅ KnownHello (Known Mode §4.3.1)
5. ✅ KnownResponse (Known Mode §4.3.2)
6. ✅ KnownFinish (Known Mode §4.3.3)
7. ✅ Sync-Frame (Migration §3.3.5)
8. ✅ Sync-Ack (Migration §3.3.6)
9. ✅ KeyUpdate (Key Rotation §4.6.2)
10. ✅ KeyUpdateAck (Key Rotation §4.6.5)
11. ✅ AckFrame (Reliability §6.4.4)
12. ✅ WindowUpdate (Flow Control §3.3.9)
13. ✅ ErrorFrame (Protocol Error §3.3.12)
14. ✅ DataFrame (Application Data §3.3.10)
15. ✅ EncryptedRecord (Encryption Wrapper §3.3.13)
16. ✅ StreamChunk (TCP Fallback §3.3.7)

---

## Phase 3 Status

**Completed Tasks:** 4/4 ✅

**Total Implementation:**
- frame.rs: ~1127 lines
- session.rs: ~765 lines
- stream.rs: ~583 lines
- Conformance tests: ~580 lines
- **Total:** ~3055 lines

**Test Summary:**
- Unit tests: 21 passing (6 frame + 4 session + 10 stream + 1 error)
- Conformance tests: 18 passing (all frame types)
- **Total:** 39 passing tests

**Quality Metrics:**
- ✅ Zero clippy warnings
- ✅ Zero unsafe code blocks (`#![forbid(unsafe_code)]`)
- ✅ All secrets properly zeroized
- ✅ No logging of sensitive data
- ⚠️ Test coverage: ~35-40% (needs improvement to 80%+ target)

---

## Critical Gaps Identified (Security Audit)

### High Priority (Before Production)
1. **Increase test coverage to >80%**
   - Current: ~35-40%
   - session.rs: ~15% coverage
   - stream.rs: ~22% coverage
   - frame.rs: ~44% coverage

2. **Add session conformance tests**
   - Missing: TEST_VECTORS.md §3.1 (Session ID derivation)
   - Missing: Full handshake flow tests with test vectors
   - Missing: Known Mode handshake tests

3. **Add fuzzing harnesses**
   - Frame parsing (malformed inputs, edge cases)
   - Session state machine (invalid transitions)
   - Flow control (window overflow, underflow)

4. **Implement or remove dead code**
   - `parse_encrypted_record()` - Marked as #[allow(dead_code)]
   - `parse_stream_chunk()` - Marked as #[allow(dead_code)]
   - Decision needed: Future work or remove?

### Medium Priority
5. Add property tests for flow control invariants
6. Add integration tests for full handshake flows
7. Add error recovery tests (malformed frames, network errors)

---

## Next Steps

**Option A: Complete Phase 3 Quality Gate**
Recommended before moving to Phase 4 (Transport Layer):
1. Run `/fuzz frame` to add fuzzing harnesses
2. Add session conformance tests from TEST_VECTORS.md
3. Increase test coverage to 80%+
4. Run `/review-code zp-core` for comprehensive review

**Option B: Continue to Phase 4 (Transport Layer)**
Accept current quality level and continue to:
1. QUIC transport integration (§3.4)
2. WebSocket transport (Appendix D)
3. WebRTC DataChannel transport (§5)
4. TCP fallback (§3.3.7)

**Option C: Implement Missing Features**
1. Known Mode handshake (SPAKE2+, §4.3)
2. Key rotation protocol (§4.6)
3. Transport migration (Sync-Frame integration, §3.3.3)
4. State Token persistence (§6.5)

**Recommended:** Option A (Quality Gate) before production, Option B acceptable for continued development.

