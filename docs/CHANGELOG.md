# zp Protocol Changelog

**Document:** Version History
**Covers:** RC1 through v1.0
**Related:** [zp Specification v1.0](./zp_specification_v1.0.md) | [Test Vectors](./TEST_VECTORS.md)

---

## Implementation Changelog

### Unreleased

**Added:**
- X25519 key exchange implementation (zp-crypto)
  - RFC 7748 §6.1 conformance with test vectors
  - Secure key generation using CSPRNG
  - Zeroizing wrappers for all secrets
  - Low-order point rejection
  - Comprehensive test coverage (5 tests, all passing)

- ML-KEM-768 key encapsulation mechanism (zp-crypto)
  - FIPS 203 conformance using RustCrypto ml-kem v0.2.1
  - Post-quantum security (NIST security level 3, equivalent to AES-192)
  - Secure key storage with Zeroizing wrappers for 2400-byte private keys
  - Public key: 1184 bytes, Ciphertext: 1088 bytes, Shared secret: 32 bytes
  - Encapsulate/decapsulate API for hybrid key exchange with X25519
  - `#![forbid(unsafe_code)]` - zero unsafe blocks
  - Comprehensive test coverage (8 tests passing)
  - Crypto-impl security audit: APPROVED

- ML-KEM-1024 key encapsulation mechanism (zp-crypto)
  - FIPS 203 conformance using RustCrypto ml-kem v0.2.1
  - Post-quantum security (NIST security level 5, equivalent to AES-256)
  - Secure key storage with Zeroizing wrappers for 3168-byte private keys
  - Public key: 1568 bytes, Ciphertext: 1568 bytes, Shared secret: 32 bytes
  - Encapsulate/decapsulate API matching ML-KEM-768 pattern
  - Used in ZP_HYBRID_2 cipher suite (X25519 + ML-KEM-1024 + ChaCha20-Poly1305)
  - `#![forbid(unsafe_code)]` - zero unsafe blocks
  - Comprehensive test coverage (8 unit tests + 1 conformance test, all passing)
  - Crypto-impl security audit: APPROVED

- HKDF-SHA256 key derivation functions (zp-crypto)
  - RFC 5869 conformance using RustCrypto hkdf v0.12.4 + sha2 v0.10.9
  - Generic `hkdf_sha256()` for flexible key derivation
  - Stranger Mode derivations (§4.2.4): `derive_session_secret_stranger()`, `derive_session_keys_stranger()`
  - Known Mode derivations (§4.3.4): `derive_session_secret_known()`, `derive_session_keys_known()`
  - Key rotation support (§4.6.3): `derive_traffic_key()`, `update_current_secret()`
  - All outputs wrapped in `Zeroizing<>` for automatic secret cleanup
  - Little-endian encoding for key_epoch per spec
  - Zero unsafe blocks, pure safe Rust
  - Test coverage: RFC 5869 vectors + 6 zp-specific tests
  - Crypto-impl security audit: APPROVED

- ChaCha20-Poly1305 AEAD (zp-crypto)
  - RFC 8439 conformance using RustCrypto chacha20poly1305 v0.10.1
  - Used in ZP_PQC_1 and ZP_CLASSICAL_1 cipher suites
  - Nonce construction per spec §6.5.1: `nonce[0:4]=0x00000000 || nonce[4:12]=counter (LE)`
  - `chacha20poly1305_encrypt()` - Encrypt with AAD, returns ciphertext || tag
  - `chacha20poly1305_decrypt()` - Decrypt and verify tag, returns `Zeroizing<Vec<u8>>`
  - `construct_nonce()` - Build 12-byte AEAD nonce from 64-bit counter
  - Proper error handling: `Error::Encryption` vs `Error::Decryption`
  - Decrypted plaintext wrapped in `Zeroizing<>` for automatic secret cleanup
  - Test coverage: RFC 8439 §2.8.2 test vector + 9 additional tests (roundtrip, failure modes, edge cases)
  - `#![forbid(unsafe_code)]` - zero unsafe blocks
  - Crypto-impl security audit: APPROVED WITH NOTES

- AES-256-GCM AEAD (zp-crypto)
  - NIST SP 800-38D conformance using RustCrypto aes-gcm v0.10.3
  - Used in ZP_HYBRID_3 and ZP_CLASSICAL_2 cipher suites
  - `aes256gcm_encrypt()` - Encrypt with 32-byte key, 12-byte nonce, AAD support
  - `aes256gcm_decrypt()` - Decrypt and verify 16-byte authentication tag
  - Returns `Zeroizing<Vec<u8>>` for automatic plaintext cleanup
  - Constant-time tag verification via library implementation
  - No key material in error messages
  - Test coverage: NIST SP 800-38D test vector + 6 unit tests (roundtrip, wrong key/nonce/AAD, corruption, empty plaintext)
  - `#![forbid(unsafe_code)]` - zero unsafe blocks
  - Crypto-impl security audit: APPROVED

- ECDH-P256 key exchange (zp-crypto)
  - RFC 5903 §8.1 conformance using RustCrypto p256 v0.11.1
  - NIST SP 800-56A compliant for FIPS 140-3 environments
  - Used exclusively in ZP_CLASSICAL_2 cipher suite for regulatory compliance
  - P-256 (secp256r1) elliptic curve Diffie-Hellman
  - `EcdhP256KeyPair::generate()` - Generate random keypair
  - `EcdhP256KeyPair::from_private()` - Deterministic keypair from 32-byte private key
  - `exchange()` - Perform ECDH, returns `Zeroizing<[u8; 32]>` shared secret
  - Public keys in uncompressed SEC 1 format (65 bytes: 0x04 || x || y)
  - Automatic zeroization: SecretKey implements ZeroizeOnDrop
  - Public key validation per NIST requirements
  - Test coverage: RFC 5903 test vector + 8 unit tests (commutativity, determinism, roundtrip, validation, uniqueness)
  - `#![forbid(unsafe_code)]` - zero unsafe blocks
  - Crypto-impl security audit: APPROVED

- Frame serialization/deserialization (zp-core)
  - All 16 frame types per spec §3.3 (Handshake, Control, Data frames)
  - Handshake frames: ClientHello, ServerHello, ClientFinish (Stranger Mode §4.2)
  - Handshake frames: KnownHello, KnownResponse, KnownFinish (Known Mode §4.3)
  - Control frames: Sync-Frame, Sync-Ack (Migration §3.3.5-6)
  - Control frames: KeyUpdate, KeyUpdateAck (Key Rotation §4.6)
  - Control frames: AckFrame, WindowUpdate, ErrorFrame (§3.3.9-12)
  - Data frames: DataFrame, EncryptedRecord, StreamChunk (§3.3.10, §3.3.13, §3.3.7)
  - Little-endian byte order for all multi-byte integers
  - Magic number constants (4-byte ASCII mnemonics: "ZPCH", "ZPSH", etc.)
  - XXH64 integrity hashing for Sync-Frame state synchronization
  - Bidirectional Frame::parse() and Frame::serialize() with roundtrip guarantees
  - Comprehensive conformance tests (18 frame format tests, all passing)
  - ~1127 lines implementation + ~580 lines conformance tests

- Session management and handshake state machine (zp-core)
  - Stranger Mode handshake implementation (§4.2 - TOFU security model)
  - Client-side: client_start_stranger(), client_process_server_hello(), client_build_finish()
  - Server-side: server_process_client_hello(), server_build_hello(), server_process_client_finish()
  - Cipher suite negotiation with downgrade attack prevention
  - Support for all 4 cipher suites (ZP_HYBRID_1/2/3, ZP_CLASSICAL_2)
  - Version negotiation (§2.2)
  - Session key derivation (§4.2.4)
    - Session ID = SHA-256(client_random || server_random || shared_secret)[0:16]
    - Session secret and traffic keys via HKDF-SHA256
    - Role-based key assignment (client/server send/recv keys)
  - Hybrid key exchange: X25519 + ML-KEM-768/1024
  - All secrets wrapped in Zeroizing<> for automatic cleanup
  - State machine enforcement (Idle → ClientHelloSent → ClientFinishReady → Established)
  - Error handling for invalid state transitions
  - ~765 lines implementation
  - Unit tests: 4 passing (session creation, handshake flow, version/cipher negotiation)
  - Known limitation: Known Mode (SPAKE2+) not yet implemented

- Flow control and stream multiplexing (zp-core)
  - Dual-level flow control per spec §3.3.9
    - Stream-level window (ZP_INITIAL_STREAM_WINDOW = 256KB)
    - Connection-level window (ZP_INITIAL_CONN_WINDOW = 1MB)
  - StreamMultiplexer for connection-level management
  - Window operations: queue_send(), receive_data(), generate_window_update()
  - WindowUpdate trigger: consumed >= initial_window / 2
  - Saturating addition for window updates (prevent overflow)
  - Stream lifecycle management (§3.3.11)
    - States: Open, HalfClosedLocal, HalfClosedRemote, Closed
    - FIN flag handling for graceful close
    - State transition enforcement
  - Stream ID allocation
    - Even IDs (0, 2, 4...) for client-initiated streams
    - Odd IDs (1, 3, 5...) for server-initiated streams
  - Priority scheduling (§3.3.8)
    - Priority range: 1-255 (0 clamped to 1)
  - Dual-level window enforcement: min(stream_window, conn_window)
  - ~583 lines implementation
  - Unit tests: 10 passing (creation, flow control, window updates, lifecycle, multiplexing)

**Phase 3 Quality Metrics:**
- Total implementation: ~3055 lines (frame.rs: 1127 + session.rs: 765 + stream.rs: 583 + tests: 580)
- Unit tests: 21 passing (6 frame + 4 session + 10 stream + 1 error)
- Conformance tests: 18 passing (all frame types)
- Total: 39 tests passing
- Zero clippy warnings
- Zero unsafe code blocks (`#![forbid(unsafe_code)]`)
- All secrets properly zeroized
- No logging of sensitive data
- Test coverage: ~35-40% (needs improvement to 80%+ for production)

**Phase 3 Known Gaps:**
- Known Mode (SPAKE2+) handshake not implemented (§4.3)
- Key rotation protocol not implemented (§4.6)
- Transport migration not yet integrated (§3.3.3)
- Session conformance tests missing (TEST_VECTORS.md §3.1)
- Low test coverage on session.rs (~15%) and stream.rs (~22%)
- No fuzzing harnesses for frame parsing
- No property tests for flow control invariants

**Cipher Suite Status:**
- ✅ **ZpHybrid1** (X25519 + ML-KEM-768 + ChaCha20-Poly1305) - DEFAULT, fully implemented
- ✅ **ZpHybrid2** (X25519 + ML-KEM-1024 + ChaCha20-Poly1305) - High security, fully implemented
- ✅ **ZpHybrid3** (X25519 + ML-KEM-768 + AES-256-GCM) - Fully implemented
- ✅ **ZpClassical2** (ECDH-P256 + AES-256-GCM) - FIPS mode, fully implemented

---

## Specification Changelog

### v1.0 (December 2025)

Final release. Promoted from RC25 after 7 rounds of external review.

**Changes from RC25:**
- Added ZP_CLASSICAL_2 cipher suite (ECDH-P256 + AES-256-GCM) for FIPS environments
- Added comprehensive test vectors (see TEST_VECTORS.md)
- Consolidated appendices E-AB into single Design Rationale appendix
- Fixed ERR_HANDSHAKE_TIMEOUT error code reference (was 0x10, corrected to 0x01)

---

## RC25 (December 2025)

External Review Round 7. 1 blocking issue resolved.

| ID | Severity | Finding | Resolution |
|----|----------|---------|------------|
| E7-1 | Blocking | ERR_PROTOCOL_VIOLATION (0x01) conflicts with ERR_HANDSHAKE_TIMEOUT | Added ERR_PROTOCOL_VIOLATION as 0x0E in Appendix B |
| E7-2 | Medium | WebSocket framing ambiguous post-handshake | Clarified EncryptedRecord usage in Appendix D |
| E7-3 | Medium | WindowUpdate initial value semantics unclear | Clarified "receive window capacity" in §3.4 |
| E7-4 | Medium | StreamChunk length field scope ambiguous | Added "payload only, not header" in §3.3.7 |
| E7-5 | Low | MISMATCH buffer purge missing | Added discard requirement in §3.3.6 |
| E7-6 | Low | Nonce zero prefix lacks justification | Added cryptographic context note in §6.5.1 |
| E7-7 | Low | ErrorFrame magic future-proofing | Added ZP_MAX_RECORD_SIZE constraint in §3.3.13 |
| E7-8 | Low | ErrorFrame/close ordering implicit | Added implementation-defined note in §3.3.12 |

---

## RC24 (December 2025)

External Review Round 6. 1 blocking issue resolved.

| ID | Severity | Finding | Resolution |
|----|----------|---------|------------|
| E6-1 | Blocking | Flow control deadlock for control frames | Added control frame exemption in §3.3.9 |
| E6-2 | Medium | P2P role ambiguity | Added SDP Offer/Answer tie-breaker in §5.1 |
| E6-3 | Medium | Priority zero contradictions | Simplified to "clamp to 1" in §3.3.8 |
| E6-4 | Medium | QUIC control stream init unclear | Specified WindowUpdate with own receive window in §3.4 |
| E6-5 | Medium | StreamChunk detection missing | Added 0xFFFFFFFF sentinel in §3.3.7 |
| E6-6 | Medium | Nonce derivation wording | Clarified "first 12 bytes" in §4.3.4 |
| E6-7 | Medium | AckFrame byte offsets missing | Added explicit offsets in §6.4.4 |
| E6-8 | Low | Control stream enforcement undefined | Added ERR_PROTOCOL_VIOLATION in §3.4 |
| E6-9 | Low | global_seq monotonicity implicit | Added explicit MUST in §3.3.10 |
| E6-10 | Low | Info string UTF-8 confusion | Clarified ASCII encoding in §4.6.3 |
| E6-11 | Low | Stream count validation missing | Added rejection rules in §6.5 |
| E6-12 | Low | IPv6 /64 may be too coarse | Added granularity note in §8.1 |

---

## RC23 (December 2025)

External Review Round 5. 2 blocking issues resolved.

| ID | Severity | Finding | Resolution |
|----|----------|---------|------------|
| E5-1 | Blocking | QUIC stream ID collision (QUIC 4 and 5 both → zp 1) | Changed to direct mapping: zp_stream_id = QUIC_stream_id |
| E5-2 | Blocking | Maximum record size undefined (disambiguation broken) | Added ZP_MAX_RECORD_SIZE = 16MB |
| E5-3 | Medium | QUIC control stream framing undefined | Added magic-prefixed framing note |
| E5-4 | Medium | QUIC control stream initialization deadlock | Added client MUST open stream 0 immediately |
| E5-5 | Medium | Handshake timeout undefined | Added ZP_HANDSHAKE_TIMEOUT/RETRIES |
| E5-6 | Medium | StreamChunk integration unclear | Clarified relationship to DataFrame |
| E5-7 | Medium | ZP_TOKEN_OVERFLOW=REJECT impossible on OS-forced background | Added fallback to LRU behavior |
| E5-8 | Low | ErrorFrame MUST scope includes terminal state | Scoped to "until terminal closed state" |
| E5-9 | Low | Integrity hash concatenation order implicit | Added explicit 20-byte sequence |
| E5-10 | Low | Key rotation 0x03 derivation ambiguous | Explicit "two separate HKDF calls" |
| E5-11 | Low | Device key failure handling missing | Added disable-persistence fallback |
| E5-12 | Low | State Token header flags undefined | Added "reserved, must be 0" |

---

## RC22 (December 2025)

External Review Round 4. 1 blocking issue resolved.

| ID | Severity | Finding | Resolution |
|----|----------|---------|------------|
| E4-1 | Blocking | ErrorFrame/EncryptedRecord disambiguation | Added Frame Disambiguation procedure in §3.3.13 |
| E4-2 | Medium | Flow control integer overflow | Changed to saturating addition in §3.3.9 |
| E4-3 | Medium | QUIC stream 0 control-only ambiguity | Clarified exclusive control use in §3.4 |
| E4-4 | Medium | AckFrame usage on reliable transports | Added transport restriction in §3.3.10 |
| E4-5 | Medium | Device-bound key singularity | Clarified single key per device in §6.6 |
| E4-6 | Low | Control stream bidirectionality | Added bidirectional note in §3.4 |
| E4-7 | Low | ErrorFrame temporal scope | Changed "post-handshake" to "any protocol phase" |
| E4-8 | Low | Integrity hash wire format | Explicit wire serialization in §3.3.5 |
| E4-9 | Low | Nonce derivation byte order | Explicit byte range in §4.3.4 |
| E4-10 | Low | Info string encoding | Added UTF-8 byte sequence in §4.6.3 |

---

## RC21 (December 2025)

External Review Round 3. First clean external review (0 blocking).

| ID | Severity | Finding | Resolution |
|----|----------|---------|------------|
| E3-1 | Low | ErrorFrame exception not in §3.3.13 | Added exception clause |
| E3-2 | Medium | QUIC stream 1 mapping table conflict | Removed row, added server restriction |
| E3-3 | Low | Integrity hash failure handling undefined | Added → MISMATCH |
| E3-4 | Medium | Token storage format vs logical format confusion | Clarified Token Persistence section |
| E3-5 | Low | Receive buffer preservation during migration | Added to §3.3.3 |

---

## RC20 (December 2025)

External Review Round 2. 2 blocking issues resolved.

| ID | Severity | Finding | Resolution |
|----|----------|---------|------------|
| E2-1 | Blocking | State Token encryption nonce missing | Added token_nonce and storage format in §6.5 |
| E2-2 | Blocking | QUIC stream ID mapping undefined | Added §3.4 QUIC Stream Mapping |
| E2-3 | Medium | Stream ID allocation policy missing | Added even/odd allocation to §3.3.1 |
| E2-4 | Medium | Sync-Ack receiver_seq semantics | Added "next expected byte" definition |
| E2-5 | Medium | Flow control integer type mismatch | Added window_increment cap |
| E2-6 | Medium | Key rotation non-rotated direction counter | Clarified counter behavior |
| E2-7 | Medium | EncryptedRecord AAD byte order | Explicit in §3.3.13 |
| E2-8 | Medium | KeyUpdate retransmission idempotency | Added to §4.6.4 |
| E2-9 | Medium | State Token storage format clarification | Added to §6.5 |
| E2-10 | Low | ErrorFrame always plaintext | Added to §3.3.12 |
| E2-11 | Low | Version abort SHOULD/MAY | Updated §2.2 |
| E2-12 | Low | Priority normalization not protocol-visible | Clarified in §3.3.8 |
| E2-13 | Low | Known Mode nonce derivation safety | Added note to §4.3.4 |

---

## RC19 (December 2025)

External Review Round 1. 3 blocking issues resolved.

| ID | Severity | Finding | Resolution |
|----|----------|---------|------------|
| E-1 | Blocking | Non-QUIC encrypted record format undefined | Added §3.3.13 EncryptedRecord |
| E-2 | Blocking | send_offset/recv_offset in State Token undefined | Added definitions in §6.5 |
| E-3 | Blocking | Migration has no session identification | Added session_id to Sync-Frame header |
| E-4 | Medium | Global byte order undefined | Added statement in §3.3 |
| E-5 | Medium | Nonce counter reset on key rotation undefined | Added to §4.6.3 |
| E-6 | Medium | State Token AAD boundary undefined | Added to §6.5 |
| E-7 | Medium | No ErrorFrame for non-QUIC | Added §3.3.12 ErrorFrame |
| E-8 | Medium | Sync-Ack status invariant unclear | Added to §3.3.6 |
| E-9 | Medium | Flow control window threshold ambiguous | Clarified in §3.3.9 |
| E-10 | Medium | Known Mode random freshness not required | Added requirement in §4.3 |
| E-11 | Low | Version mismatch abort behavior undefined | Added to §2.2 |
| E-12 | Low | Priority normalization timing unclear | Clarified in §3.3.8 |
| E-13 | Low | Android service type wording inconsistent | Fixed in §1.3 |

---

## RC1-RC18 (November-December 2025)

Initial development phase. Major milestones:

- **RC1:** Initial draft with core handshake and transport
- **RC5:** Added Known Mode (SPAKE2+)
- **RC8:** Added State Token persistence
- **RC10:** Added QUIC as primary transport
- **RC12:** Added transport migration (Sync-Frame)
- **RC15:** Added key rotation protocol
- **RC18:** Pre-external-review baseline

---

## Convergence Metrics

| Round | Blocking | Medium | Low | Assessment |
|-------|----------|--------|-----|------------|
| RC18→RC19 | 3 | 7 | 3 | Major gaps in encryption/persistence |
| RC19→RC20 | 2 | 7 | 4 | QUIC integration incomplete |
| RC20→RC21 | 0 | 2 | 3 | First clean external review |
| RC21→RC22 | 1 | 4 | 5 | Frame disambiguation |
| RC22→RC23 | 2 | 4 | 6 | Stream ID collision |
| RC23→RC24 | 1 | 6 | 5 | Flow control deadlock |
| RC24→RC25 | 1 | 3 | 4 | Error code conflict |

**Total findings addressed:** 86 (13 blocking, 33 medium, 30 low, 10 rejected with rationale)

---

*End of Changelog*
