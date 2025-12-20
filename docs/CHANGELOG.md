# zp Protocol Changelog

**Document:** Version History  
**Covers:** RC1 through v1.0  
**Related:** [zp Specification v1.0](./zp_specification_v1.0.md) | [Test Vectors](./TEST_VECTORS.md)

---

## v1.0 (December 2025)

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
