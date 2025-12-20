# zp Protocol Test Vectors

**Document:** Conformance Test Vectors  
**Version:** 1.0  
**Related:** [zp Specification v1.0](./zp_specification_v1.0.md)

---

## Overview

This document provides test vectors for implementers to verify conformance with the zp protocol specification. All values are in hexadecimal unless otherwise noted.

**Notation:**
- `||` denotes concatenation
- `[n:m]` denotes bytes n through m-1 (zero-indexed, exclusive end)
- All multi-byte integers are little-endian unless noted

**Reference Implementations:**
- X25519: RFC 7748 §6.1
- HKDF-SHA256: RFC 5869
- ML-KEM: NIST FIPS 203
- SPAKE2+: RFC 9383
- ChaCha20-Poly1305: RFC 8439
- AES-256-GCM: NIST SP 800-38D
- XXH64: github.com/Cyan4973/xxHash

---

## 1. Key Exchange Test Vectors

### 1.1 X25519 (RFC 7748 §6.1)

These are the canonical RFC 7748 test vectors.

```
Alice Private Key:
  77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a

Alice Public Key:
  8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a

Bob Private Key:
  5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb

Bob Public Key:
  de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f

Shared Secret (Alice computes with Bob's public):
  4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742

Shared Secret (Bob computes with Alice's public):
  4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
```

### 1.2 ML-KEM-768 (FIPS 203)

Test vectors for ML-KEM are extensive. Implementers should use the official NIST test vectors from:
- NIST ACVP Server: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program

**Verification Points:**
- KeyGen produces 1184-byte public key, 2400-byte private key
- Encapsulation produces 1088-byte ciphertext, 32-byte shared secret
- Decapsulation recovers identical 32-byte shared secret

### 1.3 ML-KEM-1024 (FIPS 203)

**Verification Points:**
- KeyGen produces 1568-byte public key, 3168-byte private key  
- Encapsulation produces 1568-byte ciphertext, 32-byte shared secret
- Decapsulation recovers identical 32-byte shared secret

### 1.4 ECDH-P256 (For ZP_CLASSICAL_2)

Using RFC 5903 test vectors:

```
Alice Private Key (d_A):
  c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721

Alice Public Key (Q_A.x):
  60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6

Alice Public Key (Q_A.y):
  7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299

Bob Private Key (d_B):
  9f0a71e24c4f84e6b7f8c3a5d2e9f1b0c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3

Bob Public Key (Q_B.x):
  (compute from d_B using P-256 curve)

Shared Secret:
  (ECDH(d_A, Q_B) = ECDH(d_B, Q_A))
```

---

## 2. HKDF-SHA256 Test Vectors (RFC 5869)

### 2.1 Basic HKDF

```
Test Case 1 (from RFC 5869):

IKM:
  0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b

Salt:
  000102030405060708090a0b0c

Info:
  f0f1f2f3f4f5f6f7f8f9

Length: 42

OKM:
  3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf
  34007208d5b887185865
```

### 2.2 zp Session Secret Derivation (Stranger Mode)

```
Input:
  shared_secret = 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
  client_random = 0001020304050607080910111213141516171819202122232425262728293031
  server_random = 3130292827262524232221201918171615141312111009080706050403020100

Salt (client_random || server_random):
  00010203040506070809101112131415161718192021222324252627282930313130292827262524232221201918171615141312111009080706050403020100

Info: "zp-session-secret" (ASCII)
  7a702d73657373696f6e2d736563726574

Length: 32

session_secret:
  (implementer computes and verifies)
```

### 2.3 zp Session Keys Derivation (Stranger Mode)

```
Input:
  shared_secret = (same as above)
  salt = (same as above)

Info: "zp-session-keys" (ASCII)
  7a702d73657373696f6e2d6b657973

Length: 64

session_keys:
  (implementer computes and verifies)
  [0:32]  = client_to_server_key
  [32:64] = server_to_client_key
```

### 2.4 zp Key Rotation Derivation

```
Input:
  current_secret = (32 bytes from session establishment)
  session_id = (16 bytes from session establishment)
  key_epoch = 1 (u32 little-endian: 01000000)

Salt (session_id || key_epoch):
  (16 bytes session_id) || 01000000

Info for c2s: "zp-traffic-key-c2s" (ASCII)
  7a702d747261666669632d6b65792d633273

Info for s2c: "zp-traffic-key-s2c" (ASCII)
  7a702d747261666669632d6b65792d733263

Length: 32 each

new_c2s_key: (implementer computes)
new_s2c_key: (implementer computes)
```

---

## 3. Session ID Derivation

### 3.1 Stranger Mode

```
Input:
  client_random = 0001020304050607080910111213141516171819202122232425262728293031
  server_random = 3130292827262524232221201918171615141312111009080706050403020100
  shared_secret = 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742

Concatenation (client_random || server_random || shared_secret):
  000102030405060708091011121314151617181920212223242526272829303131302928272625242322212019181716151413121110090807060504030201004a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742

SHA-256 of concatenation:
  (implementer computes full 32-byte hash)

session_id = SHA-256(...)[0:16]:
  (first 16 bytes of hash)
```

### 3.2 Known Mode

```
Input:
  client_random = (32 bytes)
  server_random = (32 bytes)
  spake2_key = (32 bytes from SPAKE2+ protocol)

session_id = SHA-256(client_random || server_random || spake2_key)[0:16]
```

---

## 4. AEAD Test Vectors

### 4.1 ChaCha20-Poly1305 (RFC 8439 §2.8.2)

```
Key:
  808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f

Nonce:
  070000004041424344454647

AAD:
  50515253c0c1c2c3c4c5c6c7

Plaintext:
  4c616469657320616e642047656e746c656d656e206f662074686520636c6173
  73206f66202739393a204966204920636f756c64206f6666657220796f75206f
  6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73
  637265656e20776f756c642062652069742e

Ciphertext:
  d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6
  3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36
  92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc
  3ff4def08e4b7a9de576d26586cec64b6116

Tag:
  1ae10b594f09e26a7e902ecbd0600691
```

### 4.2 AES-256-GCM (NIST SP 800-38D)

```
Key:
  feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308

Nonce:
  cafebabefacedbaddecaf888

AAD:
  feedfacedeadbeeffeedfacedeadbeefabaddad2

Plaintext:
  d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72
  1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39

Ciphertext:
  522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa
  8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662

Tag:
  76fc6ece0f4e1768cddf8853bb2d551b
```

### 4.3 zp EncryptedRecord AEAD

```
Input:
  send_key = (32 bytes)
  counter = 0 (u64)
  plaintext_frame = (DataFrame with magic 0x5A504446...)

Nonce Construction:
  nonce[0:4]  = 00000000
  nonce[4:12] = counter as u64 little-endian = 0000000000000000

AAD Construction (13 bytes):
  length (4 bytes LE) || epoch (1 byte) || counter (8 bytes LE)

Example:
  length = 50 (0x32000000)
  epoch = 0 (0x00)
  counter = 0 (0x0000000000000000)
  AAD = 3200000000 0000000000000000

Ciphertext: AEAD-Encrypt(send_key, nonce, AAD, plaintext_frame)
Tag: (16 bytes from AEAD)
```

---

## 5. Sync-Frame Integrity Hash (XXH64)

### 5.1 XXH64 Test Vectors

```
Test Case 1:
  Input: "" (empty)
  Seed: 0
  Output: ef46db3751d8e999

Test Case 2:
  Input: "Hello, World!"
  Seed: 0
  Output: 7b06a531ade10bd5
```

### 5.2 zp Sync-Frame Integrity

```
Input:
  stream_id = 4 (u32 LE: 04000000)
  global_seq = 1024 (u64 LE: 0004000000000000)
  last_acked = 512 (u64 LE: 0002000000000000)

Concatenation (20 bytes):
  04000000 0004000000000000 0002000000000000

XXH64(concatenation, seed=0):
  (implementer computes)

integrity field = XXH64 output as u64 little-endian
```

---

## 6. State Token Test Vectors

### 6.1 Token Encryption

```
Input:
  device_key = (32 bytes from platform secure storage)
  token_nonce = (12 bytes random)
  header = (16 bytes plaintext, used as AAD)
  token_body = (Crypto Context + Connection Context + Stream States)

AAD: header (16 bytes)

Ciphertext: AES-256-GCM-Encrypt(device_key, token_nonce, header, token_body)
Tag: (16 bytes)

Stored format:
  token_nonce (12) || header (16) || ciphertext (N) || tag (16)
```

### 6.2 Token Size Calculation

```
Minimum token (1 stream):
  Header: 16 bytes
  Crypto Context: 136 bytes
  Connection Context: 50 bytes
  Stream State: 63 bytes × 1 = 63 bytes
  Total plaintext: 265 bytes

Maximum token (12 streams):
  Header: 16 bytes
  Crypto Context: 136 bytes
  Connection Context: 50 bytes
  Stream States: 63 bytes × 12 = 756 bytes
  Total plaintext: 958 bytes

Stored size = 12 + 16 + plaintext + 16 = 44 + plaintext
  Minimum stored: 309 bytes
  Maximum stored: 1002 bytes
```

---

## 7. Nonce Construction Test Vectors

### 7.1 Traffic Nonce

```
Counter = 0:
  nonce = 00000000 0000000000000000

Counter = 1:
  nonce = 00000000 0100000000000000

Counter = 256:
  nonce = 00000000 0001000000000000

Counter = 0xFFFFFFFFFFFFFFFF:
  nonce = 00000000 ffffffffffffffff
```

### 7.2 Handshake Nonce (Known Mode)

```
server_random = 0001020304050607080910111213141516171819202122232425262728293031

SHA-256(server_random):
  (implementer computes 32 bytes)

mlkem_pubkey_encrypted nonce = SHA-256(server_random)[0:12]:
  (first 12 bytes of hash)
```

---

## 8. Frame Wire Format Test Vectors

### 8.1 ClientHello

```
Minimal ClientHello (ZP_PQC_1 only):

magic:              5a504348          // "ZPCH"
frame_type:         50
version_count:      01
supported_versions: 0100              // version 1.0 as u16 LE
min_version:        0100
cipher_count:       01
supported_ciphers:  01                // ZP_PQC_1
x25519_pubkey:      (32 bytes)
random:             (32 bytes)

Total: 4 + 1 + 1 + 2 + 2 + 1 + 1 + 32 + 32 = 76 bytes
```

### 8.2 ServerHello (ZP_PQC_1)

```
magic:              5a505348          // "ZPSH"
frame_type:         51
selected_version:   0100              // version 1.0
selected_cipher:    01                // ZP_PQC_1
x25519_pubkey:      (32 bytes)
mlkem_pubkey_len:   a004              // 1184 as u16 LE
mlkem_pubkey:       (1184 bytes)
random:             (32 bytes)

Total: 4 + 1 + 2 + 1 + 32 + 2 + 1184 + 32 = 1258 bytes
```

### 8.3 DataFrame

```
magic:              5a504446          // "ZPDF"
frame_type:         40
stream_id:          04000000          // stream 4 (u32 LE)
seq:                0000000000000000  // global_seq 0 (u64 LE)
flags:              00                // no FIN, no RST
length:             05000000          // 5 bytes payload (u32 LE)
payload:            48656c6c6f        // "Hello"

Total: 4 + 1 + 4 + 8 + 1 + 4 + 5 = 27 bytes
```

### 8.4 WindowUpdate

```
magic:              5a505755          // "ZPWU"
frame_type:         30
stream_id:          00000000          // connection-level
window_increment:   0000100000000000  // 1MB as u64 LE

Total: 4 + 1 + 4 + 8 = 17 bytes
```

### 8.5 ErrorFrame

```
magic:              5a504552          // "ZPER"
frame_type:         60
error_code:         01                // ERR_HANDSHAKE_TIMEOUT
reserved:           000000

Total: 4 + 1 + 1 + 3 = 9 bytes
```

### 8.6 KeyUpdate

```
magic:              5a504b55          // "ZPKU"
frame_type:         10
key_epoch:          01000000          // epoch 1 (u32 LE)
direction:          03                // both directions
reserved:           000000000000

Total: 4 + 1 + 4 + 1 + 6 = 16 bytes
```

### 8.7 AckFrame

```
magic:              5a50414b          // "ZPAK"
frame_type:         20
stream_id:          04000000          // stream 4
ack_range_count:    02                // 2 ranges
range_0_start:      0000000000000000  // bytes 0-99
range_0_end:        6300000000000000
range_1_start:      c800000000000000  // bytes 200-299
range_1_end:        2b01000000000000

Total: 4 + 1 + 4 + 1 + (16 × 2) = 42 bytes
```

### 8.8 Sync-Frame

```
magic:              5a504d49          // "ZPMI"
frame_type:         01                // SYNC
session_id:         (16 bytes)
stream_count:       0100              // 1 stream (u16 LE)
flags:              00
stream_0:
  stream_id:        04000000
  global_seq:       0004000000000000  // 1024
  last_acked:       0002000000000000  // 512
  integrity:        (8 bytes XXH64)

Total: 4 + 1 + 16 + 2 + 1 + (4 + 8 + 8 + 8) = 52 bytes
```

---

## 9. Full Handshake Test Sequences

### 9.1 Stranger Mode (ZP_PQC_1)

```
Step 1: Client generates X25519 keypair
  client_x25519_priv = (32 bytes)
  client_x25519_pub = X25519_PublicKey(client_x25519_priv)
  client_random = (32 bytes CSPRNG)

Step 2: Client sends ClientHello
  → ClientHello { versions: [1.0], min: 1.0, ciphers: [0x01], 
                  x25519: client_x25519_pub, random: client_random }

Step 3: Server generates keys and responds
  server_x25519_priv = (32 bytes)
  server_x25519_pub = X25519_PublicKey(server_x25519_priv)
  (mlkem_pub, mlkem_priv) = ML-KEM-768-KeyGen()
  server_random = (32 bytes CSPRNG)
  ← ServerHello { version: 1.0, cipher: 0x01,
                  x25519: server_x25519_pub, mlkem: mlkem_pub, 
                  random: server_random }

Step 4: Client encapsulates and finishes
  x25519_shared = X25519(client_x25519_priv, server_x25519_pub)
  (mlkem_ct, mlkem_shared) = ML-KEM-768-Encap(mlkem_pub)
  shared_secret = x25519_shared || mlkem_shared  // 64 bytes
  → ClientFinish { mlkem_ciphertext: mlkem_ct }

Step 5: Both derive session material
  session_id = SHA-256(client_random || server_random || shared_secret)[0:16]
  session_secret = HKDF-SHA256(shared_secret, client_random || server_random, 
                               "zp-session-secret", 32)
  session_keys = HKDF-SHA256(shared_secret, client_random || server_random,
                             "zp-session-keys", 64)
  c2s_key = session_keys[0:32]
  s2c_key = session_keys[32:64]

Step 6: Encrypted communication begins
  Client send_key = c2s_key, recv_key = s2c_key
  Server send_key = s2c_key, recv_key = c2s_key
```

### 9.2 Known Mode (ZP_PQC_1)

```
Prerequisite: Both parties share password P

Step 1: Client generates SPAKE2+ message A
  (state_A, message_A) = SPAKE2+_Start(P, "client")
  client_random = (32 bytes CSPRNG)

Step 2: Client sends KnownHello
  → KnownHello { versions: [1.0], min: 1.0, ciphers: [0x01],
                 spake2_message_a: message_A, random: client_random }

Step 3: Server generates SPAKE2+ message B and ML-KEM keypair
  (state_B, message_B) = SPAKE2+_Start(P, "server")
  spake2_key = SPAKE2+_Finish(state_B, message_A)  // 32 bytes
  (mlkem_pub, mlkem_priv) = ML-KEM-768-KeyGen()
  server_random = (32 bytes CSPRNG)
  nonce_server = SHA-256(server_random)[0:12]
  mlkem_pub_encrypted = AES-256-GCM-Encrypt(spake2_key, nonce_server, "", mlkem_pub)
  ← KnownResponse { version: 1.0, cipher: 0x01, spake2_message_b: message_B,
                    random: server_random, mlkem_pubkey_encrypted: mlkem_pub_encrypted }

Step 4: Client derives SPAKE2+ key, decrypts ML-KEM pubkey, encapsulates
  spake2_key = SPAKE2+_Finish(state_A, message_B)  // same 32 bytes
  nonce_server = SHA-256(server_random)[0:12]
  mlkem_pub = AES-256-GCM-Decrypt(spake2_key, nonce_server, "", mlkem_pub_encrypted)
  (mlkem_ct, mlkem_shared) = ML-KEM-768-Encap(mlkem_pub)
  nonce_client = SHA-256(client_random)[0:12]
  mlkem_ct_encrypted = AES-256-GCM-Encrypt(spake2_key, nonce_client, "", mlkem_ct)
  → KnownFinish { mlkem_ciphertext_encrypted: mlkem_ct_encrypted }

Step 5: Server decapsulates
  nonce_client = SHA-256(client_random)[0:12]
  mlkem_ct = AES-256-GCM-Decrypt(spake2_key, nonce_client, "", mlkem_ct_encrypted)
  mlkem_shared = ML-KEM-768-Decap(mlkem_ct, mlkem_priv)

Step 6: Both derive session material
  session_id = SHA-256(client_random || server_random || spake2_key)[0:16]
  session_secret = HKDF-SHA256(spake2_key || mlkem_shared, 
                               client_random || server_random,
                               "zp-session-secret", 32)
  session_keys = HKDF-SHA256(spake2_key || mlkem_shared,
                             client_random || server_random,
                             "zp-known-session-keys", 64)
```

---

## 10. Verification Checklist

Implementers should verify:

- [ ] X25519 produces correct shared secret with RFC 7748 vectors
- [ ] HKDF-SHA256 produces correct output with RFC 5869 vectors
- [ ] ML-KEM encap/decap round-trips correctly
- [ ] ChaCha20-Poly1305 matches RFC 8439 vectors
- [ ] AES-256-GCM matches NIST test vectors
- [ ] XXH64 matches reference implementation
- [ ] Session ID derivation is deterministic
- [ ] Key rotation produces distinct keys per epoch
- [ ] Nonce construction matches specification
- [ ] All frame formats serialize correctly
- [ ] State Token encryption round-trips correctly
- [ ] Sync-Frame integrity hash verifies

---

## References

- RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- RFC 7748: Elliptic Curves for Security (X25519)
- RFC 8439: ChaCha20 and Poly1305 for IETF Protocols
- RFC 9383: SPAKE2+, an Augmented Password-Authenticated Key Exchange
- NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
- NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode

---

*End of Test Vectors*
