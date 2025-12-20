# Agent: fuzz-gen

## Purpose

Generate fuzzing harnesses for zp protocol components, focusing on parsing untrusted input and state machine transitions.

## Activation

```
/agent fuzz-gen
```

## Capabilities

1. **Generate fuzz targets** - Create cargo-fuzz compatible harnesses
2. **Identify attack surfaces** - Find code paths handling untrusted input
3. **Create seed corpora** - Generate initial inputs from spec/test vectors
4. **Analyze coverage** - Identify under-fuzzed code paths

## Fuzzing Targets

### Priority 1: Frame Parsing

| Target | Input | Attack Surface |
|--------|-------|----------------|
| `fuzz_client_hello` | Raw bytes | Version/cipher parsing |
| `fuzz_server_hello` | Raw bytes | ML-KEM pubkey parsing |
| `fuzz_encrypted_record` | Raw bytes | Length/epoch/ciphertext |
| `fuzz_data_frame` | Raw bytes | Stream ID/seq/flags |
| `fuzz_sync_frame` | Raw bytes | Session ID/stream entries |
| `fuzz_error_frame` | Raw bytes | Error code handling |

### Priority 2: State Machines

| Target | Input | Attack Surface |
|--------|-------|----------------|
| `fuzz_handshake_state` | Frame sequence | State transitions |
| `fuzz_migration_state` | Sync/SyncAck sequence | Migration logic |
| `fuzz_stream_state` | DataFrame sequence | FIN/RST handling |
| `fuzz_rekey_state` | KeyUpdate sequence | Epoch transitions |

### Priority 3: Crypto Boundaries

| Target | Input | Attack Surface |
|--------|-------|----------------|
| `fuzz_mlkem_decap` | Ciphertext | Decapsulation failures |
| `fuzz_aead_decrypt` | Ciphertext + tag | Decryption failures |
| `fuzz_hkdf_derive` | Variable-length IKM | Key derivation |

## Harness Template

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

// For structured fuzzing
#[derive(Debug, Arbitrary)]
struct FuzzInput {
    // Define structured input
}

fuzz_target!(|data: &[u8]| {
    // Option 1: Raw bytes
    let _ = parse_frame(data);
    
    // Option 2: Structured
    if let Ok(input) = FuzzInput::arbitrary(&mut arbitrary::Unstructured::new(data)) {
        let _ = process_input(input);
    }
});
```

## Seed Corpus Generation

```bash
# Extract test vectors as seeds
for vector in $(grep -l "^##" docs/TEST_VECTORS.md); do
    # Convert hex to binary
    xxd -r -p > fuzz/corpus/target/$vector.bin
done
```

## Coverage Analysis

```bash
# Build with coverage
RUSTFLAGS="-C instrument-coverage" cargo fuzz build

# Run fuzzer
cargo fuzz run target -- -max_total_time=3600

# Generate coverage report
cargo cov -- show target/coverage --format=html
```

## Output Format

```
[FUZZ-GEN]

Target: [name]
Attack Surface: [description]
Priority: [1/2/3]

Generated:
- fuzz/fuzz_targets/[name].rs
- fuzz/corpus/[name]/[seeds]

Coverage Gaps:
1. [Uncovered code path]
2. [Uncovered edge case]

Run Command:
cargo fuzz run [name] -- -max_total_time=3600
```

## Crash Triage

When fuzzer finds crash:

1. Minimize: `cargo fuzz tmin target crash-xxxxx`
2. Analyze: Determine root cause
3. Classify:
   - **Security**: Memory safety, crypto failure → CRITICAL
   - **Correctness**: Logic error, bad state → HIGH
   - **Robustness**: Panic on bad input → MEDIUM
4. Create regression test from minimized input
5. Fix and verify

## Escalation

If fuzzer discovers:
- Memory safety issue → Immediate fix, security advisory
- Spec violation → Fix + escalate to DA for clarification
- Performance DoS → Evaluate, may need spec update
