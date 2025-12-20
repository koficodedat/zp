# zp Fuzzing Harnesses

Fuzzing harnesses using `cargo-fuzz` (libFuzzer).

## Setup

```bash
cargo install cargo-fuzz
```

## Available Fuzz Targets

### `fuzz_frame_parser`
Fuzzes `Frame::parse()` with arbitrary bytes to test:
- Buffer overruns
- Panic-free parsing
- Malformed frame handling
- Integer overflow in length fields
- Out-of-bounds access
- Serialization round-trip idempotence

## Running Fuzzers

```bash
# Run frame parser fuzzer for 60 seconds
cd tests/fuzz
cargo fuzz run fuzz_frame_parser -- -max_total_time=60

# Run with custom corpus
cargo fuzz run fuzz_frame_parser corpus/fuzz_frame_parser

# Run until crash found (no time limit)
cargo fuzz run fuzz_frame_parser
```

## Analyzing Crashes

Crashes are saved to `tests/fuzz/artifacts/fuzz_frame_parser/`:

```bash
# Reproduce a crash
cargo fuzz run fuzz_frame_parser artifacts/fuzz_frame_parser/crash-<hash>

# Minimize crash input
cargo fuzz tmin fuzz_frame_parser artifacts/fuzz_frame_parser/crash-<hash>

# Get coverage report
cargo fuzz coverage fuzz_frame_parser
```

## Adding Seed Corpus

Add known-good test vectors to bootstrap fuzzing:

```bash
# Add from TEST_VECTORS.md
echo "5a5043484..." | xxd -r -p > corpus/fuzz_frame_parser/clienthello_valid
```

## Continuous Fuzzing

For production readiness, run fuzzers for 1+ hours:

```bash
cargo fuzz run fuzz_frame_parser -- -max_total_time=3600
```

Target: **0 crashes, >1M executions**

See CLAUDE.md for fuzzing requirements (1+ hours before release).
