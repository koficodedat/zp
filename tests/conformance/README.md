# Conformance Tests

Tests that verify implementation compliance with zp specification v1.0 and TEST_VECTORS.md.

## Structure

- `crypto/` - Cryptographic primitive conformance (§1 of TEST_VECTORS.md)
- `frames/` - Frame parsing/serialization (§3.3 of spec)
- `handshake/` - Handshake state machine (§4 of spec)
- `flow_control/` - Flow control behavior (§3.3.9 of spec)

## Running

```bash
cargo test --test conformance
```

All tests must pass before merging.
