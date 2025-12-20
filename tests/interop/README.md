# Interoperability Tests

Tests that verify cross-platform compatibility.

## Structure

- `platform/` - iOS ↔ Android ↔ Browser interop
- `cipher_suites/` - Cross-platform cipher suite compatibility
- `version_negotiation/` - Protocol version negotiation

## Running

Requires platform-specific test infrastructure:

```bash
# iOS tests
cargo test --test interop --features ios

# Android tests
cargo test --test interop --features android

# Browser tests
wasm-pack test --node
```
