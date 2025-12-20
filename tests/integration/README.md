# Integration Tests

Tests that verify cross-component behavior.

## Structure

- `end_to_end/` - Full client-server scenarios
- `transport_fallback/` - QUIC → TCP → WebSocket fallback chain
- `session_resumption/` - Session persistence and resumption

## Running

```bash
cargo test --test integration
```
