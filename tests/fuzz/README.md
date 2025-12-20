# Fuzz Tests

Fuzzing harnesses for parsers and state machines.

## Structure

- `frame_parser/` - Frame parsing fuzzing
- `handshake/` - Handshake state machine fuzzing
- `crypto/` - Cryptographic input fuzzing

## Running

```bash
# Run all fuzz targets for 1 hour
/fuzz all 3600

# Run specific target
cargo fuzz run frame_parser
```

See CLAUDE.md for fuzzing requirements (1+ hours before release).
