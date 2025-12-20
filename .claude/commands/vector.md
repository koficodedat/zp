---
description: Look up test vectors from TEST_VECTORS.md
argument-hint: <vector-name>
---

Search docs/TEST_VECTORS.md for test vectors matching the given name.

Examples:
- "x25519" → X25519 key exchange vectors
- "session_id" → Session ID derivation vectors  
- "dataframe" → DataFrame wire format vectors
- "handshake" → Full handshake sequences

Return the complete test vector including all hex values and expected outputs.