---
description: Security self-audit a component
argument-hint: <crate-path>
allowed-tools: bash, Read, Grep
---

Perform security audit on the specified crate:

1. Static analysis:
```bash
   cargo clippy -p [crate] -- -D warnings
   cargo audit
```

2. Check for unsafe code:
```bash
   grep -r "unsafe" [crate-path]/src/
```
   For each unsafe block, verify SAFETY comment exists.

3. Check for secret handling:
   - Search for `Zeroizing` usage on key material
   - Search for any logging of sensitive data

4. Generate report with findings and severity.