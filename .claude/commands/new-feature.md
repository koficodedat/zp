---
description: Add a new protocol feature to the implementation
argument-hint: "<feature-name>"
---

# New Feature: $ARGUMENTS

## Step 1: Spec Review
Use /spec to identify all relevant sections for this feature.
List requirements as MUST/SHOULD/MAY.
Flag any ambiguities for potential DA escalation.

## Step 2: Design
Determine which crates are affected.
Define public API signatures.
Define internal data structures.
Document trade-offs considered.

## Step 3: Test First
Extract test vectors from TEST_VECTORS.md using /vector.
Write failing conformance tests.
Write failing unit tests.

## Step 4: Implement
Implement minimal code to pass tests.
Add rustdoc documentation.
Run `cargo clippy -- -D warnings` and fix.

## Step 5: Review
If crypto involved, reference agents/crypto-impl.md patterns.
Check security requirements.
Run benchmarks if performance-critical.

## Step 6: Finalize
Update CHANGELOG.md with feature description.
Commit with message: "feat: [feature-name]"

## Checklist
- [ ] Spec sections identified
- [ ] DA escalations resolved (if any)
- [ ] Conformance tests passing
- [ ] Unit tests passing
- [ ] Clippy clean
- [ ] Benchmarks run (if applicable)
- [ ] CHANGELOG updated