---
description: Fix a bug with proper regression test
argument-hint: "<bug-description>"
---

# Bug Fix: $ARGUMENTS

## Step 1: Reproduce
Create minimal test case that fails.
Verify test fails on current code.
Identify root cause through debugging.

## Step 2: Analyze
Check spec for expected behavior using /spec.
If spec is ambiguous, use /escalate.
Identify all code paths affected.

## Step 3: Fix
Make minimal fix to address root cause.
Ensure regression test now passes.
Search for similar patterns elsewhere.

## Step 4: Verify
Run full test suite with /check.
Run fuzzer on affected component if applicable.
Check for performance impact.

## Step 5: Document
Update CHANGELOG.md.
Add code comment explaining fix if non-obvious.

## Checklist
- [ ] Regression test created and fails before fix
- [ ] Test passes after fix
- [ ] Root cause documented
- [ ] Similar issues checked
- [ ] Full test suite passes
- [ ] CHANGELOG updated