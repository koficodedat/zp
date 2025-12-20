---
description: Smart commit with pre-flight checks, tests, and intelligent grouping
argument-hint: [--dry-run]
allowed-tools: Bash, Read, Grep, Glob, AskUserQuestion
---

You are a **Smart Commit Assistant** for the ZP protocol implementation.

Execute the following workflow:

## 1. PRE-FLIGHT CHECKS

```bash
# Auto-fix formatting
cargo fmt --all

# Attempt clippy fixes
cargo clippy --all-targets --all-features --fix --allow-dirty -- -D warnings

# Verify clippy passes
cargo clippy --all-targets --all-features -- -D warnings

# Build check
cargo build --all
```

**Abort if build fails.** Report errors with suggestions.

## 2. TEST VALIDATION

```bash
# Run all non-ignored tests
cargo test --all
```

**On failure:**
- Analyze error output
- If obvious fix (e.g., outdated assertion), apply fix
- Else report with context and prompt user for direction

## 3. ZP-SPECIFIC VALIDATIONS

### Crypto Code Safety Check
```bash
# Check for logging in crypto code (security violation)
CRYPTO_LOGS=$(grep -r "println!\|eprintln!\|log::\|dbg!" --include="*.rs" crates/zp-crypto/src/ | grep -v test | wc -l)

if [ $CRYPTO_LOGS -gt 0 ]; then
    echo "❌ SECURITY VIOLATION: Found logging statements in crypto code"
    grep -r "println!\|eprintln!\|log::\|dbg!" --include="*.rs" crates/zp-crypto/src/ | grep -v test
    echo "Crypto code must not log sensitive data. Remove these before committing."
    # This is a hard fail for crypto code
fi
```

### Spec Compliance Check
```bash
# Verify spec references exist in code (informational)
SPEC_REFS=$(git diff --cached | grep -c "spec §\|Spec §\|per spec\|zp_specification" || echo "0")
echo "ℹ️  Spec references in changes: $SPEC_REFS"
```

## 4. CLEANUP SCAN

Search and clean:

```bash
# Find debugging artifacts in non-test code
grep -r "dbg!" --include="*.rs" crates/*/src/ | grep -v test

# Find temp files (excluding target/)
find . -type f \( -name "*.orig" -o -name "*.bak" -o -name ".DS_Store" \) ! -path "*/target/*"

# Find log files outside target/
find . -type f -name "*.log" ! -path "*/target/*" ! -path "*/bench-*.log"
```

**Actions:**
- Remove `dbg!()` from non-test code automatically
- Remove temp files (*.orig, *.bak, .DS_Store)
- Report `println!()` in non-test code → prompt user (may be intentional)
- Report TODO/FIXME count as info

## 5. ANALYZE & GROUP CHANGES

```bash
# Get all changes
git status --porcelain
git diff --stat
```

**Categorize files by type:**
- `feat` — New features (spec implementations, new cipher suites)
- `fix` — Bug fixes
- `test` — Test-only changes (conformance, unit tests)
- `docs` — Documentation (*.md, doc comments, spec references)
- `chore` — Build, CI, tooling (.github/, Cargo.toml)
- `perf` — Performance improvements (benchmarks)
- `refactor` — Code restructuring without behavior change
- `security` — Security fixes or hardening

**ZP-Specific Scopes:**
- `crypto` — zp-crypto crate
- `transport` — zp-transport crate
- `core` — zp-core crate
- `platform` — zp-platform crate
- `ffi` — zp-ffi crate
- `conformance` — tests/conformance
- `spec` — Specification compliance
- `ci` — CI/CD
- `docs` — Documentation

**Group related files into logical commits:**
- Group by crate if changes span multiple crates
- Separate docs from code changes (unless tightly coupled)
- Keep test changes with related code changes
- Separate crypto changes from other changes (require crypto-impl audit)

**Show proposed commits:**
```
Proposed commits:

1. feat(crypto): implement ML-KEM-1024 for ZP_HYBRID_2 cipher suite
   - crates/zp-crypto/src/kex/ml_kem.rs
   - crates/zp-crypto/src/kex.rs
   - tests/conformance/crypto_test.rs

   Spec compliance: FIPS 203, zp spec §4.2 (ZP_PQC_2)
   Security: Requires crypto-impl audit approval

2. docs: update CHANGELOG and NEXT_TASKS for ML-KEM-1024
   - docs/CHANGELOG.md
   - NEXT_TASKS.md

   Documentation updates for completed Task 2.8

Proceed? (y/n)
```

## 6. COMMIT EXECUTION

For each approved group:

```bash
git add <files>
git commit -m "<prefix>(<scope>): <message>"
```

**Commit message format:**
- `<prefix>` — feat/fix/docs/test/chore/perf/refactor/security
- `<scope>` — Affected component (crypto, transport, core, platform, ffi, conformance, spec, ci, docs)
- `<message>` — Concise description (50 chars max)

**Examples:**
```
feat(crypto): implement ML-KEM-1024 for ZP_HYBRID_2 cipher suite
fix(transport): handle QUIC stream ID collision per spec §3.4
docs(spec): update CHANGELOG with cipher suite status
test(conformance): add RFC 5903 ECDH-P256 test vectors
chore(ci): add cargo-audit security scanning workflow
perf(crypto): optimize ChaCha20-Poly1305 SIMD operations
security(crypto): verify constant-time operations for P-256
```

**IMPORTANT:**
- **NEVER add "🤖 Generated with Claude Code" attribution**
- **NEVER add "Co-Authored-By: Claude" trailer**
- Keep messages concise and descriptive
- Use present tense ("add" not "added")
- Reference spec sections where applicable (e.g., "per spec §3.4")
- For crypto changes, note if crypto-impl audit approved

## 7. SUMMARY REPORT

After commits:
```
✅ 2 commits created:
   - a1b2c3d feat(crypto): implement ML-KEM-1024 for ZP_HYBRID_2
   - d4e5f6g docs: update CHANGELOG and NEXT_TASKS for ML-KEM-1024

📊 Pre-flight:
   - Format: ✅ Clean
   - Clippy: ✅ 0 warnings
   - Build: ✅ Success
   - Tests: ✅ 55 passing (zp-crypto)
   - Crypto safety: ✅ No logging in crypto code

🧹 Cleanup:
   - Removed 0 dbg!() calls
   - Removed 0 temp files
   - 0 TODOs added (non-blocking)

📋 ZP Compliance:
   - Spec references: 3 (FIPS 203, zp spec §4.2)
   - Test vectors: RFC 5903, TEST_VECTORS.md §1.3
   - Crypto audit: APPROVED (crypto-impl agent)

Next: Run /smart-push to push commits, or continue development
```

## 8. DRY-RUN MODE

If `--dry-run` argument provided:
- Execute all checks (format, clippy, build, tests)
- Show proposed commits
- DO NOT execute git commands
- Report what would be done

**To see plan without committing:**
```
/smart-commit --dry-run
```

## 9. ZP-SPECIFIC NOTES

### For Crypto Changes:
- Always verify crypto-impl agent approval exists in CHANGELOG
- Check for Zeroizing usage on secrets
- Verify no unsafe code added (forbidden in zp-crypto)
- Ensure spec references for algorithms (e.g., "FIPS 203", "RFC 5903")

### For Spec Implementations:
- Reference spec section in commit message
- Ensure conformance tests exist
- Update CHANGELOG.md with feature description
- Update NEXT_TASKS.md if completing a task

### For Test Changes:
- Separate conformance tests from unit tests if large
- Note test vector sources (RFC, FIPS, TEST_VECTORS.md)
- Verify test coverage metrics

### Commit Message Quality:
- **Good**: `feat(crypto): implement ECDH-P256 per NIST SP 800-56A`
- **Better**: `feat(crypto): implement ECDH-P256 for ZP_CLASSICAL_2 (RFC 5903)`
- **Best**: `feat(crypto): implement ECDH-P256 for ZP_CLASSICAL_2 FIPS mode`

**Avoid:**
- Generic messages: `feat(crypto): add new code`
- Missing scope: `feat: implement something`
- Overly long: `feat(crypto): implement ECDH-P256 key exchange using NIST P-256 curve for the ZP_CLASSICAL_2 cipher suite to enable FIPS 140-3 compliance` (too long)

## 10. ERROR HANDLING

**If pre-flight fails:**
- Show which check failed
- Provide fix commands
- **Do NOT proceed with commit**
- User must fix issues and re-run

**If crypto safety check fails:**
- **HARD FAIL** - Logging in crypto code is a security violation
- User must remove all logging statements
- Explain: "Crypto code must not leak sensitive data through logs"

**If user cancels commit:**
- Show: "Commit cancelled. Your changes remain staged/unstaged as before."
- Provide: "Run /smart-commit again when ready"
