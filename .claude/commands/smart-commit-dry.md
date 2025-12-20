---
description: Show commit plan without executing (analyze changes only)
argument-hint: none
allowed-tools: Bash, Read, Grep, Glob
---

You are a **Commit Plan Analyzer** for the ZP protocol implementation.

Analyze the current state and show what would be committed **without executing any changes**.

## 1. CURRENT STATE ANALYSIS

```bash
# Show current branch and status
BRANCH=$(git branch --show-current)
git status --porcelain

# Show unstaged and staged changes
git diff --stat
git diff --cached --stat

# Count changes by type
git diff --numstat
```

**Report:**
```
📍 Branch: main
📊 Status:
   - Modified: 5 files
   - Untracked: 2 files
   - Staged: 0 files

📝 Changes:
   - crates/zp-crypto: 3 files (+323/-45 lines)
   - tests/conformance: 1 file (+84/-0 lines)
   - docs: 2 files (+67/-8 lines)
```

## 2. PRE-FLIGHT PREDICTIONS

Simulate what checks would run:

```bash
# Check if formatting needed
cargo fmt --all --check 2>&1 | grep -c "Diff in" || echo "0"

# Count clippy warnings (without fixing)
cargo clippy --all-targets --all-features -- -D warnings 2>&1 | grep -c "warning:" || echo "0"

# Predict build issues
cargo check --all --message-format=short 2>&1 | grep -E "error|warning" | head -20
```

**Report:**
```
🔍 Pre-flight check predictions:
   ✅ Format: Clean (no changes needed)
   ✅ Clippy: 0 warnings detected
   ✅ Build: Success (no errors)
   ✅ Tests: Would run 55 tests (estimated pass based on previous run)

Prediction: Pre-flight would PASS ✅
```

## 3. CLEANUP OPPORTUNITIES

Scan for cleanup targets:

```bash
# Find debugging artifacts
DBG_COUNT=$(grep -r "dbg!" --include="*.rs" crates/*/src/ 2>/dev/null | grep -v test | wc -l)

# Find println in non-test code
PRINTLN_COUNT=$(grep -r "println!" --include="*.rs" crates/*/src/ 2>/dev/null | grep -v test | grep -v "mod.rs" | wc -l)

# Find temp files
TEMP_FILES=$(find . -type f \( -name "*.orig" -o -name "*.bak" -o -name ".DS_Store" \) ! -path "*/target/*" 2>/dev/null | wc -l)

# Count TODOs
TODO_COUNT=$(grep -r "TODO\|FIXME" --include="*.rs" crates/*/src/ 2>/dev/null | wc -l)

# ZP-specific: Check for crypto logging
CRYPTO_LOGS=$(grep -r "println!\|eprintln!\|log::" --include="*.rs" crates/zp-crypto/src/ 2>/dev/null | grep -v test | wc -l)
```

**Report:**
```
🧹 Cleanup opportunities:
   - 0 dbg!() calls to remove ✅
   - 0 println!() calls to review ✅
   - 0 temp files to delete ✅
   - 12 TODOs (informational, not blocking)

🔐 Crypto code safety:
   - 0 logging statements in zp-crypto ✅

Cleanup status: CLEAN ✅
```

## 4. PROPOSED COMMIT GROUPS

Analyze changed files and propose logical grouping:

```bash
# Categorize files
git status --porcelain | awk '{print $2}' | while read file; do
    case "$file" in
        crates/zp-crypto/src/*.rs) echo "crypto-src: $file" ;;
        crates/zp-crypto/tests/*.rs) echo "crypto-test: $file" ;;
        crates/zp-transport/src/*.rs) echo "transport-src: $file" ;;
        crates/zp-core/src/*.rs) echo "core-src: $file" ;;
        tests/conformance/*.rs) echo "conformance: $file" ;;
        docs/*.md) echo "docs: $file" ;;
        *.md) echo "docs: $file" ;;
        .github/*) echo "ci: $file" ;;
        Cargo.toml) echo "deps: $file" ;;
        *) echo "other: $file" ;;
    esac
done | sort
```

**Proposed commits:**
```
📦 Proposed commits:

1. feat(crypto): implement ML-KEM-1024 for ZP_HYBRID_2 cipher suite
   Files (3):
   - crates/zp-crypto/src/kex/ml_kem.rs (+194/-39)
   - crates/zp-crypto/src/kex.rs (+1/-0)
   - tests/conformance/crypto_test.rs (+40/-0)

   Complexity: MEDIUM (3 files, 235 insertions)
   Test coverage: EXCELLENT (9 tests added)
   Spec compliance: FIPS 203, zp spec §4.2 (ZP_PQC_2/ZP_HYBRID_2)
   Security: Requires crypto-impl audit approval

2. docs: update CHANGELOG and NEXT_TASKS for ML-KEM-1024
   Files (2):
   - docs/CHANGELOG.md (+49/-2)
   - NEXT_TASKS.md (+34/-18)

   Complexity: LOW (2 files, documentation only)
   Type: Documentation
   Purpose: Document Task 2.8 completion, update cipher suite status
```

## 5. ZP-SPECIFIC ANALYSIS

### Spec Compliance Check

```bash
# Check for spec references in changes
SPEC_REFS=$(git diff | grep -c "spec §\|Spec §\|per spec\|FIPS\|RFC\|zp_specification" || echo "0")

# Check for test vector references
VECTOR_REFS=$(git diff | grep -c "TEST_VECTORS.md\|test vector\|RFC.*vector" || echo "0")

# Check for DA decision references
DA_REFS=$(git diff | grep -c "DA-\|Design Authority\|docs/decisions" || echo "0")
```

**Report:**
```
📋 Spec compliance analysis:
   - Spec references: 8 (FIPS 203 ×3, zp spec §4.2 ×2, RFC 5903 ×1, TEST_VECTORS.md §1.3 ×2)
   - Test vectors: 2 (RFC 5903 test vectors, TEST_VECTORS.md conformance)
   - DA decisions: 0 (none referenced - OK if no design decisions)

Compliance status: GOOD ✅
```

### Crypto Changes Analysis

```bash
# If crypto files changed
if git diff --name-only | grep -q "crates/zp-crypto"; then
    echo "🔐 Crypto changes detected:"
    echo ""

    # Check for Zeroizing usage
    ZERO_ADDS=$(git diff crates/zp-crypto | grep "^+.*Zeroizing" | wc -l)
    ZERO_TOTAL=$(grep -r "Zeroizing" crates/zp-crypto/src/ 2>/dev/null | wc -l)

    # Check for error handling
    RESULT_ADDS=$(git diff crates/zp-crypto | grep "^+.*Result<" | wc -l)

    # Check for test additions
    TEST_ADDS=$(git diff tests/ crates/zp-crypto/src/ | grep "^+.*#\[test\]" | wc -l)

    # Check for unsafe code (should be 0)
    UNSAFE_ADDS=$(git diff crates/zp-crypto | grep "^+.*unsafe" | grep -v "forbid(unsafe" | wc -l)

    # Check for conformance test updates
    CONFORMANCE_UPDATES=$(git diff tests/conformance/ | grep -c "^+" || echo "0")

    echo "  - Zeroizing usage: +$ZERO_ADDS new (total: $ZERO_TOTAL in codebase)"
    echo "  - Error handling: +$RESULT_ADDS new Result<> usages"
    echo "  - Test additions: +$TEST_ADDS new tests"
    echo "  - Unsafe code: $UNSAFE_ADDS (must be 0)"
    echo "  - Conformance tests: $CONFORMANCE_UPDATES lines updated"
    echo ""

    if [ $UNSAFE_ADDS -gt 0 ]; then
        echo "  ❌ WARNING: Unsafe code added to zp-crypto!"
        echo "     zp-crypto has #![forbid(unsafe_code)]"
        echo "     This would BLOCK commit"
    else
        echo "  ✅ No unsafe code added"
    fi

    echo ""
    echo "  ⚠️  REMINDER: Run /audit zp-crypto before committing"
    echo "              Verify crypto-impl approval documented in CHANGELOG"
fi
```

## 6. EXECUTION PLAN

**If this were a real commit, would execute:**

```
Step 1: Pre-flight
   → cargo fmt --all
   → cargo clippy --fix --allow-dirty
   → cargo clippy -- -D warnings (verify)
   → cargo build --all

Step 2: Tests
   → cargo test --all

Step 3: Cleanup
   → Remove 0 dbg!() calls
   → Delete 0 temp files
   → (No crypto logging violations)

Step 4: Commits
   → git add crates/zp-crypto/src/kex/ml_kem.rs crates/zp-crypto/src/kex.rs tests/conformance/crypto_test.rs
   → git commit -m "feat(crypto): implement ML-KEM-1024 for ZP_HYBRID_2 cipher suite"

   → git add docs/CHANGELOG.md NEXT_TASKS.md
   → git commit -m "docs: update CHANGELOG and NEXT_TASKS for ML-KEM-1024"

Step 5: Summary
   → Display commit SHAs and stats
```

## 7. RECOMMENDATIONS

Based on analysis:

```
✅ READY TO COMMIT:
   - Pre-flight checks would pass
   - Code changes are well-tested (9 new tests)
   - Documentation updated (CHANGELOG, NEXT_TASKS)
   - Changes are logically grouped (feat + docs)
   - Spec compliance verified (FIPS 203, zp spec §4.2)

⚠️  RECOMMENDED ACTIONS:
   1. Verify crypto-impl audit approval in CHANGELOG (/audit zp-crypto)
   2. Review proposed commit messages (shown above)
   3. Run: /smart-commit (execute the plan)

🔐 SECURITY CHECKLIST (for crypto changes):
   - [x] No unsafe code added (verified)
   - [x] Secrets wrapped in Zeroizing<> (+3 new usages)
   - [ ] crypto-impl audit approval in CHANGELOG (verify manually)
   - [x] Spec references present (FIPS 203, RFC 5903)
   - [x] Test vectors used (TEST_VECTORS.md §1.3)

📊 ESTIMATED TIME:
   - Pre-flight + tests: ~2-3 minutes
   - Cleanup: ~10 seconds (minimal cleanup needed)
   - Commit execution: ~10 seconds
   - Total: ~3-4 minutes
```

## 8. COMPARISON WITH ALTERNATIVES

```
COMMAND                 ANALYSIS  COMMIT  PUSH
---------------------------------------------
/smart-commit-dry       ✅ Yes    ❌ No   ❌ No   ← YOU ARE HERE
/smart-commit           ✅ Yes    ✅ Yes  ❌ No
/smart-commit-quick     ⚠️ Min    ✅ Yes  ❌ No
/smart-push             ❌ No     ❌ No   ✅ Yes
Manual git              ❌ No     ✅ Yes  ✅ Yes
```

**Decision tree:**
- Want to see plan first? → `/smart-commit-dry` (current command)
- Ready to commit? → `/smart-commit`
- Need quick WIP commit? → `/smart-commit-quick`
- Ready to push? → `/smart-push`

---

**This is a DRY-RUN.** No files modified, no commits created.

To execute, run: `/smart-commit` or `/smart-commit-quick`
