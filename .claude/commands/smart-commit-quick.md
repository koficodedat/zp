---
description: Quick commit with minimal checks (skip tests, basic cleanup only)
argument-hint: [commit-message]
allowed-tools: Bash, Read, Grep
---

You are a **Quick Commit Assistant** for the ZP protocol implementation.

Execute fast pre-commit workflow (skip tests, minimal cleanup):

## 1. ESSENTIAL CHECKS ONLY

```bash
# Auto-fix formatting
cargo fmt --all

# Clippy check (no fix attempts, just validate)
cargo clippy --all-targets --all-features -- -D warnings

# Quick build check
cargo build --all
```

**Abort if clippy or build fails.** Report errors.

## 2. MINIMAL CLEANUP

```bash
# Only remove obvious artifacts
find . -type f \( -name "*.orig" -o -name "*.bak" -o -name ".DS_Store" \) ! -path "*/target/*" -delete

# Count dbg! calls (report only, don't remove)
DBG_COUNT=$(grep -r "dbg!" --include="*.rs" crates/*/src/ 2>/dev/null | wc -l)
if [ $DBG_COUNT -gt 0 ]; then
    echo "ℹ️  Found $DBG_COUNT dbg!() calls (will be cleaned in full commit)"
fi

# ZP-specific: Warn if logging in crypto code (don't block, just warn)
CRYPTO_LOGS=$(grep -r "println!\|eprintln!\|log::" --include="*.rs" crates/zp-crypto/src/ 2>/dev/null | grep -v test | wc -l)
if [ $CRYPTO_LOGS -gt 0 ]; then
    echo "⚠️  WARNING: Found $CRYPTO_LOGS log statements in zp-crypto"
    echo "    These will block a full commit. Remove before /smart-commit"
fi
```

**Report:** Temp files removed, dbg! count (if any), crypto warnings (if any)

## 3. SMART COMMIT

If `$ARGUMENTS` provided (custom message):
```bash
git add -A
git commit -m "$ARGUMENTS"
```

Else, analyze changes and create descriptive commit:

```bash
# Analyze what changed
git status --porcelain
git diff --stat --cached
```

**Auto-categorize:**
- New files → `feat` or `test` (if in tests/)
- Modified tests → `test`
- Modified docs → `docs`
- Modified crates/zp-crypto → `feat(crypto)` or `fix(crypto)`
- Modified crates/zp-transport → `feat(transport)` or `fix(transport)`
- Modified crates/zp-core → `feat(core)` or `fix(core)`
- Multiple crates → `refactor` or `chore`

**Create single commit** with appropriate prefix:
```bash
git add -A
git commit -m "<prefix>(<scope>): <inferred-message>"
```

**Message inference:**
- Use file paths to determine scope (crypto, transport, core, etc.)
- Use git diff summary to describe changes
- Keep under 50 characters
- Present tense
- Add "WIP: " prefix if changes are incomplete

**Examples of inferred messages:**
```
# If only modified crates/zp-crypto/src/kex/ml_kem.rs
→ "feat(crypto): update ML-KEM-1024 implementation"

# If modified multiple test files
→ "test(crypto): add ML-KEM-1024 test coverage"

# If modified docs/CHANGELOG.md
→ "docs: update CHANGELOG"

# If changes incomplete or experimental
→ "WIP: feat(crypto): ML-KEM-1024 implementation"

# If modified Cargo.toml files
→ "chore: update dependencies"

# If modified .github/ workflows
→ "chore(ci): update GitHub Actions workflow"
```

## 4. QUICK SUMMARY

```
✅ Committed: a1b2c3d feat(crypto): update ML-KEM-1024 implementation

📊 Quick checks:
   - Format: ✅ Clean
   - Clippy: ✅ 0 warnings
   - Build: ✅ Success

🧹 Cleanup: 2 temp files removed

⚠️  Warnings: 1 dbg!() call found (non-blocking)

⏭️  Skipped: Full tests, crypto audit verification
    Use /smart-commit for full validation before pushing
```

## 5. USE CASES

### When to Use /smart-commit-quick:

✅ **Good for:**
- WIP commits during active development
- Small, obvious changes (typo fixes, formatting)
- Documentation updates
- When you've already run tests manually
- Iterating on implementation quickly
- Experimental code that's not ready for review

❌ **Do NOT use for:**
- **Final commits before PR** (use /smart-commit)
- **Crypto code changes** (always use /smart-commit + /audit)
- **Complex multi-file changes** (use /smart-commit for proper grouping)
- **Before pushing to remote** (use /smart-commit + /smart-push)
- **Spec-compliant implementations** (use /smart-commit for full validation)

### Common Workflows:

**Scenario 1: WIP during Task implementation**
```bash
# Implementing Task 2.8, want to checkpoint progress
/smart-commit-quick "WIP: feat(crypto): ML-KEM-1024 key generation"

# Continue implementing...
/smart-commit-quick "WIP: feat(crypto): ML-KEM-1024 encapsulate/decapsulate"

# Done with implementation, now do full commit:
git reset HEAD~2  # Undo WIP commits
/smart-commit     # Create proper feat + test + docs commits
```

**Scenario 2: Quick doc update**
```bash
# Fixed typo in README
/smart-commit-quick

# Auto-infers: "docs: fix typo in README"
# ✅ Safe because docs-only, no tests needed
```

**Scenario 3: Small fix during development**
```bash
# Fixed obvious bug while implementing feature
/smart-commit-quick "fix(crypto): handle zero-length input"

# Continue with feature work...
```

## 6. ZP-SPECIFIC NOTES

### Crypto Code Warning:
If you modify zp-crypto and use /smart-commit-quick, you'll see:
```
⚠️  WARNING: Crypto changes detected
    /smart-commit-quick skips:
    - Full test suite
    - crypto-impl audit verification
    - Zeroization checks

    For final commit, use:
    1. /audit zp-crypto (verify security)
    2. /smart-commit (full validation)
```

### Custom Message Format:
```bash
# Provide your own message
/smart-commit-quick "feat(crypto): add ML-KEM-1024 decapsulation"

# Or let it infer (recommended for quick WIP)
/smart-commit-quick
```

### Quick vs Full Commit Comparison:

| Check | /smart-commit-quick | /smart-commit |
|-------|---------------------|---------------|
| Format | ✅ Yes | ✅ Yes |
| Clippy | ✅ Yes | ✅ Yes |
| Build | ✅ Yes | ✅ Yes |
| Tests | ❌ No | ✅ Yes |
| Cleanup (dbg!) | ⚠️ Warn only | ✅ Auto-remove |
| Crypto logging check | ⚠️ Warn only | ❌ Hard fail |
| Commit grouping | ❌ Single commit | ✅ Logical groups |
| Time | ~30 seconds | ~2-5 minutes |

## 7. SAFETY FEATURES

- ✅ Still runs clippy (catches most code quality issues)
- ✅ Still builds (catches compilation errors)
- ✅ Still formats code (maintains consistency)
- ⚠️ Skips tests (you must run manually)
- ⚠️ Warns on crypto changes (but doesn't block)
- ⚠️ Single commit only (no intelligent grouping)

**Remember:** This is for speed during development. Always use /smart-commit before pushing!

## 8. EXAMPLES

**Example 1: Auto-inferred message**
```
User: /smart-commit-quick