---
description: Quick push with minimal checks (skip tests, basic validation only)
argument-hint: none
allowed-tools: Bash, AskUserQuestion
---

You are a **Quick Push Assistant** for the ZP protocol implementation.

Execute fast push workflow (skip tests, minimal checks):

## 1. PRE-PUSH CHECKS

```bash
# Get current branch
BRANCH=$(git branch --show-current)
echo "📍 Current branch: $BRANCH"

# Fetch latest from origin
git fetch origin

# Check if behind remote
git status -sb
```

**Check if behind remote:**
- If output contains `[behind N]` → Use AskUserQuestion to prompt:
  - Question: "Local branch is N commits behind remote. Rebase first?"
  - Options: "Yes, rebase" / "No, force push (dangerous)" / "Cancel"
  - If "Yes" → Run `git pull --rebase` then retry push
  - If "No" → Continue with force push warning
  - If "Cancel" → Abort

**Check if pushing to main branch:**
- If branch is `main` → Use AskUserQuestion:
  - Question: "Pushing directly to main. ZP is a research/prototype project. Continue?"
  - Options: "Yes, main is our primary branch" / "Cancel"
  - If "Cancel" → Abort with suggestion: "Consider using feature branch for experimental work"

## 2. MINIMAL QUALITY CHECKS

```bash
# Quick validation (no fixes, just verify)
echo "Running minimal quality checks..."

# 1. Format check (no auto-fix)
cargo fmt --all --check

# 2. Clippy check (no fix, just validate)
cargo clippy --all-targets --all-features -- -D warnings

# 3. Build check
cargo build --all
```

**On failure:**
- Abort push with message: "Quick checks failed. Fix issues or use /smart-push --no-test to skip entirely."
- Show which check failed (format/clippy/build)
- Provide fix commands

**On success:**
- Report: "✅ Quick checks passed (format, clippy, build)"
- Continue to push

### ZP-Specific Warning Checks

```bash
# Warn on crypto changes (don't block, just inform)
if git diff --name-only origin/$BRANCH..HEAD | grep -q "crates/zp-crypto"; then
    echo "⚠️  Crypto changes detected"
    echo "    /smart-push-quick skips full test suite"
    echo "    Ensure you've already validated with /check or /smart-commit"

    # Check for crypto-impl approval in CHANGELOG (warn only)
    if ! git diff origin/$BRANCH..HEAD -- docs/CHANGELOG.md | grep -q "crypto-impl.*APPROVED"; then
        echo "⚠️  No crypto-impl approval found in CHANGELOG diff"
        echo "    Verify /audit was run before this push"
    fi

    # Check for unsafe code (hard fail even in quick mode)
    if git diff origin/$BRANCH..HEAD -- crates/zp-crypto/ | grep -q "^+.*unsafe"; then
        echo "❌ ERROR: Unsafe code added to zp-crypto"
        echo "    zp-crypto has #![forbid(unsafe_code)]"
        echo "    This push is BLOCKED for security reasons"
        exit 1
    fi
fi
```

## 3. PUSH

```bash
# Push to origin
git push origin "$BRANCH"
```

**On push failure (rejected):**

Check error message:
- If contains "rejected" → Report: "Push rejected. Remote has changes. Run: git pull --rebase"
- If contains "no upstream" → Run: `git push -u origin "$BRANCH"` (set upstream)
- Other errors → Report error and abort

**On success:**
- Report: "✅ Pushed N commits to origin/$BRANCH"
- Show commit SHAs pushed

## 4. POST-PUSH

### For feature branches (not main):

```bash
# Check if gh CLI installed
which gh
```

**If gh installed:**
- Use AskUserQuestion:
  - Question: "Create pull request?"
  - Options: "Yes, create PR" / "No, just push"

**If "Yes, create PR":**

Generate PR from commit messages:

```bash
# Get commits since main
git log --oneline origin/main..HEAD

# Extract commit messages
git log --pretty=format:"%s" origin/main..HEAD
```

**Build PR title and body:**
- Title: Use first commit message if only 1 commit, else summarize scope
- Body: List all commit messages with bullets

**Create PR:**

```bash
gh pr create --title "<title>" --body "$(cat <<'EOF'
## Summary
<commit messages as bullets>

## Pre-Push Checks (Quick Mode)
- ✅ Format check passed
- ✅ Clippy passed (0 warnings)
- ✅ Build successful
- ⚠️  Full test suite skipped (quick push)

## Notes
This PR was pushed using /smart-push-quick (minimal validation).
Full test suite should be run by CI or verified locally before merge.

## Spec Compliance
- [ ] All changes comply with zp specification v1.0
- [ ] Test vectors verified (if applicable)
- [ ] DA decisions followed (if applicable)

## Security (if crypto changes)
- [ ] crypto-impl agent review: APPROVED
- [ ] All secrets wrapped in Zeroizing<>
- [ ] Zero unsafe code
- [ ] Constant-time operations verified (where required)

## Checklist
- [ ] CI checks pass (verify after push)
- [ ] Documentation updated (CHANGELOG, NEXT_TASKS)
- [ ] No breaking changes (or documented)
- [ ] Spec references added to code comments
EOF
)"
```

**Report PR URL** returned by gh

### For all pushes:

```bash
# Get repository info
REPO_URL=$(git remote get-url origin | sed 's/.*:\(.*\)\.git/\1/' | sed 's/.*\/\([^/]*\/[^/]*\)$/\1/')
```

**Show links:**
```
🔗 Links:
   - Commits: https://github.com/$REPO_URL/commits/$BRANCH
   - CI: https://github.com/$REPO_URL/actions
```

## 5. SUMMARY REPORT

```
✅ Quick push successful

📤 Pushed: 2 commits to origin/main
   - a1b2c3d feat(crypto): implement ML-KEM-1024 for ZP_HYBRID_2
   - d4e5f6g docs: update CHANGELOG and NEXT_TASKS for ML-KEM-1024

📊 Pre-push:
   - Behind remote: ✅ Up to date
   - Quick checks: ✅ Passed (format, clippy, build)
   - Full tests: ⚠️  SKIPPED (quick mode)
   - Branch: main

⚠️  Crypto changes detected:
   - crypto-impl approval: ⚠️  Not verified in this push
   - Unsafe code: ✅ None added
   - Full test validation: ⚠️  Skipped (ensure CI passes)

🔗 Links:
   - Commits: https://github.com/yourorg/zp/commits/main
   - CI: https://github.com/yourorg/zp/actions

⚠️  REMINDER: Quick push skips test suite. Monitor CI for test results.
```

## 6. EXAMPLES

**Quick push after local validation:**
```
# Already validated locally
/check
# ... all tests pass ...

# Now push quickly without re-running tests
/smart-push-quick
```

**Documentation-only push:**
```
# Only changed *.md files
/smart-push-quick
# ✅ Perfect use case - no tests needed
```

**After WIP commits:**
```
# Made several WIP commits with /smart-commit-quick
/smart-commit-quick "WIP: feat(crypto): implement feature"
/smart-commit-quick "WIP: test(crypto): add tests"

# Now ready to push
/smart-push-quick
```

## 7. USE CASES

### When to Use /smart-push-quick:

✅ **Good for:**
- Already validated locally with /check or /smart-commit
- Documentation-only changes (*.md files)
- Non-critical changes where CI will catch issues
- Quick iteration during development
- When you trust your local validation
- Pushing after successful /smart-commit (pre-flight already passed)

❌ **Do NOT use for:**
- **First push of the day** (use /smart-push for full validation)
- **Crypto changes without local testing** (always run /check first)
- **Complex multi-crate changes** (use /smart-push for comprehensive validation)
- **When you skipped local testing** (use /smart-push instead)
- **Production-critical code** (use /smart-push with full quality gate)

### Comparison with /smart-push:

| Check | /smart-push-quick | /smart-push |
|-------|-------------------|-------------|
| Format | ✅ Check only | ✅ Check only |
| Clippy | ✅ Check only | ✅ Check + report |
| Build | ✅ Yes | ✅ Yes |
| Tests | ❌ No | ✅ Yes (unless --no-test) |
| Crypto audit check | ⚠️ Warn only | ✅ Verify in CHANGELOG |
| Commit grouping | ❌ No | ❌ No |
| Time | ~30 seconds | ~2-5 minutes |

**Decision tree:**
- Already ran /check or /smart-commit? → `/smart-push-quick` ✅
- First time pushing this code? → `/smart-push`
- Documentation only? → `/smart-push-quick` ✅
- Crypto changes? → `/smart-push` (with full tests)
- Not sure? → `/smart-push` (better safe than sorry)

## 8. SAFETY FEATURES

- ✅ Still checks format (catches formatting issues)
- ✅ Still runs clippy (catches most code quality issues)
- ✅ Still builds (catches compilation errors)
- ✅ Still blocks unsafe code in zp-crypto (critical security check)
- ✅ Still fetches and checks if behind remote
- ✅ Still warns on main branch pushes
- ✅ Still prompts before force push
- ⚠️ Skips tests (you must validate locally first)
- ⚠️ Warns on crypto changes (but doesn't block)
- ⚠️ Doesn't verify crypto-impl approval (just warns)

**Remember:** This is for speed when you've already validated. Always ensure CI passes after push!

## 9. ERROR HANDLING

**Quick checks failure:**
```
❌ Quick validation failed

Failed checks:
- ❌ Clippy: 2 warnings in zp-transport
- ✅ Format: passed
- ✅ Build: passed

Fix: cargo clippy -p zp-transport --fix
Then: /smart-push-quick (or /smart-push for full validation)
```

**Crypto safety violation (unsafe code):**
```
❌ ERROR: Unsafe code added to zp-crypto
    crates/zp-crypto/src/kex/ml_kem.rs:142: unsafe { ... }

    zp-crypto has #![forbid(unsafe_code)] directive.
    This push is BLOCKED even in quick mode.

Fix: Remove unsafe code from zp-crypto
Then: cargo build -p zp-crypto
Then: /smart-push-quick
```

**Behind remote:**
```
⚠️  Local branch is 2 commits behind origin/main

Rebase first?
  1. Yes, rebase (recommended)
  2. No, force push (DANGEROUS)
  3. Cancel

Recommendation: Select 1 (rebase) unless you know what you're doing.
```

**Crypto changes without local testing:**
```
⚠️  Crypto changes detected

/smart-push-quick skips test suite.
Have you validated locally?
  1. Yes, I ran /check or /smart-commit (continue push)
  2. No, run tests first (recommended)
  3. Cancel

If you select 1, ensure CI passes after push.
If you select 2, run /check then /smart-push-quick.
```

## 10. WORKFLOW INTEGRATION

**Typical development flow:**

```bash
# Morning: Start work
git pull
/check  # Full validation

# Implement feature
# ... write code ...
/smart-commit-quick "WIP: implement feature"  # Quick checkpoint

# Continue work
# ... write tests ...
/smart-commit-quick "WIP: add tests"  # Another checkpoint

# Ready to push
/check  # Validate one more time locally
/smart-push-quick  # Fast push (tests already validated)

# Monitor CI
# Check GitHub Actions for test results
```

**Alternative: Full validation flow:**

```bash
# Implement feature
# ... write code and tests ...

# Full validation + commit
/smart-commit  # Runs all checks, groups commits intelligently

# Full validation + push
/smart-push  # Runs all checks again (redundant if just ran /smart-commit)

# OR: Quick push after smart-commit
/smart-push-quick  # Skip redundant checks (already validated by /smart-commit)
```

**Best practice:** Use `/smart-commit` for local commits (full validation), then `/smart-push-quick` for push (skip redundant validation).
