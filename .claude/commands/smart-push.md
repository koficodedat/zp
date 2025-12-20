---
description: Smart push with pre-push checks, tests, and optional PR creation
argument-hint: [--no-test]
allowed-tools: Bash, AskUserQuestion
---

You are a **Smart Push Assistant** for the ZP protocol implementation.

Execute the following workflow:

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

## 2. ZP QUALITY GATE (skip if --no-test argument provided)

If `--no-test` NOT in arguments:

```bash
# Run ZP quality checks
echo "Running ZP quality gate..."

# 1. Format check
cargo fmt --all --check

# 2. Clippy (must be clean)
cargo clippy --all-targets --all-features -- -D warnings

# 3. Build
cargo build --all

# 4. Tests
cargo test --all
```

**On failure:**
- Abort push with message: "ZP quality gate failed. Fix before pushing or use --no-test to skip."
- Show failure summary (format/clippy/tests/build)
- Provide fix commands

**On success:**
- Report: "✅ ZP quality gate passed (format, clippy, build, tests)"
- Continue to push

### ZP-Specific Gate Checks

**If pushing crypto changes:**
```bash
# Check if crypto files changed
if git diff --name-only origin/$BRANCH..HEAD | grep -q "crates/zp-crypto"; then
    echo "🔐 Crypto changes detected - verifying crypto-impl audit..."

    # Verify crypto-impl approval in CHANGELOG
    if ! git diff origin/$BRANCH..HEAD -- docs/CHANGELOG.md | grep -q "crypto-impl.*APPROVED"; then
        echo "⚠️  WARNING: Crypto changes without crypto-impl approval in CHANGELOG"
        echo "    Verify /audit zp-crypto was run and approval documented"
    else
        echo "✅ crypto-impl audit approval found in CHANGELOG"
    fi

    # Check for unsafe code in crypto (forbidden)
    if git diff origin/$BRANCH..HEAD -- crates/zp-crypto/ | grep -q "^+.*unsafe"; then
        echo "❌ ERROR: Unsafe code added to zp-crypto"
        echo "    zp-crypto has #![forbid(unsafe_code)]"
        echo "    Abort push and remove unsafe code"
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

## Spec Compliance
- [x] All changes comply with zp specification v1.0
- [x] Test vectors verified (if applicable)
- [x] DA decisions followed (if applicable)

## Pre-Push Quality Gate
- ✅ Format check passed
- ✅ Clippy passed (0 warnings)
- ✅ All tests passing (N tests)
- ✅ Build successful

## Security (if crypto changes)
- [x] crypto-impl agent review: APPROVED
- [x] All secrets wrapped in Zeroizing<>
- [x] Zero unsafe code
- [x] Constant-time operations verified (where required)

## Checklist
- [x] CI checks pass locally
- [x] Documentation updated (CHANGELOG, NEXT_TASKS)
- [x] No breaking changes (or documented)
- [x] Spec references added to code comments

## Cipher Suite Impact (if applicable)
<Note which cipher suites are affected or enabled>
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
✅ Push successful

📤 Pushed: 2 commits to origin/main
   - a1b2c3d feat(crypto): implement ML-KEM-1024 for ZP_HYBRID_2
   - d4e5f6g docs: update CHANGELOG and NEXT_TASKS for ML-KEM-1024

📊 Pre-push:
   - Behind remote: ✅ Up to date
   - Quality gate: ✅ All passing (format, clippy, tests, build)
   - Branch: main

🔐 Crypto validation:
   - crypto-impl approval: ✅ Found in CHANGELOG
   - Unsafe code: ✅ None added
   - Zeroization: ✅ All secrets wrapped

🔗 Links:
   - Commits: https://github.com/yourorg/zp/commits/main
   - CI: https://github.com/yourorg/zp/actions

Next: Monitor CI, continue development, or create release
```

## 6. EXAMPLES

**Push with full quality gate:**
```
/smart-push
```

**Push without quality gate (fast, when already validated):**
```
/smart-push --no-test
```

**Force push scenario (behind remote):**
```
User: /smart-push
Assistant: Local branch is 2 commits behind remote. Rebase first?
  1. Yes, rebase
  2. No, force push (dangerous)
  3. Cancel

User selects: 1
Assistant: Rebasing... Done. Pushing...
```

**Crypto changes without approval:**
```
User: /smart-push
Assistant:
📤 Preparing to push...
🔐 Crypto changes detected - verifying crypto-impl audit...
⚠️  WARNING: Crypto changes without crypto-impl approval in CHANGELOG
    Verify /audit zp-crypto was run and approval documented

Continue anyway?
  1. Yes, I've verified approval offline
  2. No, cancel and add approval to CHANGELOG

User selects: 2
Assistant: Push cancelled. Add crypto-impl approval to CHANGELOG.md first.
```

## 7. SAFETY FEATURES

- ✅ Always fetch before checking status
- ✅ Warn on main branch pushes (but allow for research project)
- ✅ Prompt before force push
- ✅ Run full quality gate before pushing (format, clippy, tests, build) unless --no-test
- ✅ Verify crypto-impl approval for crypto changes
- ✅ Block pushes with unsafe code in zp-crypto
- ✅ Automatic upstream setup for new branches
- ⚠️ NEVER force push without explicit user confirmation

## 8. ZP-SPECIFIC NOTES

### Quality Gate Threshold:
- **Format**: Must pass (cargo fmt --check)
- **Clippy**: Must pass with -D warnings (zero warnings)
- **Build**: Must succeed (all crates)
- **Tests**: Must pass (all non-ignored tests)

### Crypto Changes Require:
- crypto-impl agent approval documented in CHANGELOG
- No unsafe code added
- All secrets zeroized
- Spec references for algorithms

### When to Skip Quality Gate (--no-test):
- Documentation-only changes (*.md files)
- Already validated locally with /check
- Quick iteration on non-critical code
- **NEVER for crypto changes** - always run full gate

### PR Body Checklist Explanation:
- **Spec Compliance**: All code follows zp_specification_v1.0.md
- **Test Vectors**: Conformance tests use TEST_VECTORS.md or RFC vectors
- **DA Decisions**: Any design choices reference DA decisions from docs/decisions/
- **Security**: For crypto, verify crypto-impl audit approval
- **Cipher Suite Impact**: Note which of 4 suites (ZpHybrid1/2/3, ZpClassical2) are affected

## 9. ERROR HANDLING

**Quality gate failure:**
```
❌ ZP quality gate failed

Failed checks:
- ❌ Clippy: 3 warnings in zp-crypto
- ✅ Format: passed
- ✅ Build: passed
- ✅ Tests: passed

Fix: cargo clippy -p zp-crypto --fix
Then: /smart-push (or /smart-push --no-test if confident)
```

**Crypto safety violation:**
```
❌ ERROR: Unsafe code added to zp-crypto
    crates/zp-crypto/src/kex/ml_kem.rs:142: unsafe { ... }

    zp-crypto has #![forbid(unsafe_code)] directive.
    This push is BLOCKED for security reasons.

Fix: Remove unsafe code from zp-crypto
Then: cargo test -p zp-crypto
Then: /smart-push
```

**Behind remote:**
```
⚠️  Local branch is 3 commits behind origin/main

Rebase first?
  1. Yes, rebase (recommended)
  2. No, force push (DANGEROUS - will lose remote commits)
  3. Cancel

Recommendation: Select 1 (rebase) unless you know what you're doing.
Force push will permanently delete the 3 remote commits.
```
