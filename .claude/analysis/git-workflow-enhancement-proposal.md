# Git Workflow Enhancement Proposal for ZP

**Date:** 2025-12-20
**Source Analysis:** Lang project `.claude/commands/` workflow
**Target:** ZP protocol implementation
**Status:** Proposal for enhanced git automation

---

## Executive Summary

After analyzing the Lang project's git workflow commands, I've identified **5 high-value automation patterns** that would significantly enhance the ZP project's development velocity while maintaining the superior quality gates already in place.

**Key Recommendation:** Adopt Lang's tiered commit/push workflow (`smart-commit`, `smart-commit-quick`, `smart-push`) while preserving ZP's superior domain-specific commands (spec, vector, decision, audit).

---

## Current State Analysis

### ZP Project Strengths (Superior to Lang)

| Feature | Status | Quality |
|---------|--------|---------|
| **Domain Commands** | ✅ Excellent | Spec compliance, test vectors, DA escalation |
| **Security Review** | ✅ Superior | crypto-impl agent integration |
| **Quality Gates** | ✅ Excellent | `/check`, `/audit`, `/bench`, `/fuzz` |
| **Documentation** | ✅ Superior | CLAUDE.md, workflow-driven development |
| **Feature Workflow** | ✅ Excellent | `/new-feature` structured approach |

**ZP Advantages:**
1. **Spec-driven development** (`/spec`, `/vector`, `/decision`) - Lang doesn't have this
2. **Crypto-specific review** (`crypto-impl agent`) - Domain expertise Lang lacks
3. **Design Authority integration** (`/escalate`) - Formal decision-making process
4. **Structured feature workflow** (`/new-feature` with checklist) - More rigorous than Lang

### ZP Project Gaps (Lang Does Better)

| Feature | ZP Status | Lang Status | Impact |
|---------|-----------|-------------|--------|
| **Smart Commit** | ❌ Missing | ✅ Excellent | Medium-High |
| **Smart Push** | ❌ Missing | ✅ Excellent | Medium-High |
| **Commit Dry-Run** | ❌ Missing | ✅ Good | Medium |
| **Code Review** | ⚠️ Partial | ✅ Comprehensive | Medium |
| **Pre-Phase Gates** | ⚠️ Informal | ✅ Formal | Low (ZP has DA) |

---

## Proposed Enhancements

### Tier 1: High Priority (Immediate Value)

#### 1. `/smart-commit` - Intelligent Commit Workflow

**What it does:**
- Runs pre-flight checks (format, clippy, build)
- Optionally runs tests (skip with `--quick`)
- Auto-cleanup (dbg!, temp files, .DS_Store)
- Analyzes changes and proposes logical commit grouping
- Creates conventional commits (feat/fix/docs/test/chore/perf/refactor)

**ZP-Specific Adaptations:**

```markdown
## ZP Smart Commit Additions

### Pre-Flight Checks
```bash
# Standard checks (same as Lang)
cargo fmt --all
cargo clippy --all-targets --all-features --fix --allow-dirty -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo build --all

# ZP-specific: Verify spec compliance markers
grep -r "MUST\|SHOULD\|MAY" crates/zp-*/src/ | wc -l  # Report only
```

### Cleanup Scan (ZP-Enhanced)
```bash
# Standard cleanup (from Lang)
grep -r "dbg!" --include="*.rs" crates/*/src/ | grep -v test
find . -type f \( -name "*.orig" -o -name "*.bak" -o -name ".DS_Store" \) ! -path "*/target/*"

# ZP-specific: Check for crypto logging violations
grep -r "println!\|eprintln!\|log::" --include="*.rs" crates/zp-crypto/src/ | grep -v test
# Fail build if found in crypto code - security critical!

# ZP-specific: Verify zeroization usage
grep -r "Zeroizing" crates/zp-crypto/src/ | wc -l  # Report count
```

### Commit Message Format (ZP-Adapted)
```
feat(crypto): implement ML-KEM-1024 for ZP_HYBRID_2
fix(transport): handle QUIC connection migration edge case
docs(spec): update cipher suite table in CHANGELOG
test(conformance): add RFC 5903 ECDH-P256 vectors
chore(ci): add nightly MIRI test workflow
perf(crypto): optimize X25519 scalar multiplication
```

**NO attribution footers** (following Lang's clean approach):
- ❌ No "🤖 Generated with Claude Code"
- ❌ No "Co-Authored-By: Claude"
- ✅ Clean, professional commit messages only

### Proposed Commit Grouping Logic (ZP)

```
Group 1: feat(crypto): ML-KEM-1024 implementation
  - crates/zp-crypto/src/kex/ml_kem.rs
  - crates/zp-crypto/src/kex.rs
  - tests/conformance/crypto_test.rs

Group 2: test(crypto): comprehensive ML-KEM-1024 coverage
  - crates/zp-crypto/src/kex/ml_kem.rs (test module)
  [Only if tests are separate enough to warrant split]

Group 3: docs: update CHANGELOG and NEXT_TASKS
  - docs/CHANGELOG.md
  - NEXT_TASKS.md
```

**Proposed Command Location:**
`.claude/commands/smart-commit.md`

**Estimated Implementation:** 2-3 hours to adapt Lang template to ZP conventions

---

#### 2. `/smart-commit-quick` - Fast WIP Commits

**What it does:**
- Minimal checks (format + clippy + build)
- No tests (for speed)
- Single commit with auto-inferred message
- Perfect for WIP during development

**ZP Adaptation:**
```markdown
## ZP Quick Commit

### Checks (minimal)
- cargo fmt --all
- cargo clippy --all-targets -- -D warnings (no fix, just verify)
- cargo build --all

### Message Inference (ZP-specific)
- Modified crates/zp-crypto → "wip(crypto): ..."
- Modified crates/zp-transport → "wip(transport): ..."
- Modified docs/ → "docs: ..."
- Modified tests/ → "test: ..."

### Use Cases
- WIP commits during Task 2.8 implementation
- Small fixes during iteration
- When you know tests pass (ran manually)

### NOT for:
- Final commits before PR
- Commits touching crypto primitives (use full /smart-commit)
- Before pushing to remote
```

**Proposed Command Location:**
`.claude/commands/smart-commit-quick.md`

---

#### 3. `/smart-push` - Intelligent Push with Safety

**What it does:**
- Pre-push checks (fetch, check if behind remote)
- Optionally runs full CI (`--no-test` to skip)
- Warns on protected branch pushes (main/master)
- Prompts before force push
- Auto-creates PR with gh CLI
- Shows CI links after push

**ZP-Specific Enhancements:**

```markdown
## ZP Smart Push

### Pre-Push Checks (ZP-Enhanced)
```bash
# Standard (from Lang)
git fetch origin
git status -sb  # Check if behind remote

# ZP-specific: Verify Phase 2 quality gates before push
if [[ $(git branch --show-current) == "main" ]]; then
    echo "Pushing to main - verify Phase 2 complete:"
    cargo test -p zp-crypto --lib
    cargo clippy -p zp-crypto -- -D warnings
    # Verify all cipher suites complete
    grep -q "✅.*ZpHybrid1.*ZpHybrid2.*ZpHybrid3.*ZpClassical2" docs/CHANGELOG.md
fi
```

### Protected Branch Logic (ZP)
```
If branch == "main":
  - Prompt: "Pushing directly to main. This is a research/prototype project. Continue?"
  - Options: "Yes, main is our primary branch" / "Cancel"

If branch matches "feature/*" or "task-*":
  - OK, proceed normally
```

### PR Creation (ZP-Enhanced)
```bash
# If gh installed and not main branch
gh pr create --title "<title>" --body "$(cat <<'EOF'
## Summary
<commit messages as bullets>

## Spec Compliance
- [x] All changes comply with zp spec v1.0
- [x] Test vectors verified (if applicable)
- [x] DA decisions followed (if applicable)

## Quality Checks
- ✅ Format check passed
- ✅ Clippy passed (0 warnings)
- ✅ All tests passing
- ✅ Build successful

## Security (if crypto changes)
- [x] crypto-impl agent review: APPROVED
- [x] All secrets zeroized
- [x] No unsafe code added
- [x] Constant-time operations verified

## Checklist
- [x] CI checks pass locally
- [x] Documentation updated (CHANGELOG, NEXT_TASKS)
- [x] No breaking changes (or documented)
- [x] Spec references added to code comments
EOF
)"
```

**Proposed Command Location:**
`.claude/commands/smart-push.md`

---

#### 4. `/smart-commit-dry` - Analyze Before Committing

**What it does:**
- Shows what WOULD be committed (no changes)
- Predicts pre-flight check results
- Finds cleanup opportunities
- Proposes logical commit groups
- Estimates time for full commit

**ZP Value:**
- **Before major commits** (e.g., after completing Task 2.8)
- **Verify Phase 2 completion** before marking as done
- **Plan multi-commit workflows** (feature + tests + docs)

**ZP-Specific Analysis:**

```markdown
## ZP Dry-Run Additions

### Spec Compliance Check (Dry-Run)
```bash
# Check for spec references in code
git diff --cached | grep -c "spec §\|Spec §\|per spec"

# Verify test vectors referenced
git diff --cached crates/zp-crypto/ | grep -c "TEST_VECTORS.md"

# Report:
# "📋 Spec compliance: 12 spec references, 3 test vector references"
```

### Crypto-Specific Analysis
```bash
# If crypto files changed, verify patterns
if git diff --name-only | grep -q "crates/zp-crypto"; then
    echo "🔐 Crypto changes detected:"
    echo "  - Zeroizing usage: $(git diff --cached crates/zp-crypto | grep -c 'Zeroizing')"
    echo "  - Error handling: $(git diff --cached crates/zp-crypto | grep -c 'Result<')"
    echo "  - Test additions: $(git diff --cached tests/ | grep -c '+.*#\[test\]')"
    echo "  ⚠️  Remember: Run /audit zp-crypto before committing"
fi
```

**Proposed Command Location:**
`.claude/commands/smart-commit-dry.md`

---

### Tier 2: Medium Priority (Quality of Life)

#### 5. `/review-code` - Comprehensive Code Review

**What it does:**
- Two-phase review: Automated pre-flight + Manual inspection
- Pre-flight: clippy, tests, security, benchmarks
- Manual: 8-point framework (correctness, spec, quality, security, performance, testing, docs, integration)
- Categorized issues: Critical / Important / Minor / Suggestions
- Action items with effort estimates

**ZP Adaptation:**

```markdown
## ZP Code Review Framework

### Automated Pre-Flight (ZP-Enhanced)
```bash
# Standard checks
cargo clippy -p <crate> -- -D warnings
cargo test -p <crate>
cargo fmt --check

# ZP-specific: Crypto crate special handling
if [[ $CRATE == "zp-crypto" ]]; then
    # Verify crypto-impl agent approval exists
    grep -q "crypto-impl.*APPROVED" docs/CHANGELOG.md || echo "⚠️ Missing crypto-impl approval"

    # Check for unsafe code (should be forbidden)
    grep -r "unsafe" crates/zp-crypto/src/ && echo "❌ Unsafe code in crypto!"

    # Verify zeroization pattern
    grep -r "Zeroizing" crates/zp-crypto/src/ | wc -l
fi
```

### Manual Review (8-Point Framework + ZP Additions)
1. **Correctness** ← Same as Lang
2. **Spec Compliance** ← ZP CRITICAL (verify against zp_specification_v1.0.md)
3. **Code Quality** ← Same as Lang
4. **Security** ← ZP ENHANCED (crypto-specific checks)
5. **Performance** ← Same as Lang
6. **Testing** ← ZP ENHANCED (conformance test requirement)
7. **Documentation** ← ZP ENHANCED (spec references required)
8. **Integration** ← Same as Lang

**ZP-Specific Review Questions:**
- Does this match the zp specification exactly? (cite section)
- Are test vectors from TEST_VECTORS.md used?
- Is there a DA decision referenced? (if design choice)
- Are all crypto operations constant-time where required?
- Is secret material properly zeroized?

**Proposed Command Location:**
`.claude/commands/review-code.md`

---

#### 6. `/smart-push-quick` - Fast Push Without CI

**What it does:**
- Skip full CI checks (use when already validated)
- Minimal safety checks (fetch, check status)
- Fast push for small changes

**ZP Use Case:**
- Pushing doc updates
- Pushing after already running `/check` locally
- Quick iteration on non-critical code

**Proposed Command Location:**
`.claude/commands/smart-push-quick.md`

---

### Tier 3: Lower Priority (Future Consideration)

#### 7. `/pre-phase` - Phase Gate Validation

**Lang Implementation:**
- Validates previous phase completion
- Runs comprehensive quality checks
- Assesses technical debt
- Compares metrics to baseline
- Produces GO/NO-GO recommendation

**ZP Status:**
- ✅ **Already have Design Authority** (superior to Lang's phase gates)
- ✅ **Already have `/check` command** (automated validation)
- ⚠️ **Could formalize phase transitions**

**Recommendation:**
**DEFER** - ZP's DA process is already superior to Lang's phase gates.
If needed later, could create `/phase-complete` command that:
- Runs all quality checks
- Generates phase completion report
- Archives to `docs/phases/`
- But this is lower priority given DA exists

---

## Implementation Priority & Effort

| Command | Priority | Effort | Value | Rationale |
|---------|----------|--------|-------|-----------|
| `/smart-commit` | **P0** | 3h | ⭐⭐⭐⭐⭐ | Automates most tedious commit work |
| `/smart-push` | **P0** | 2h | ⭐⭐⭐⭐⭐ | Safety + automation for pushes |
| `/smart-commit-quick` | **P1** | 1h | ⭐⭐⭐⭐ | Fast iteration during development |
| `/smart-commit-dry` | **P1** | 2h | ⭐⭐⭐⭐ | Great for planning commits |
| `/review-code` | **P2** | 3h | ⭐⭐⭐ | Useful but `/audit` covers crypto |
| `/smart-push-quick` | **P2** | 1h | ⭐⭐⭐ | Nice-to-have for docs |
| `/pre-phase` | **P3** | 4h | ⭐⭐ | DA process is better |

**Total Effort (P0-P1):** ~8 hours
**Total Effort (P0-P2):** ~12 hours
**Total Effort (All):** ~16 hours

---

## Recommended Commit Message Format for ZP

### Conventional Commits (Adapted from Lang)

**Prefixes:**
- `feat` — New features (implementations of spec requirements)
- `fix` — Bug fixes
- `test` — Test-only changes (conformance, unit, integration)
- `docs` — Documentation (*.md, doc comments, spec references)
- `chore` — Build, CI, tooling
- `perf` — Performance improvements (benchmarks)
- `refactor` — Code restructuring without behavior change
- `security` — Security fixes or enhancements

**Scopes (ZP-Specific):**
- `crypto` — zp-crypto crate
- `transport` — zp-transport crate
- `core` — zp-core crate
- `platform` — zp-platform crate
- `ffi` — zp-ffi crate
- `conformance` — tests/conformance
- `spec` — Specification compliance
- `ci` — CI/CD
- `docs` — Documentation

**Examples:**
```
feat(crypto): implement ML-KEM-1024 for ZP_HYBRID_2 cipher suite
fix(transport): handle QUIC stream ID collision per spec \u00a73.4
test(conformance): add RFC 5903 ECDH-P256 test vectors
docs(spec): update CHANGELOG with ML-KEM-1024 implementation
chore(ci): add cargo-audit security scanning
perf(crypto): optimize ChaCha20-Poly1305 SIMD path
refactor(core): extract session management to dedicated module
security(crypto): verify constant-time operation for P-256
```

**Message Guidelines:**
- Max 50 characters for subject line
- Present tense ("add" not "added")
- No period at end
- Imperative mood ("fix bug" not "fixes bug")
- Reference spec sections where applicable
- **NO attribution footers** (clean, professional)

---

## Migration Strategy

### Phase 1: Core Automation (Week 1)
1. ✅ Create `/smart-commit` command
2. ✅ Create `/smart-push` command
3. ✅ Create `/smart-commit-quick` command
4. 📝 Update CLAUDE.md with new workflow
5. 🧪 Test on current Task 2.8 completion

### Phase 2: Enhancement (Week 2)
1. ✅ Create `/smart-commit-dry` command
2. ✅ Create `/smart-push-quick` command
3. 📝 Document usage patterns in CLAUDE.md

### Phase 3: Review Tools (Future)
1. ✅ Create `/review-code` command
2. 📝 Integrate with existing `/audit` workflow

---

## Example Workflow: Task 2.8 Completion

### Old Workflow (Manual)
```bash
# 1. Format
cargo fmt --all

# 2. Check clippy
cargo clippy --all-targets -- -D warnings

# 3. Run tests
cargo test -p zp-crypto

# 4. Update docs manually
vim docs/CHANGELOG.md
vim NEXT_TASKS.md

# 5. Stage files manually
git add crates/zp-crypto/src/kex/ml_kem.rs
git add crates/zp-crypto/src/kex.rs
git add tests/conformance/crypto_test.rs
git add docs/CHANGELOG.md
git add NEXT_TASKS.md

# 6. Write commit message manually
git commit -m "feat(crypto): implement ML-KEM-1024 for ZP_HYBRID_2 cipher suite"

# 7. Push manually
git push origin main
```

**Time:** ~15-20 minutes of manual work

### New Workflow (Automated)
```bash
# 1. Dry-run to see plan
/smart-commit-dry

# 2. Execute smart commit
/smart-commit

# Proposes:
# Group 1: feat(crypto): implement ML-KEM-1024 for ZP_HYBRID_2
#   - crates/zp-crypto/src/kex/ml_kem.rs
#   - crates/zp-crypto/src/kex.rs
#   - tests/conformance/crypto_test.rs
#
# Group 2: docs: update CHANGELOG and NEXT_TASKS for ML-KEM-1024
#   - docs/CHANGELOG.md
#   - NEXT_TASKS.md
#
# Proceed? (y/n)

# User: y

# ✅ 2 commits created:
#    - a1b2c3d feat(crypto): implement ML-KEM-1024 for ZP_HYBRID_2
#    - d4e5f6g docs: update CHANGELOG and NEXT_TASKS for ML-KEM-1024

# 3. Push with safety checks
/smart-push

# ✅ Pushed 2 commits to origin/main
# 🔗 CI: https://github.com/yourorg/zp/actions
```

**Time:** ~5 minutes (with review of proposed commits)

**Savings:** ~10-15 minutes per commit cycle

---

## Compatibility with Existing ZP Workflows

### Preserved ZP Strengths
| ZP Feature | Status | Integration |
|------------|--------|-------------|
| `/spec <section>` | ✅ Keep | Referenced in commit messages |
| `/vector <name>` | ✅ Keep | Used in test development |
| `/decision <id>` | ✅ Keep | Referenced when making choices |
| `/check` | ✅ Keep | Used by smart-commit pre-flight |
| `/audit <crate>` | ✅ Keep | crypto-impl agent unchanged |
| `/bench` | ✅ Keep | Performance validation |
| `/fuzz` | ✅ Keep | Security testing |
| `/new-feature` | ✅ Keep | Structured feature workflow |
| `/fix-bug` | ✅ Keep | Bug fix workflow |

### Enhanced Workflows
| Task | Old Way | New Way | Benefit |
|------|---------|---------|---------|
| **Commit** | Manual staging + message | `/smart-commit` | Auto-grouping, cleanup |
| **Push** | `git push` | `/smart-push` | Safety checks, PR creation |
| **WIP commit** | Manual | `/smart-commit-quick` | 2x faster |
| **Plan commit** | Mental | `/smart-commit-dry` | See before doing |

---

## Risks & Mitigations

### Risk 1: Over-Automation
**Concern:** Developers stop thinking about commit structure
**Mitigation:**
- All commands show proposed actions and prompt for approval
- Dry-run mode encourages review
- Keep manual git available for complex cases

### Risk 2: ZP-Specific Requirements Missed
**Concern:** Lang patterns don't fit ZP's needs
**Mitigation:**
- All commands adapted for ZP (spec compliance, crypto checks)
- Preserve existing ZP domain commands
- Iterative refinement based on usage

### Risk 3: Commit Message Quality
**Concern:** Auto-generated messages lack context
**Mitigation:**
- Smart inference from file changes
- User can override with custom message
- Messages follow conventional commits standard

---

## Success Metrics

### Quantitative (After 2 Weeks)
- ⏱️ **Time saved per commit:** Target 10-15 minutes → 5 minutes
- 🎯 **Commit quality:** 90%+ follow conventional commits
- ✅ **Pre-commit test pass rate:** 95%+ (catch issues before push)
- 🔄 **Iteration velocity:** 2x faster WIP commits

### Qualitative
- ✅ **Developer experience:** Less context switching (stay in Claude)
- ✅ **Consistency:** All commits follow same format
- ✅ **Safety:** No accidental pushes to main without checks
- ✅ **Documentation:** Better commit history for future reference

---

## Recommendation

### Immediate Action (P0)
**Implement `/smart-commit` and `/smart-push` this week.**

These two commands provide 80% of the value with minimal effort (~5 hours total).
They automate the most tedious parts of the git workflow while preserving ZP's superior spec-driven development process.

### Follow-Up (P1)
**Add `/smart-commit-quick` and `/smart-commit-dry` next week.**

These enhance the core workflow with faster WIP commits and planning tools.

### Future Consideration (P2-P3)
**Evaluate `/review-code` and `/smart-push-quick` based on usage patterns.**

May not be needed given ZP's existing `/audit` command is already excellent.

---

## Appendix: Template Files

### Template: `/smart-commit` for ZP
*See separate file: `.claude/commands/smart-commit.md.template`*

### Template: `/smart-push` for ZP
*See separate file: `.claude/commands/smart-push.md.template`*

### Template: `/smart-commit-quick` for ZP
*See separate file: `.claude/commands/smart-commit-quick.md.template`*

---

**Next Steps:**
1. Review this proposal
2. Approve P0 commands for implementation
3. I'll create the command files based on templates
4. Test on Task 2.8 commit (ML-KEM-1024)
5. Iterate based on feedback

---

*Analysis completed: 2025-12-20*
*Estimated implementation time: 5 hours (P0), 8 hours (P0+P1), 12 hours (P0+P1+P2)*
