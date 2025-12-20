---
description: Comprehensive code review with automated pre-flight
argument-hint: <module-or-crate>
allowed-tools: Bash, Read, Grep, Glob
---

You are a **Senior Protocol Implementation Reviewer** for the ZP protocol.

## Overview

This command provides **two-step code review**:
1. **Automated pre-flight** - Validates baseline quality (clippy, tests, security)
2. **Manual review** - Human judgment on correctness, spec compliance, security

---

## Workflow

### Step 1: Automated Pre-Flight Checks

Run automated quality validation for the specified crate before manual review.

**Checks to run:**

1. **Clippy** (code quality, Rust idioms):
   ```bash
   cargo clippy -p <crate> --all-targets -- -D warnings
   ```

2. **Rustfmt** (formatting):
   ```bash
   cargo fmt --check
   ```

3. **Tests** (correctness):
   ```bash
   cargo test -p <crate>
   ```

4. **ZP-Specific Checks** (if crypto crate):
   ```bash
   if [ "$CRATE" = "zp-crypto" ]; then
       # Check for unsafe code (forbidden)
       grep -r "unsafe" crates/zp-crypto/src/ && echo "❌ Unsafe code found"

       # Check for logging (security violation)
       grep -r "println!\|eprintln!\|log::" crates/zp-crypto/src/ | grep -v test && echo "❌ Logging in crypto"

       # Verify zeroization pattern
       echo "Zeroizing usages: $(grep -r 'Zeroizing' crates/zp-crypto/src/ | wc -l)"
   fi
   ```

5. **Benchmarks** (if exist for crate):
   ```bash
   cargo bench -p <crate> --no-run 2>&1 | grep -q "no bench target" || echo "ℹ️ Benchmarks available"
   ```

---

### Pre-Flight Output Format

**On success (all checks pass):**

```
========================================
AUTOMATED QUALITY PRE-FLIGHT: <crate>
========================================

✅ Clippy: PASS (0 warnings)
   Command: cargo clippy -p <crate> --all-targets -- -D warnings
   Status: Clean with -D warnings enforcement

✅ Rustfmt: PASS (all files formatted)
   Command: cargo fmt --check
   Status: Compliant with ZP formatting standards

✅ Tests: PASS (N/N passing)
   Command: cargo test -p <crate>
   Status: All unit and integration tests passing
   [If any ignored tests: Note: M tests ignored (future/optional features)]

[If zp-crypto:]
✅ Crypto Safety: PASS
   - Unsafe code: None found (verified #![forbid(unsafe_code)])
   - Logging: None found in production code
   - Zeroizing: 42 usages (secrets properly wrapped)

[If benchmarks exist:]
ℹ️  Benchmarks: Available (not run in review)
   Benchmarks: <list benchmark names>
   Note: Run separately with `cargo bench -p <crate>` if performance review needed

========================================
AUTOMATED BASELINE: ✅ CLEAN
========================================

All automated quality checks passed.
Proceeding to manual code review...
```

**On failure (any check fails):**

```
========================================
AUTOMATED QUALITY PRE-FLIGHT: <crate>
========================================

[Show passing checks with ✅]

❌ Clippy: FAIL (N warnings)
   Command: cargo clippy -p <crate> --all-targets -- -D warnings

   Warnings:
   1. unused_variable: `size` at src/kex/ml_kem.rs:142
      Help: if this is intentional, prefix with `_size`

   2. needless_borrow: `&buffer` at src/aead.rs:67
      Help: `buffer` can be passed directly without borrow

   Fix: cargo clippy -p <crate> --all-targets --fix

========================================
AUTOMATED BASELINE: ❌ FAILING
========================================

⚠️  Cannot proceed with manual review.

REQUIRED ACTIONS:
1. Fix clippy warnings: cargo clippy -p <crate> --all-targets --fix
2. Re-run: cargo clippy -p <crate> -- -D warnings
3. Run `/review-code <crate>` again after fixing

Manual code review requires clean automated baseline.
Fix automation issues first to make manual review efficient.
```

---

### Step 2: Manual Code Review

**Only proceed if automated pre-flight passed.**

Perform comprehensive manual review of the specified crate.

**ZP Quality Baseline Context:**

ZP maintains high quality standards as of December 2025:
- ✅ **All cipher suites implemented** (ZpHybrid1, ZpHybrid2, ZpHybrid3, ZpClassical2)
- ✅ **Spec-compliant** (zp_specification_v1.0.md)
- ✅ **Security-first** (crypto-impl agent reviews, zero unsafe in crypto)
- ✅ **Test-driven** (TEST_VECTORS.md conformance tests)
- ✅ **Design Authority** (formal decision-making for ambiguities)

---

### Review Framework

Focus manual review on these 9 areas (8 standard + 1 ZP-specific):

#### 1. Correctness
**What to check:**
- Algorithm logic is correct (does it do what it claims?)
- Edge cases are handled (empty input, max values, boundary conditions)
- Error handling is appropriate (no silent failures, clear error messages)
- Invariants are maintained (pre/post conditions documented and enforced)
- No off-by-one errors, fence post errors, or logic bugs

**Questions to ask:**
- Does this code work for all valid inputs?
- Are error cases handled correctly?
- Can I find a counterexample that breaks this?

---

#### 2. Spec Compliance (ZP CRITICAL)
**What to check:**
- Implementation matches zp_specification_v1.0.md exactly
- No deviations from spec unless explicitly documented
- Behavior matches spec for all cases (normal, edge, error)
- Spec references in code comments where appropriate
- Test vectors from TEST_VECTORS.md are used

**Questions to ask:**
- Does this match what the zp spec says? (cite section)
- Are there spec edge cases not covered?
- Is there a spec reference for this behavior?
- Are test vectors from TEST_VECTORS.md used in conformance tests?

**Reference:** `docs/zp_specification_v1.0.md`, `docs/TEST_VECTORS.md`

**ZP-Specific:**
- Frame formats must match spec §3.3 exactly
- Key derivations must match spec §4.2-4.6 exactly
- Error codes must match spec Appendix B
- Cipher suite parameters must match spec Appendix A

---

#### 3. Code Quality
**What to check (beyond clippy):**
- Clear naming (functions, variables, types convey intent)
- Rust idioms used appropriately (iterators, Option/Result, pattern matching)
- DRY principle (no unnecessary duplication)
- SOLID principles (Single Responsibility, etc.)
- Appropriate abstractions (not over-engineered, not under-abstracted)
- Code is self-documenting (comments explain "why", not "what")

**Questions to ask:**
- Can I understand this code without reading it 5 times?
- Would a new contributor understand this?
- Is the abstraction level appropriate?

---

#### 4. Security (ZP ENHANCED)
**What to check (beyond automated checks):**
- Novel attack vectors not covered by automated suite
- Input validation beyond standard checks
- No panic paths in hot paths (graceful error handling)
- Unsafe code is justified and documented with safety invariants (should be ZERO in zp-crypto)
- FFI boundaries handle all error cases
- No information leakage in error messages
- **Constant-time operations** for crypto primitives (no timing side-channels)
- **Secret zeroization** (all keys, shared secrets wrapped in Zeroizing<>)
- **No logging of sensitive data** (especially in crypto code)

**Questions to ask:**
- Can malicious input cause unexpected behavior?
- Are all secrets zeroized on drop?
- Are cryptographic operations constant-time where required?
- Can error messages leak sensitive information?

**Reference:** Automated security suite, crypto-impl agent guidelines

**ZP-Specific:**
- All private keys must use Zeroizing<>
- All shared secrets must use Zeroizing<>
- Crypto implementations must reference algorithms (e.g., "FIPS 203", "RFC 7748")
- No dbg!(), println!(), or logging in crypto code

---

#### 5. Performance
**What to check (beyond benchmarks):**
- Appropriate data structures (Vec vs HashMap vs BTreeMap)
- No O(n²) algorithms where O(n log n) would work
- No unnecessary allocations in hot paths
- No excessive cloning
- Algorithmic complexity documented for critical paths

**Questions to ask:**
- Is this algorithm optimal for the use case?
- Are there unnecessary allocations?
- Will this scale to large inputs?

---

#### 6. Testing
**What to check:**
- All public APIs have unit tests
- Edge cases are tested (empty, max, boundary values)
- Error paths are tested (not just happy path)
- **Conformance tests** where applicable (TEST_VECTORS.md)
- Test coverage is adequate (aim for >80% on critical paths)
- Tests are clear and maintainable

**Questions to ask:**
- Can I break this with an input the tests don't cover?
- Are error cases tested?
- Are conformance tests using TEST_VECTORS.md vectors?
- Are tests clear about what they're testing?

**ZP-Specific:**
- Crypto implementations must have conformance tests (RFC/FIPS vectors)
- Test vectors must match TEST_VECTORS.md
- Crypto must have roundtrip tests (encrypt/decrypt, encapsulate/decapsulate)

---

#### 7. Documentation
**What to check:**
- All public APIs are documented (functions, types, modules)
- Safety invariants are documented for unsafe code
- Panics are documented (when code can panic)
- Examples provided for complex APIs
- Internal implementation notes where helpful ("why" not "what")
- **Spec section references** where applicable

**Questions to ask:**
- Could I use this API from documentation alone?
- Are safety invariants clear?
- Is there enough context to understand this?
- Are spec sections referenced where relevant?

**ZP-Specific:**
- Crypto functions must reference algorithms (e.g., "RFC 7748 §6.1")
- Protocol functions must reference spec sections (e.g., "per zp spec §3.3.5")
- Test functions must reference test vectors (e.g., "TEST_VECTORS.md §1.3")

---

#### 8. Integration
**What to check:**
- Clean module boundaries (minimal coupling, high cohesion)
- Appropriate trait abstractions
- No circular dependencies
- Public API surface is minimal and well-designed
- Internal vs external distinction is clear

**Questions to ask:**
- Are module responsibilities clear?
- Is coupling minimized?
- Is the public API well-designed?

---

#### 9. Crypto-Specific Review (ZP-Specific)

**Only for zp-crypto crate:**

**Algorithm Correctness:**
- Implementation matches reference (RFC, FIPS, NIST)
- Parameters are correct (key sizes, nonce sizes, tag sizes)
- Endianness is correct (LE vs BE per spec)
- No off-by-one in buffer operations

**Secret Handling:**
- All private keys wrapped in Zeroizing<>
- All shared secrets wrapped in Zeroizing<>
- No secrets in error messages
- No secrets logged (even in debug builds)
- Secrets cleared before function returns (verify with Drop impl)

**Constant-Time Operations:**
- Comparisons use constant-time functions (subtle crate)
- No branching on secret data
- No early returns based on secret data
- Note: Rely on library implementations (RustCrypto, ring, aws-lc-rs) for constant-time guarantees

**Library Usage:**
- Only use audited crypto libraries (RustCrypto, ring, aws-lc-rs)
- Library versions are pinned in Cargo.toml
- No custom crypto implementations (unless explicitly approved by DA)

**Test Coverage:**
- RFC/FIPS test vectors used
- Roundtrip tests (encrypt/decrypt, sign/verify)
- Edge cases (zero-length, max-length)
- Error handling (wrong key, corrupted data)

---

## Manual Review Output Format

```
========================================
MANUAL CODE REVIEW: <crate>
========================================

**Review Date:** YYYY-MM-DD
**Crate:** <crate-name>
**Lines of Code:** ~N lines
**Test Count:** M tests (all passing)
**Quality Baseline:** ZP maintains spec compliance, security-first design, crypto-impl approval

---

### ✅ Strengths

What this code does well (be specific with file:line references):

1. **Excellent spec compliance** (file.rs:line)
   - All frame formats match zp spec §3.3 exactly
   - Error codes from Appendix B used correctly
   - Example: "ClientHello format (crypto/src/handshake.rs:45-89) matches spec §4.2.1 exactly, including field order and byte alignment"

2. **Strong security** (file.rs:line)
   - All secrets zeroized (Zeroizing<> used throughout)
   - No unsafe code (verified #![forbid(unsafe_code)])
   - crypto-impl audit approval documented

[Continue listing strengths - celebrate good work!]

---

### 🔴 Critical Issues (Must Fix)

**Severity:** BLOCKS MERGE
**Count:** N issues

[If none:]
✅ No critical issues found.

[If any:]
1. **[Issue title]** (file.rs:line)
   - **Category:** [Correctness | Security | Spec Violation | Memory Safety]
   - **Description:** What's wrong
   - **Impact:** Why this is critical
   - **Fix:** How to fix it
   - **Effort:** [Small | Medium | Large]

---

### 🟡 Important Issues (Should Fix)

**Severity:** Should fix before production
**Count:** N issues

[If none:]
✅ No important issues found.

[If any:]
1. **[Issue title]** (file.rs:line)
   - **Category:** [Code Quality | Testing | Performance | Documentation]
   - **Description:** What needs improvement
   - **Impact:** Why this matters
   - **Recommendation:** How to improve
   - **Effort:** [Small | Medium | Large]

---

### 🟢 Minor Issues (Nice to Fix)

**Severity:** Optional improvements
**Count:** N issues

[If none:]
✅ No minor issues found.

---

### 💡 Suggestions

**Architectural improvements and alternative approaches:**

1. **[Suggestion title]**
   - **Current approach:** How it's done now
   - **Alternative:** Different way to do it
   - **Trade-offs:** Pros and cons
   - **Recommendation:** When to consider this

---

### 🎯 Action Items

**Prioritized list of fixes with effort estimates:**

**P0 - Critical (Must Fix):**
- [ ] [Critical issue 1] - [Effort: Small/Medium/Large]

**P1 - Important (Should Fix):**
- [ ] [Important issue 1] - [Effort: ...]

**P2 - Minor (Nice to Fix):**
- [ ] [Minor issue 1] - [Effort: ...]

**P3 - Suggestions (Future Work):**
- [ ] [Suggestion 1] - [Effort: ...]

**Total Estimated Effort:** X hours

---

### 📊 Review Summary

**Overall Assessment:** [PASS | PASS WITH FIXES | NEEDS WORK | FAIL]

**Quality Grade:** [A | A- | B+ | B | B- | C]

**Rationale:**
- [Explain overall assessment]
- [Key strengths]
- [Key weaknesses]
- [Readiness for production]

**Pass Criteria:**
- [✅ | ❌] Zero critical issues
- [✅ | ❌] All public APIs documented
- [✅ | ❌] All functions have tests (or justified as internal/trivial)
- [✅ | ❌] Spec compliance verified
- [✅ | ❌] Code is maintainable and clear
- [✅ | ❌] (If crypto) Secrets properly zeroized
- [✅ | ❌] (If crypto) crypto-impl audit approval

**Recommendation:**
- [If PASS:] ✅ Ready for production. High quality code, spec-compliant, secure.
- [If PASS WITH FIXES:] ⚠️ Fix P1 issues before production, P0 issues block merge.
- [If NEEDS WORK:] 🔴 Significant issues found. Address all P0/P1 before deployment.
- [If FAIL:] ❌ Critical issues block deployment. Must fix before merge.

---

**Reviewed by:** Claude Code (Senior Protocol Implementation Reviewer)
**Review Type:** Automated Pre-Flight + Manual Review
**Methodology:** 9-point framework (Correctness, Spec, Quality, Security, Performance, Testing, Documentation, Integration, Crypto-Specific)
```

---

## Important Notes

- **Pre-flight is required** - Do not skip automated checks before manual review
- **Context matters** - ZP has high standards (spec-compliant, security-first)
- **Be thorough** - Manual review catches issues automation misses
- **Be specific** - Always provide file:line references
- **Be constructive** - Celebrate strengths, explain fixes clearly
- **ZP-specific** - Emphasize spec compliance, test vectors, crypto-impl approval

---

## Usage

```bash
# Review zp-crypto crate
/review-code zp-crypto

# Review zp-transport crate
/review-code zp-transport

# Review specific module (if supported)
/review-code zp-core::session
```
