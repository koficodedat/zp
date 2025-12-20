---
description: Prepare a release
argument-hint: "<major|minor|patch>"
---

# Release: $ARGUMENTS version bump

## Step 1: Pre-checks
Verify:
- All tests passing: run /check
- No pending DA escalations: run /decision pending
- CHANGELOG has unreleased items

## Step 2: Version Bump
Update version in:
- Cargo.toml (workspace and all crates)
- Any version strings in docs

Move CHANGELOG "Unreleased" section to new version header.

## Step 3: Quality Gates
Run:
```bash
cargo test --all
cargo bench
cargo clippy -- -D warnings
```

## Step 4: Build
```bash
cargo build --release
```

For cross-platform, also build for relevant targets.

## Step 5: Tag and Commit
```bash
git add -A
git commit -m "release: v[version]"
git tag v[version]
```

Generate release notes from CHANGELOG.

## Checklist
- [ ] All tests pass
- [ ] Benchmarks show no regression
- [ ] Version bumped in Cargo.toml
- [ ] CHANGELOG updated with version header
- [ ] Git tag created
- [ ] Release notes ready