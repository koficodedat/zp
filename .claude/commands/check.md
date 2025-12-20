---
description: Run test suite
argument-hint: "[filter] [--quick]"
allowed-tools: bash
---

Run the zp test suite.

If no arguments: `cargo test`
If filter provided: `cargo test [filter]`
If --quick: `cargo test --lib` (skip integration tests)

After tests complete:
1. Run `cargo clippy -- -D warnings`
2. Run `cargo fmt --check`

Report summary: X passed, Y failed, Z warnings.