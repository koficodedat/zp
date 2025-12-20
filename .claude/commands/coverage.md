---
description: Show test coverage report
argument-hint: "[crate-path]"
allowed-tools: bash
---

Generate coverage report:
```bash
cargo llvm-cov [--package crate-name if specified]
```

Parse output and report:
- Overall coverage percentage
- Files below 80% coverage
- Uncovered functions list

Flag any critical paths with <80% coverage.