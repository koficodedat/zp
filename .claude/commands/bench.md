---
description: Run performance benchmarks
argument-hint: "[target] [--compare baseline] [--save name]"
allowed-tools: bash
---

Run criterion benchmarks.

Commands:
- No args: `cargo bench`
- With target: `cargo bench --bench [target]`
- Compare: `cargo bench -- --baseline [baseline]`
- Save: `cargo bench -- --save-baseline [name]`

After benchmarks complete, summarize:
- Mean/median times
- Comparison to baseline if provided
- Flag any regressions >10%