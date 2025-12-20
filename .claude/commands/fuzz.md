---
description: Run fuzzing on a target
argument-hint: "<target> [duration-seconds]"
allowed-tools: bash
---

Run cargo-fuzz on the specified target.

If target is "list": `cargo fuzz list`

Otherwise:
```bash
cargo fuzz run [target] -- -max_total_time=[duration or 60]
```

If fuzzer finds crashes:
1. Report crash location
2. Suggest: `cargo fuzz tmin [target] [crash-file]`