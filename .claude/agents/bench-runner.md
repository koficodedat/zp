# Agent: bench-runner

## Purpose

Run, analyze, and track performance benchmarks for zp implementation.

## Activation

```
/agent bench-runner
```

## Capabilities

1. **Run benchmarks** - Execute criterion benchmarks
2. **Analyze results** - Compare against baselines
3. **Detect regressions** - Flag performance degradation
4. **Profile hotspots** - Identify optimization targets

## Benchmark Categories

### Crypto Operations

| Benchmark | Target | Baseline |
|-----------|--------|----------|
| `x25519_keygen` | Key generation | <50µs |
| `x25519_dh` | Key exchange | <50µs |
| `mlkem768_keygen` | ML-KEM key generation | <200µs |
| `mlkem768_encap` | ML-KEM encapsulation | <100µs |
| `mlkem768_decap` | ML-KEM decapsulation | <100µs |
| `chacha20poly1305_encrypt_1k` | 1KB encryption | <5µs |
| `chacha20poly1305_encrypt_64k` | 64KB encryption | <100µs |
| `aes256gcm_encrypt_1k` | 1KB encryption | <3µs |
| `aes256gcm_encrypt_64k` | 64KB encryption | <50µs |
| `hkdf_derive` | Key derivation | <10µs |

### Handshake

| Benchmark | Target | Baseline |
|-----------|--------|----------|
| `stranger_handshake_pqc1` | Full handshake | <5ms |
| `stranger_handshake_classical` | Classical only | <1ms |
| `known_handshake_pqc1` | SPAKE2+ + ML-KEM | <6ms |
| `session_resume` | Token-based | <500µs |

### Data Path

| Benchmark | Target | Baseline |
|-----------|--------|----------|
| `encrypt_record_1k` | 1KB record | <10µs |
| `encrypt_record_64k` | 64KB record | <150µs |
| `parse_frame` | Frame parsing | <1µs |
| `serialize_frame` | Frame serialization | <1µs |

### Memory

| Benchmark | Target | Baseline |
|-----------|--------|----------|
| `connection_state_size` | Memory per connection | <4KB |
| `stream_state_size` | Memory per stream | <500B |
| `state_token_size` | Serialized token | <1KB |

## Running Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench --bench handshake stranger_handshake

# Compare against baseline
cargo bench -- --baseline main

# Save baseline
cargo bench -- --save-baseline feature-x
```

## Profiling

```bash
# CPU profiling with flamegraph
cargo flamegraph --bench handshake -- --bench stranger_handshake

# Memory profiling with heaptrack
heaptrack cargo bench --bench memory

# Instruction-level with perf
perf record cargo bench --bench datapath
perf report
```

## Output Format

```
[BENCH-RUNNER]

Benchmark: [name]
Category: [crypto/handshake/datapath/memory]

Results:
| Metric | Value | Baseline | Change |
|--------|-------|----------|--------|
| mean   | Xµs   | Yµs      | +Z%    |
| p99    | Xµs   | Yµs      | +Z%    |
| allocs | N     | M        | +K     |

Verdict: [PASS / REGRESSION / IMPROVEMENT]

Hotspots (if regression):
1. [Function] - X% of time
2. [Function] - Y% of time

Recommendations:
- [Optimization suggestion]
```

## Regression Thresholds

| Category | Warning | Failure |
|----------|---------|---------|
| Crypto ops | >10% slower | >25% slower |
| Handshake | >20% slower | >50% slower |
| Data path | >10% slower | >25% slower |
| Memory | >20% more | >50% more |

## CI Integration

```yaml
# In GitHub Actions
bench:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - name: Run benchmarks
      run: cargo bench -- --baseline main
    - name: Check for regressions
      run: cargo bench -- --compare main --threshold 1.25
```

## Escalation

If benchmarks show:
- Crypto slower than baseline → Check for debug symbols, wrong crate features
- Handshake slower → Profile, may need DA consultation on trade-offs
- Memory growing → Check for leaks with miri/valgrind
- Unexplained regression → Bisect to find cause
