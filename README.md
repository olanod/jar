# Grey

A JAM (Join-Accumulate Machine) blockchain node implementation in Rust, following the [Gray Paper v0.7.2](https://github.com/gavofyork/graypaper/releases/download/v0.7.2/graypaper-0.7.2.pdf).

## Highlights

- **313 tests passing** across all crates, **101/101 conformance blocks**
- **PVM recompiler faster than polkavm's compiler** — grey's x86-64 JIT recompiler outperforms polkavm v0.30.0's compiler backend on both compute and host-call workloads (including compilation time in each iteration):

  | Benchmark | Grey Recompiler | PolkaVM Compiler | Result |
  |-----------|-----------------|------------------|--------|
  | Fibonacci (1M iter) | 425 us | 445 us | **Grey 5% faster** |
  | Host calls (100K ecalli) | 679 us | 3,331 us | **Grey 4.9x faster** |

  Key optimizations: per-basic-block gas metering with fused `sub [mem], imm` + `js` (2 instructions), cold OOG stubs to keep PC stores off the hot path, `inc`/`dec` for +1/-1, register-mapped PVM state. Benchmarks include full compile+execute each iteration (realistic JAM model where each work-package is compiled fresh). See [docs/pvm-recompiler-optimization.md](docs/pvm-recompiler-optimization.md) for details.

- **PVM interpreter also faster than polkavm** — grey's interpreter beats polkavm's interpreter:

  | Benchmark | Grey | PolkaVM | Result |
  |-----------|------|---------|--------|
  | Fibonacci (1M iter) | 10.8 ms | 9.4 ms | PolkaVM 1.15x faster |
  | Host calls (100K ecalli) | 0.91 ms | 2.6 ms | **Grey 2.9x faster** |

  Key optimizations: pre-decoded instruction cache, basic-block gas charging, inline flat-operand execution, pre-resolved branch targets. See [docs/pvm-interpreter-optimization.md](docs/pvm-interpreter-optimization.md) for details.

## Building

```
cargo build
```

## Test Status

**313 tests passing** across all crates.

| Category | Crate | Tests | Status |
|----------|-------|------:|--------|
| Codec (Appendix C) | `grey-codec` | 32 | All passing |
| Cryptography (Section 3.8) | `grey-crypto` | 15 | All passing |
| PVM — Polkadot Virtual Machine (Appendix A) | `grey-pvm` | 41 | All passing |
| Merkle tries (Appendices D & E) | `grey-merkle` | 14 | All passing |
| Erasure coding (Appendix H) | `grey-erasure` | 24 | All passing |
| Safrole consensus (Section 6) | `grey-consensus` | 25 | All passing |
| STF — Safrole | `grey-state` | 21 | All passing |
| STF — Disputes | `grey-state` | 28 | All passing |
| STF — Reports | `grey-state` | 42 | All passing |
| STF — Assurances | `grey-state` | 10 | All passing |
| STF — Accumulate | `grey-state` | 30 | All passing |
| STF — History | `grey-state` | 4 | All passing |
| STF — Preimages | `grey-state` | 8 | All passing |
| STF — Authorizations | `grey-state` | 3 | All passing |
| STF — Statistics | `grey-state` | 3 | All passing |
| State core | `grey-state` | 10 | All passing |
| Services | `grey-services` | 11 | All passing |

### Conformance Testing

Grey includes a conformance target binary (`grey-conform`) that speaks the JAM fuzz-proto v1 protocol over Unix domain sockets, compatible with [minifuzz](https://github.com/davxy/jam-conformance), Polkajam, and Jamzig fuzzers.

**Status: 101/101 blocks passing** on the `0.7.2/no_forks` trace (tiny config: V=6, C=2, E=12). Grey passes the full conformance block test suite.

```bash
# Quick test: replay trace and show pass/fail per block
python3 scripts/run_conform.py

# Compare state with a reference implementation at any block
python3 scripts/compare_with_ref.py 68

# Dump state at a specific block for debugging
python3 scripts/dump_state.py --block 8
```

See [docs/conformance-testing.md](docs/conformance-testing.md) for the full debugging guide, protocol details, and script reference.

### Known Spec Issues

- [docs/pvm-sbrk.md](docs/pvm-sbrk.md) — Ambiguity in the Gray Paper's `sbrk` definition (`sbrk(0)` is undefined; all implementations use a heap-pointer tracking model)
- [docs/host-call-ordering.md](docs/host-call-ordering.md) — GP requires host calls to read guest memory before privilege checks; memory faults take priority over error sentinels

## Project Structure

```
crates/
  grey/              # Binary — node executable + conformance target
  grey-types/        # Core protocol types and constants
  grey-codec/        # JAM serialization (Appendix C)
  grey-crypto/       # Blake2b, Keccak, Ed25519, Bandersnatch, BLS
  grey-pvm/          # Polkadot Virtual Machine (Appendix A)
  grey-merkle/       # Binary Patricia trie, MMR, state serialization (Appendices D & E)
  grey-erasure/      # Reed-Solomon erasure coding (Appendix H)
  grey-state/        # Chain state transitions (Sections 4–13)
  grey-consensus/    # Safrole block production (Section 6)
  grey-services/     # Service accounts, accumulation (Sections 9, 12)
  grey-network/      # P2P networking (scaffolded)
```

## License

See [LICENSE](LICENSE) for details.
