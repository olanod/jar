# JAR

**JAM Axiomatic Reference** — a formal specification of the [JAM protocol](https://graypaper.com/) in Lean 4, with a Rust protocol node implementation.

## Components

### [JarBook — Formal Specification](/spec/)

The JAR specification formalized in Lean 4, covering the complete JAM protocol: state transitions, Safrole consensus, GRANDPA finality, PVM execution, erasure coding, and accumulation. Built with [Verso](https://github.com/leanprover/verso).

### [Grey — Rust Node](https://github.com/jarchain/jar/tree/master/grey)

A JAM protocol node implemented in Rust, featuring an interpreter and JIT recompiler for the Polkadot Virtual Machine (PVM), with full state transition support.

### [Genesis — Proof of Intelligence](https://github.com/jarchain/jar/blob/master/GENESIS.md)

A token distribution protocol where every merged PR is scored on difficulty, novelty, and design quality through ranked peer review. Contributions earn genesis allocations proportional to their assessed value.

## Links

- [GitHub Repository](https://github.com/jarchain/jar)
- [Gray Paper](https://graypaper.com/)
