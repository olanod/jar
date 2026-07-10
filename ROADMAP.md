# JAM alignment roadmap

This fork's direction: a **JAM-aligned VM and node**. Upstream (jarchain/jar)
has diverged from JAM structurally — grey/ deleted, the JAM-PVM ISA replaced
(PVM2 = RV64E + Xjar + EEI), the Lean JAM spec and the entire conformance
vector corpus removed, state serialization moved to SSZ, and the project
itself rebranding — so this fork converges on the graypaper instead, and is
now the **sole maintainer** of three assets that no longer exist upstream:

1. the JAM-PVM implementation lineage (grey-transpiler, javm, grey-state),
2. the Lean spec with its dual-variant machinery (`gp072_*` = graypaper
   0.7.2 semantics, `jar1` = the local variant), and
3. the conformance-vector corpus (`spec/tests/vectors/`, gp072 + jar1) plus
   the `jarstf`/`jartest` oracle that can run and re-bless it.

## Fork policy (hard divergence)

This repository is a **hard fork** of `jarchain/jar`. The divergence is
declared at merge-base **`4f0890c8`** ("Merge PR #786", 2026-04-28) — the last
commit shared with upstream.

- **Never merge `upstream/master`.** After the base, upstream deleted `grey/`,
  replaced the JAM-PVM ISA (PVM2 = RV64E + Xjar + EEI), removed the Lean JAM
  spec and the entire conformance-vector corpus, and moved state serialization
  to SSZ. A merge is therefore a delete/modify conflict across essentially the
  whole working tree and would destroy the three assets this fork now solely
  maintains (the JAM-PVM lineage, the dual-variant Lean spec, the vector
  corpus). Merging is prohibited.
- **Cherry-pick only.** Individual upstream fixes may be cherry-picked when
  they touch code this fork still shares. An audit at the base found **nothing
  left worth cherry-picking**: upstream applied zero fixes to the shared
  lineage after `4f0890c8`.
- **Monitor cadence: quarterly, not per-merge.** Re-audit upstream for
  cherry-pick candidates roughly every quarter; do not track it continuously.
- The fork keeps its own Lean spec CI alive (`ci-spec.yml`); upstream deleted
  theirs.

## The method: the vector corpus is the ratchet

The gp072 Lean branch is a **complete, vector-gated model of the on-chain
STF** (all 9 sub-transitions pass pinned 0.7.2 vectors at tiny and full
params, including real PVM execution, plus ~600 full-block gp072_tiny
cases). grey today tests only `jar1`. Convergence therefore proceeds
subsystem-by-subsystem: flip grey onto the gp072 vectors, fix what fails,
freeze, move on. Vectors are only re-blessed when the pinned graypaper
revision changes — never to make an implementation pass.

Known limit of the ratchet: the **in-core pipeline has no oracle** — Ψ_R
refine, Ψ_I, Ξ work-report computation exist in the Lean spec only as
simplified dead code, and no variant has refine or PVM-instruction-level
vectors. In-core conformance (phases 5–6) needs the spec extended first and
the community PVM test vectors imported.

## Phases

Gates are named after what turns green, not after effort spent.

**Phase 0 — repo posture (S)**
- Declare the hard divergence formally: merge-base `4f0890c8` (2026-04-28);
  policy = never merge upstream/master (a merge is a delete/modify conflict
  across the entire working tree); cherry-pick-only, and audit found nothing
  left worth cherry-picking (upstream applied zero fixes to the shared
  lineage after the base). Monitor upstream quarterly, not per-merge.
- Housekeeping: prune pre-divergence WIP branches; keep the Lean spec CI
  alive in the fork (upstream deleted theirs); ensure `fuzz/jar-fuzz`
  passes `--variant` (stale CLI contract).
- Downstream pins: vos consumes this fork at three different revs — unify
  on current master (the stale `6db1168` pin predates every transpiler/javm
  correctness fix and runs known-buggy codegen).

**Phase 1 — execution ABI (DONE — see vos `docs/design/jam-entry-points.md`)**
- ✅ Entry prologue: refine IC 0 / accumulate IC 5; the `φ[7]=1` selector
  retired. Ψ_T stays absent (GP main removed it; transfers are accumulate
  inputs — `AccumulationInput` already models this). *(landed 232531b8)*
- ✅ Host-owned SP (`φ[1] = stack_top` set at kernel init; blob preamble
  dropped) and args in GP's `ω_7/ω_8`. *(landed 232531b8)*
- ✅ Halt convention: GP's halt address (`djump(2^32−2^16)`, `ω_0` init);
  REPLY-as-termination retired (root REPLY now panics; REPLY stays the
  inter-VM CALL return); refine output read from `μ[ω_7..+ω_8]`, accumulate
  commitment from `μ[ω_7..+32]` at halt, not packed `φ[7]`. Window
  accessors validate guest ptr/len against the cap table first. *(ff1976b0)*
- ✅ ISA strictness: opcode 3 (`Ecall`) rejected under an `IsaMode::
  Conformance` knob (cache-keyed); branch/djump targets validated against
  strict basic-block starts ({0} ∪ post-terminator) on both backends and in
  the Lean oracle; Lean djump gains GP eq-210 alignment; `load_imm_jump_ind`
  uses the pre-state base register. *(dcfbe17b)*
- ✅ Interpreter/JIT page-permission parity: the interpreter gained a
  per-page RO/RW/none map matching the recompiler's mmap protection (RO
  writes and gap reads now fault identically), fault addresses unified on
  the page base via `si_addr`, uniform-RW fast path keeps flat-buffer speed.
  The differential fuzzer was extended (RO/gap memory, ISA modes,
  self-consistent bitmasks, protocol-call servicing) and drove out **11
  pre-existing interpreter/JIT divergences** — including a consensus-relevant
  recompiler-resume signal-state use-after-scope, division `#DE` faults, and
  several gas-accounting mismatches; each fixed with a regression test.
  *(7e13230b, f024c184)*
- ✅ Guests ported off REPLY termination to `ret`/halt (javm_entry! macro,
  minimal/bootstrap/pixels, grey-bench blobs); service blobs rebuilt and
  jar1 accumulate vectors re-blessed (gp072 untouched). Gate met: jar1
  suites green on both backends, spec `make test` across all 3 variants,
  harness serial scenario green.

**Phase 2 — the ratchet switched on (DONE)**
- ✅ Parameterized grey's vector loaders on variant (`load_jar_test_variant`
  + `discover_all_variant_test!` + `config_for_variant`); turned on gp072
  for all named subsystems: erasure (already green via its own crate),
  history, authorizations (param-independent), statistics (needs
  `Config::tiny()` for the epoch-boundary vector), reports. Gate met:
  every named subsystem green on `gp072_tiny` + `gp072_full`.
- ✅ Reports was the hard one: `report_hash` was computed over grey's jar1
  wire format, but gp072 guarantee signatures are over the graypaper
  (varnat) encoding — and grey's jar1 reports fixtures are all degenerate
  bad_signature cases, so the signature-verify path had never run. Added a
  GP-native encoder for the WorkReport family (`grey_crypto::gp072_codec`,
  encode_nat/GP C.1 + the work types) selected via a new `Config.gp072_codec`
  flag; all 42 reports vectors now pass on both gp072 variants — first real
  coverage of signature verify, the ok outputs, and every post-signature
  error. The 42 passing signatures are cryptographic proof the GP encoder
  is byte-exact vs the Lean oracle.
- ✅ Codec `.bin` vectors wired. `grey_crypto::gp072_codec` grew into a full
  GP (varnat) encode+decode codec, and a round-trip conformance test
  (`decode .bin` → re-encode → assert byte-equal) covers all 15 vector types
  on both gp072 variants (30 round-trips): work report/result/item/package,
  refine context, the five sub-extrinsics, headers, and block. Param-dependent
  layouts come from the Config (assurance bitfield = `ceil(C/8)`, verdict
  judgments = supermajority, epoch-marker validators = V, tickets marker = E).
  These were the canonical JAM vectors — the round-trip pinned down several
  layouts where the Lean helpers had diverged. This GP codec is the
  serialization foundation Phase 3's GP SPI loader builds on.

Phase 2 is complete: all five named STF subsystems and all codec vectors are
green on `gp072_tiny` + `gp072_full`.

**Phase 3 — blob format + PVM-level conformance (L)** — _in progress_
- **GP SPI loader** in javm (the standard-program blob format + Y-function
  memory layout + metadata-prefix stripping) as a parallel init path; the
  `JAR\x02` capability manifest stays behind the magic sniff for jar1
  compatibility during transition. **DONE.** `javm::spi` parses the
  standard-program blob (metadata strip → E₃/E₂ header → ro/rw → compact
  deblob), computes the GP flat-memory layout + register ABI (GP eq A.42–A.43),
  and `InvocationKernel::new_standard` loads it by translating to an equivalent
  manifest and running under `IsaMode::Conformance`. Validated byte-for-byte
  against a real service preimage, and end-to-end on both the interpreter and
  recompiler backends (ro readable at Z_Z, stack writable, φ registers per GP).
  `spi::is_jar_manifest` provides the magic sniff for the eventual dispatch in
  the accumulate path.
- Per-instruction gas mode (the model the 0.7.2 vectors pin) alongside the
  block-gas models. _Next; self-contained._
- Import the community JAM PVM test-vector suite (instruction-level
  pre/post register/memory/gas/fault cases); use polkavm-linker (already a
  build-pvm dep) to cross-check with independently-built blobs. _Blocked on
  sourcing: the canonical `w3f/jamtestvectors` has no `pvm/` directory; the
  community `tomusdrw/jamtestvectors-pvm` mirror is unlicensed. Needs a
  decision — vendor from an unlicensed source, wait for a licensed one, or
  synthesize + cross-check with polkavm-linker instead._
- Gate: PVM vectors green on interpreter AND recompiler; gp072 accumulate
  vectors executable through grey's own PVM. _(The last clause also depends on
  Phase 4 host-call convergence for a real service to run to completion; the
  SPI loading mechanics are in place.)_

**Phase 4 — hostcall convergence (L)**
- Raw `ecalli`-id dispatch for consensus execution (drop the cap-table
  indirection); numbering pinned to GP 0.7.2 exactly (note: jar's slots
  already coincide with GP-*main* ids for fetch..provide because main
  inserted `grow_heap=1` — only `gas` moves; the main renumbering is a
  one-line shift when Phase 7 advances the pin).
- Raw-pointer buffer addressing (retire the `φ[12]` DATA-cap window);
  FETCH register ABI + offset window per GP.
- Fill the accumulate Ω table (6 of 27 host calls are live today):
  lookup/info/bless/assign/designate/new/upgrade/eject/query/solicit/
  forget/provide — the surrounding Δ+/Δ*/Δ1 pipeline and state write-back
  are already GP-shaped, so this is handler-by-handler fill-in. `new`'s
  minting formula and reserved range already match GP; add the `+42`
  stride and registrar path.
- Note: today's gp072 accumulate vectors exercise only no-op services —
  richer vectors get blessed from the Lean oracle as handlers land (the
  fork owns blessing).
- Gate: gp072 accumulate vectors (with non-trivial blobs) green; balance-
  dependent handlers (`new`/`transfer`/`eject` CASH/FULL paths) explicitly
  carved out for Phase 5.

**Phase 5 — the economics decision (XL, product decision — not started
until explicitly made)**
- jar1's coinless QuotaEcon (quota_items/quota_bytes + χ_Q quota service,
  amount-less transfers) is this fork's deliberate philosophical divergence
  (`docs/coinless.md`); GP requires BalanceEcon (balance/threshold, CASH/
  FULL, funded transfers). The Lean spec dual-models both behind one
  typeclass, fully proven on each side, so the knob is *mechanically*
  isolated — but reintroducing a token is a protocol-economics decision,
  not a refactor. Full gp072 accumulate conformance (and any claim of "JAM
  conformant") is gated on it; everything before Phase 5 is unaffected.

**Phase 6 — the in-core pipeline (XL)**
- Extend the Lean spec's refine model from sketch to oracle (Ψ_R hostcall
  family: historical_lookup/export + the inner-PVM machine/peek/poke/
  pages/invoke/expunge; Ψ_I args `E2(core)`; Ξ availability-spec, bundle,
  erasure-root and segment export/import — grey-erasure's codec is already
  GP-conformant and vector-gated; the gap is bundle construction and tree
  shape); bless refine vectors; implement in grey. The existing kernel
  VM-pool machinery is architecturally reusable for `machine`/`invoke`.
- This phase is where VOS's parent-agent/sub-actor (`machine`-hostcall)
  story gains its on-chain counterpart.

**Phase 7 — advance the GP pin (recurring)**
- 0.7.2 is the pin because the vectors exist; graypaper main has already
  moved (Ψ_T removed — matching our Phase-1 direction; `grow_heap`
  renumbering; **block-based gas merged** — notably the same *family* as
  jar's block-gas models, so the Phase-3 per-instruction mode is a
  0.7.2-conformance tool, not the end state). Advancing the pin means:
  re-bless vectors from the updated Lean spec, shift hostcall numbering,
  adopt main's published gas cost function. Record the GP commit hash in
  the spec header at every pin change.

## Deliberate divergences (kept, flagged, isolated)

- `variableValidators` (elastic validator sets, tracks GP proposal #514):
  well-isolated (single `if` per use site); keep behind the flag, off for
  strict conformance runs.
- Coinless economics until the Phase-5 decision.
- The capability kernel and `JAR\x02` manifest remain available as a
  non-consensus execution mode during transition; consensus execution
  converges on the GP model.

## Cleanups the audit flagged

- `memoryModel` config knob is dead surface (nothing dispatches on it) —
  delete or wire honestly.
- `.basicBlockFull` gas model (32-entry ROB sim) is unused — candidate for
  deletion when Phase 3 lands per-instruction mode.
- Test-side jar1 codec selection rides on `variableValidators` instead of
  a codec knob — untangle when Phase 2 touches the loaders.
- GP debug `log` (100) hostcall unmodeled in both variants.

## Relationship to the VOS roadmap

VOS pins this fork and ships on the jar1 surface today. The vos-side
sequencing (vos `docs/plans/vos-core-execution.md`, `docs/design/
jam-entry-points.md`, `docs/design/work-result-contract.md`): Phase 1 here
gates vos A15 (guest accumulate as thin APPLY); Phases 3–4 make VOS blobs
GP-portable; Phase 6 makes the VOS agent/sub-actor model expressible
on-chain. VOS's federation showcase depends on **none** of this — it ships
on the current jar1 surface; this roadmap is the platform track underneath
it.
