#!/usr/bin/env python3
"""
Generate Lean test files from disputes JSON test vectors.

Usage:
  python3 tools/gen_disputes_tests.py <test_vectors_dir> <output_lean_file>
"""

import json
import os
import sys
from pathlib import Path


def hex_to_lean(hex_str: str) -> str:
    h = hex_str.removeprefix("0x")
    return f'hexSeq "{h}"'


def gen_vote(v: dict) -> str:
    vote = "true" if v["vote"] else "false"
    sig = hex_to_lean(v["signature"])
    return f"{{ vote := {vote}, index := {v['index']}, signature := {sig} }}"


def gen_verdict(v: dict, name_prefix: str, idx: int) -> (str, str):
    """Returns (def_lines, reference_name) for a verdict extracted to its own def."""
    vote_lines = []
    for j in v["votes"]:
        vote = "true" if j["vote"] else "false"
        sig = hex_to_lean(j["signature"])
        vote_lines.append(f"  {{ vote := {vote}, index := {j['index']}, signature := {sig} }}")
    votes_str = ",\n".join(vote_lines)
    ref = f"{name_prefix}_verdict_{idx}"
    defn = (
        f"def {ref} : TDVerdict := {{\n"
        f"  target := {hex_to_lean(v['target'])},\n"
        f"  age := {v['age']},\n"
        f"  votes := #[\n{votes_str}] }}"
    )
    return defn, ref


def gen_culprit(c: dict, name_prefix: str, idx: int) -> (str, str):
    ref = f"{name_prefix}_culprit_{idx}"
    defn = (
        f"def {ref} : TDCulprit := {{\n"
        f"  target := {hex_to_lean(c['target'])},\n"
        f"  key := {hex_to_lean(c['key'])},\n"
        f"  signature := {hex_to_lean(c['signature'])} }}"
    )
    return defn, ref


def gen_fault(f: dict, name_prefix: str, idx: int) -> (str, str):
    vote = "true" if f["vote"] else "false"
    ref = f"{name_prefix}_fault_{idx}"
    defn = (
        f"def {ref} : TDFault := {{\n"
        f"  target := {hex_to_lean(f['target'])},\n"
        f"  vote := {vote},\n"
        f"  key := {hex_to_lean(f['key'])},\n"
        f"  signature := {hex_to_lean(f['signature'])} }}"
    )
    return defn, ref


def gen_validator_key(vk: dict) -> str:
    bs = vk["bandersnatch"].removeprefix("0x")
    ed = vk["ed25519"].removeprefix("0x")
    bl = vk["bls"].removeprefix("0x")
    mt = vk["metadata"].removeprefix("0x")
    return f'mkVK "{bs}" "{ed}" "{bl}" "{mt}"'


def gen_judgments(psi: dict, name: str) -> str:
    lines = []

    def gen_hash_array(arr, field_name):
        if not arr:
            return f"  {field_name} := #[]"
        items = ",\n    ".join(hex_to_lean(h) for h in arr)
        return f"  {field_name} := #[\n    {items}]"

    def gen_key_array(arr, field_name):
        if not arr:
            return f"  {field_name} := #[]"
        items = ",\n    ".join(hex_to_lean(k) for k in arr)
        return f"  {field_name} := #[\n    {items}]"

    lines.append(f"def {name} : TDJudgments := {{")
    lines.append(gen_hash_array(psi["good"], "good") + ",")
    lines.append(gen_hash_array(psi["bad"], "bad") + ",")
    lines.append(gen_hash_array(psi["wonky"], "wonky") + ",")
    lines.append(gen_key_array(psi["offenders"], "offenders"))
    lines.append("}")
    return "\n".join(lines)


def gen_state(s: dict, name: str) -> str:
    lines = []

    # Judgments
    lines.append(gen_judgments(s["psi"], f"{name}_psi"))
    lines.append("")

    # Validators
    kappa = s["kappa"]
    kappa_items = ",\n    ".join(gen_validator_key(vk) for vk in kappa)
    lines.append(f"def {name}_kappa : Array ValidatorKey := #[\n    {kappa_items}]")
    lines.append("")

    lam = s["lambda"]
    lam_items = ",\n    ".join(gen_validator_key(vk) for vk in lam)
    lines.append(f"def {name}_lambda : Array ValidatorKey := #[\n    {lam_items}]")
    lines.append("")

    # rho (simplified to boolean array)
    rho_items = ", ".join("true" if r is not None else "false" for r in s["rho"])
    lines.append(f"def {name}_rho : Array Bool := #[{rho_items}]")
    lines.append("")

    lines.append(f"def {name} : TDState := {{")
    lines.append(f"  psi := {name}_psi,")
    lines.append(f"  rho := {name}_rho,")
    lines.append(f"  tau := {s['tau']},")
    lines.append(f"  kappa := {name}_kappa,")
    lines.append(f"  lambda := {name}_lambda")
    lines.append("}")
    return "\n".join(lines)


def gen_input(inp: dict, name: str) -> str:
    """Generate input def. Returns (preamble_defs, input_def) as a single string."""
    disp = inp["disputes"]
    all_lines = []

    # Extract verdicts as separate defs
    verdict_refs = []
    for i, v in enumerate(disp["verdicts"]):
        defn, ref = gen_verdict(v, name, i)
        all_lines.append(defn)
        all_lines.append("")
        verdict_refs.append(ref)

    # Extract culprits as separate defs
    culprit_refs = []
    for i, c in enumerate(disp["culprits"]):
        defn, ref = gen_culprit(c, name, i)
        all_lines.append(defn)
        all_lines.append("")
        culprit_refs.append(ref)

    # Extract faults as separate defs
    fault_refs = []
    for i, f in enumerate(disp["faults"]):
        defn, ref = gen_fault(f, name, i)
        all_lines.append(defn)
        all_lines.append("")
        fault_refs.append(ref)

    verdicts_str = "#[" + ", ".join(verdict_refs) + "]" if verdict_refs else "#[]"
    culprits_str = "#[" + ", ".join(culprit_refs) + "]" if culprit_refs else "#[]"
    faults_str = "#[" + ", ".join(fault_refs) + "]" if fault_refs else "#[]"

    all_lines.append(f"def {name} : TDInput := {{")
    all_lines.append(f"  verdicts := {verdicts_str},")
    all_lines.append(f"  culprits := {culprits_str},")
    all_lines.append(f"  faults := {faults_str}")
    all_lines.append("}")
    return "\n".join(all_lines)


def gen_result(output: dict, name: str) -> str:
    if output is None:
        return f"def {name} : TDResult := .ok #[]"
    if "err" in output:
        return f'def {name} : TDResult := .err "{output["err"]}"'
    if "ok" in output:
        ok = output["ok"]
        if ok is None:
            return f"def {name} : TDResult := .ok #[]"
        marks = ok.get("offenders_mark", [])
        if not marks:
            return f"def {name} : TDResult := .ok #[]"
        items = ",\n    ".join(hex_to_lean(k) for k in marks)
        return f"def {name} : TDResult := .ok #[\n    {items}]"
    return f"def {name} : TDResult := .ok #[]"


def sanitize_name(filename: str) -> str:
    name = Path(filename).stem
    return name.replace("-", "_")


def check_validators_equal(a, b):
    return a == b


def generate_test_file(test_dir: str, output_file: str):
    json_files = sorted(f for f in os.listdir(test_dir) if f.endswith(".json"))

    if not json_files:
        print(f"No JSON files found in {test_dir}")
        sys.exit(1)

    print(f"Generating tests for {len(json_files)} test vectors...")

    lines = []
    lines.append("import Jar.Test.Disputes")
    lines.append("")
    lines.append("/-! Auto-generated disputes test vectors. Do not edit. -/")
    lines.append("")
    lines.append("namespace Jar.Test.DisputesVectors")
    lines.append("")
    lines.append("open Jar.Test.Disputes")
    lines.append("")

    # Helpers
    lines.append("def hexToBytes (s : String) : ByteArray :=")
    lines.append("  let chars := s.toList")
    lines.append("  let nibble (c : Char) : UInt8 :=")
    lines.append("    if c.toNat >= 48 && c.toNat <= 57 then (c.toNat - 48).toUInt8")
    lines.append("    else if c.toNat >= 97 && c.toNat <= 102 then (c.toNat - 87).toUInt8")
    lines.append("    else if c.toNat >= 65 && c.toNat <= 70 then (c.toNat - 55).toUInt8")
    lines.append("    else 0")
    lines.append("  let rec go (cs : List Char) (acc : ByteArray) : ByteArray :=")
    lines.append("    match cs with")
    lines.append("    | hi :: lo :: rest => go rest (acc.push ((nibble hi <<< 4) ||| nibble lo))")
    lines.append("    | _ => acc")
    lines.append("  go chars ByteArray.empty")
    lines.append("")
    lines.append("def hexSeq (s : String) : OctetSeq n := ⟨hexToBytes s, sorry⟩")
    lines.append("")
    lines.append("def mkVK (bs ed bl mt : String) : ValidatorKey := {")
    lines.append("  bandersnatch := hexSeq bs,")
    lines.append("  ed25519 := hexSeq ed,")
    lines.append("  bls := hexSeq bl,")
    lines.append("  metadata := hexSeq mt }")
    lines.append("")

    test_names = []
    for json_file in json_files:
        with open(os.path.join(test_dir, json_file)) as f:
            data = json.load(f)

        test_name = sanitize_name(json_file)
        test_names.append(test_name)

        lines.append(f"-- ============================================================================")
        lines.append(f"-- {json_file}")
        lines.append(f"-- ============================================================================")
        lines.append("")

        pre = data["pre_state"]
        post = data["post_state"]
        inp = data["input"]
        output = data["output"]

        # Pre state
        lines.append(gen_state(pre, f"{test_name}_pre"))
        lines.append("")

        # Post state — reuse validators if same
        lines.append(gen_judgments(post["psi"], f"{test_name}_post_psi"))
        lines.append("")

        if check_validators_equal(pre["kappa"], post["kappa"]):
            lines.append(f"def {test_name}_post_kappa : Array ValidatorKey := {test_name}_pre_kappa")
        else:
            kappa_items = ",\n    ".join(gen_validator_key(vk) for vk in post["kappa"])
            lines.append(f"def {test_name}_post_kappa : Array ValidatorKey := #[\n    {kappa_items}]")
        lines.append("")

        if check_validators_equal(pre["lambda"], post["lambda"]):
            lines.append(f"def {test_name}_post_lambda : Array ValidatorKey := {test_name}_pre_lambda")
        else:
            lam_items = ",\n    ".join(gen_validator_key(vk) for vk in post["lambda"])
            lines.append(f"def {test_name}_post_lambda : Array ValidatorKey := #[\n    {lam_items}]")
        lines.append("")

        rho_items = ", ".join("true" if r is not None else "false" for r in post["rho"])
        lines.append(f"def {test_name}_post_rho : Array Bool := #[{rho_items}]")
        lines.append("")

        lines.append(f"def {test_name}_post : TDState := {{")
        lines.append(f"  psi := {test_name}_post_psi,")
        lines.append(f"  rho := {test_name}_post_rho,")
        lines.append(f"  tau := {post['tau']},")
        lines.append(f"  kappa := {test_name}_post_kappa,")
        lines.append(f"  lambda := {test_name}_post_lambda")
        lines.append("}")
        lines.append("")

        # Input
        lines.append(gen_input(inp, f"{test_name}_input"))
        lines.append("")

        # Expected result
        lines.append(gen_result(output, f"{test_name}_result"))
        lines.append("")

    # Test runner
    lines.append("-- ============================================================================")
    lines.append("-- Test Runner")
    lines.append("-- ============================================================================")
    lines.append("")
    lines.append("end Jar.Test.DisputesVectors")
    lines.append("")
    lines.append("open Jar.Test.Disputes Jar.Test.DisputesVectors in")
    lines.append("def main : IO Unit := do")
    lines.append('  IO.println "Running disputes test vectors..."')
    lines.append("  let mut passed := (0 : Nat)")
    lines.append("  let mut failed := (0 : Nat)")

    for name in test_names:
        lines.append(
            f'  if (← runTest "{name}" {name}_pre {name}_input {name}_result {name}_post_psi)'
        )
        lines.append(f"  then passed := passed + 1")
        lines.append(f"  else failed := failed + 1")

    lines.append(
        f'  IO.println s!"Disputes: {{passed}} passed, {{failed}} failed out of {len(test_names)}"'
    )
    lines.append("  if failed > 0 then")
    lines.append("    IO.Process.exit 1")

    with open(output_file, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Generated {output_file} with {len(test_names)} test cases")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <test_vectors_dir> <output_lean_file>")
        sys.exit(1)
    generate_test_file(sys.argv[1], sys.argv[2])
