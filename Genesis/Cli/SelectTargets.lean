/-
  genesis_select_targets CLI

  Input:  {"prId": 42, "prCreatedAt": 1774000000, "indices": [...]}
  Output: {"targets": ["abc123", ...]}
-/

import Genesis.Cli.Common

open Lean (Json ToJson toJson fromJson? FromJson)
open Genesis.Cli

def main : IO UInt32 := runJsonPipe fun j => do
  let prId ← IO.ofExcept (j.getObjValAs? Nat "prId")
  let prCreatedAt ← IO.ofExcept (j.getObjValAs? Nat "prCreatedAt")
  let indices ← IO.ofExcept (j.getObjValAs? (List CommitIndex) "indices")
  let scoredCommits := indices.map (fun idx => (idx.commitHash, idx.epoch))
  let eligible := scoredCommits.filter (fun (_, epoch) => epoch < prCreatedAt)
  let targets := selectComparisonTargets scoredCommits (min rankingSize eligible.length) prId prCreatedAt
  return Json.mkObj [("targets", toJson targets)]
