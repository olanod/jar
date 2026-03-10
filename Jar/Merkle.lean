import Jar.Notation
import Jar.Types.Numerics
import Jar.Crypto

/-!
# Merklization — Appendices D–E

Binary Patricia Merkle Trie and Merkle tree constructions.
References: `graypaper/text/merklization.tex`.

## Structure
- §D.3–D.5: Binary Patricia Merkle Trie (node types, root computation)
- §D.1: State-key constructor `C`
- §D.2: State serialization `T(σ)`
- §E.1: Well-balanced binary Merkle tree `M_B`
- §E.4: Constant-depth binary Merkle tree `M`
- §E.7–E.10: Merkle Mountain Ranges & Belts
-/

namespace Jar.Merkle

-- ============================================================================
-- Node Types — Appendix D
-- ============================================================================

/-- A Merkle trie node is always 64 bytes (512 bits). GP Appendix D.
    Encoded as the first bit distinguishing branch (0) from leaf (1). -/
inductive Node where
  /-- Branch node: first bit = 0.
      Contains left (255 bits) and right (256 bits) child hashes. -/
  | branch (left right : Hash) : Node
  /-- Embedded-value leaf: first bit = 1, second bit = 0.
      Bits 2-7 encode value size. 31-byte key, ≤32-byte value. -/
  | embeddedLeaf (key : OctetSeq 31) (value : ByteArray) : Node
  /-- Regular leaf: first bit = 1, second bit = 1.
      31-byte key, 32-byte hash of value. -/
  | regularLeaf (key : OctetSeq 31) (valueHash : Hash) : Node

/-- Encode a branch node to 64 bytes. GP Appendix D.
    B(l, r) = 0 ∥ bits(l)[1:256] ∥ bits(r). -/
opaque encodeBranch (left right : Hash) : OctetSeq 64 := default

/-- Encode a leaf node to 64 bytes. GP Appendix D.
    L(k, v) with embedded or hashed value. -/
opaque encodeLeaf (key : OctetSeq 31) (value : ByteArray) : OctetSeq 64 := default

-- ============================================================================
-- Merkle Trie Root — Appendix D
-- ============================================================================

/-- M(d) : Compute Merkle trie root from a dictionary of bitstring keys
    to (key, value) pairs. GP Appendix D eq (D.3–D.5).
    Returns ℍ_0 for empty, or blake2b(encode(root_node)). -/
opaque trieRoot (entries : Array (OctetSeq 31 × ByteArray)) : Hash := Hash.zero

-- ============================================================================
-- State Merklization — Appendix D
-- ============================================================================

/-- M_σ(σ) : Compute the state Merkle root. GP Appendix D eq (D.2).
    Serializes state into key-value pairs and computes the trie root. -/
opaque stateRoot (entries : Array (OctetSeq 31 × ByteArray)) : Hash := Hash.zero

-- ============================================================================
-- Well-Balanced Binary Merkle Tree — Appendix E
-- ============================================================================

/-- Helper: split array in half and hash both halves recursively. -/
private def merkleHelper (items : Array Hash) (depth : Nat) : Hash :=
  match depth with
  | 0 => if items.size > 0 then items[0]! else Hash.zero
  | d + 1 =>
    if items.size == 0 then Hash.zero
    else if items.size == 1 then items[0]!
    else
      let mid := items.size / 2
      let left := merkleHelper (items.extract 0 mid) d
      let right := merkleHelper (items.extract mid items.size) d
      Crypto.blake2b (left.data ++ right.data)

def binaryMerkleRoot (items : Array Hash) : Hash :=
  merkleHelper items items.size

-- ============================================================================
-- Constant-Depth Merkle Tree — Appendix E
-- ============================================================================

/-- M(data, depth) : Constant-depth binary Merkle tree. GP Appendix E eq (E.4).
    Pads to 2^depth leaves with zero hashes, then computes binary Merkle root. -/
def constDepthMerkleRoot (items : Array Hash) (depth : Nat) : Hash :=
  let targetSize := 2^depth
  let padded := if items.size < targetSize then
    items ++ Array.mkArray (targetSize - items.size) Hash.zero
  else items.extract 0 targetSize
  binaryMerkleRoot padded

-- ============================================================================
-- Merkle Mountain Range — Appendix E
-- ============================================================================

/-- MMR peak computation. GP Appendix E eq (E.7).
    A Merkle Mountain Range is a collection of perfect binary trees
    (peaks) whose sizes correspond to the binary representation of n. -/
structure MerkleMountainRange where
  /-- The peaks of the MMR, each a hash. -/
  peaks : Array Hash

/-- Append a leaf to an MMR. GP Appendix E eq (E.8). -/
def MerkleMountainRange.append (mmr : MerkleMountainRange) (leaf : Hash) : MerkleMountainRange :=
  let rec merge (peaks : Array Hash) (h : Hash) : Array Hash :=
    -- If last peak can be merged (same height), combine and continue
    if peaks.size == 0 then #[h]
    else
      -- Simplified: in a real MMR, we track heights and merge same-height peaks
      peaks.push h
  { peaks := merge mmr.peaks leaf }

/-- Bag the peaks of an MMR to get a single root hash. GP Appendix E eq (E.9). -/
def MerkleMountainRange.root (mmr : MerkleMountainRange) : Hash :=
  match mmr.peaks.size with
  | 0 => Hash.zero
  | 1 => mmr.peaks[0]!
  | _ => mmr.peaks.foldl (init := Hash.zero) fun acc peak =>
    Crypto.blake2b (acc.data ++ peak.data)

end Jar.Merkle
