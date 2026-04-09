import Jar.Erasure

/-!
# Erasure Coding Proofs

Properties of Reed-Solomon erasure coding constants and utility functions:
GF(2^16) field parameters, Cantor basis size, and shard relationships.
-/

namespace Jar.Proofs

-- ============================================================================
-- GF(2^16) field constants
-- ============================================================================

/-- GF(2^16) has order 65536 = 2^16. -/
theorem gf_order_value : Jar.Erasure.GF_ORDER = 65536 := by rfl

/-- GF element bit width is 16. -/
theorem gf_bits_value : Jar.Erasure.GF_BITS = 16 := by rfl

/-- GF modulus is 2^16 - 1 = 65535. -/
theorem gf_modulus_value : Jar.Erasure.GF_MODULUS = 65535 := by rfl

/-- GF order equals 2^GF_BITS. -/
theorem gf_order_eq_pow_bits :
    Jar.Erasure.GF_ORDER = 2 ^ Jar.Erasure.GF_BITS := by rfl

/-- Cantor basis has exactly 16 elements (one per GF bit). -/
theorem cantor_basis_size : Jar.Erasure.CANTOR_BASIS.size = 16 := by rfl

-- ============================================================================
-- Utility function properties
-- ============================================================================

/-- nextMultipleOf n 1 = n (every number is a multiple of 1). -/
theorem nextMultipleOf_one (n : Nat) :
    Jar.Erasure.nextMultipleOf n 1 = n := by
  unfold Jar.Erasure.nextMultipleOf
  simp

-- ============================================================================
-- Shard relationships
-- ============================================================================

/-- pieceSize is twice the number of data shards. -/
theorem pieceSize_eq_double_dataShards [JarConfig] :
    Jar.Erasure.pieceSize = 2 * Jar.Erasure.dataShards := by
  unfold Jar.Erasure.pieceSize Jar.Erasure.dataShards
  omega

end Jar.Proofs
