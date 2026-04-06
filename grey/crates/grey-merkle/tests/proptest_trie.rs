//! Property-based tests for the Merkle trie.

use grey_merkle::trie::merkle_root;
use grey_types::Hash;
use proptest::prelude::*;

/// Generate a random 31-byte key (trie keys are 31 bytes, padded to 32 for the function).
fn arb_key() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 32..=32)
}

/// Generate a random value (1-64 bytes, covering both embedded and hashed leaf paths).
fn arb_value() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..=64)
}

/// Generate a list of unique key-value pairs.
fn arb_kvs(max_len: usize) -> impl Strategy<Value = Vec<(Vec<u8>, Vec<u8>)>> {
    prop::collection::vec((arb_key(), arb_value()), 0..=max_len).prop_map(|mut kvs| {
        // Deduplicate by key (keep first occurrence)
        let mut seen = std::collections::HashSet::new();
        kvs.retain(|kv| seen.insert(kv.0.clone()));
        kvs
    })
}

proptest! {
    #[test]
    fn empty_kvs_returns_zero_hash(_dummy in 0u8..1) {
        let root = merkle_root(&[]);
        prop_assert_eq!(root, Hash::ZERO);
    }

    #[test]
    fn single_kv_produces_nonzero_hash(
        key in arb_key(),
        value in arb_value(),
    ) {
        let kvs: Vec<(&[u8], &[u8])> = vec![(&key, &value)];
        let root = merkle_root(&kvs);
        prop_assert_ne!(root, Hash::ZERO, "single KV should produce non-zero root");
    }

    #[test]
    fn deterministic_root(kvs in arb_kvs(8)) {
        let refs: Vec<(&[u8], &[u8])> = kvs.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect();
        let root1 = merkle_root(&refs);
        let root2 = merkle_root(&refs);
        prop_assert_eq!(root1, root2, "same inputs should produce same root");
    }

    #[test]
    fn different_values_different_roots(
        key in arb_key(),
        value1 in prop::collection::vec(any::<u8>(), 1..=32),
        value2 in prop::collection::vec(any::<u8>(), 1..=32),
    ) {
        prop_assume!(value1 != value2);
        let root1 = merkle_root(&[(&key, &value1)]);
        let root2 = merkle_root(&[(&key, &value2)]);
        prop_assert_ne!(root1, root2, "different values for same key should produce different roots");
    }

    #[test]
    fn adding_kv_changes_root(kvs in arb_kvs(4)) {
        prop_assume!(!kvs.is_empty());
        let refs: Vec<(&[u8], &[u8])> = kvs.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect();
        let full_root = merkle_root(&refs);
        let partial_root = merkle_root(&refs[..refs.len() - 1]);
        prop_assert_ne!(full_root, partial_root, "adding a KV should change the root");
    }

    /// Merkle root must be independent of the input order.
    /// Shuffling the key-value pairs should produce the same root hash.
    #[test]
    fn order_independent_root(kvs in arb_kvs(8), seed: u64) {
        prop_assume!(kvs.len() >= 2);
        let refs: Vec<(&[u8], &[u8])> = kvs.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect();
        let root_original = merkle_root(&refs);

        // Shuffle using a deterministic permutation derived from the seed
        let mut shuffled = refs.clone();
        // Simple Fisher-Yates with deterministic seed
        let mut rng = seed;
        for i in (1..shuffled.len()).rev() {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let j = (rng as usize) % (i + 1);
            shuffled.swap(i, j);
        }

        let root_shuffled = merkle_root(&shuffled);
        prop_assert_eq!(root_original, root_shuffled, "root should be order-independent");
    }
}
