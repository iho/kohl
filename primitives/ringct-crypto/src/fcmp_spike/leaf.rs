//! Leaf and Merkle domain hashes for Path A (design § Leaf & tree encoding).
//!
//! These constants and functions are intended to freeze in PR-0b if Path A
//! tree maintenance is selected. They are **not** yet consensus.

use sp_io::hashing::blake2_256;

/// Occupied-leaf preimage domain: `LEAF_DOM || P || C`.
pub const LEAF_DOM: &[u8] = b"kohl/fcmp/leaf/v1";

/// Immature / not-yet-admitted leaf placeholder domain.
pub const EMPTY_LEAF_DOM: &[u8] = b"kohl/fcmp/leaf/empty/v1";

/// Internal Merkle node domain: `MERKLE_DOM || left || right`.
pub const MERKLE_DOM: &[u8] = b"kohl/fcmp/merkle/v1";

/// Missing child beyond `TreeSlots` (depth padding), distinct from leaf EMPTY.
pub const MERKLE_EMPTY_DOM: &[u8] = b"kohl/fcmp/merkle/v1/empty";

/// Binary tree (design: `FCMP_TREE_ARITY = 2`).
pub const TREE_ARITY: usize = 2;

/// Engineering bound: max depth 32 ⇒ max 2^32 slots.
pub const MAX_DEPTH: u32 = 32;

/// `preimage(P, C) = LEAF_DOM || P || C` (compressed Ristretto pair).
pub fn preimage(p: &[u8; 32], c: &[u8; 32]) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec::Vec::with_capacity(LEAF_DOM.len() + 64);
    v.extend_from_slice(LEAF_DOM);
    v.extend_from_slice(p);
    v.extend_from_slice(c);
    v
}

/// Occupied leaf digest `blake2_256(preimage(P,C))`.
pub fn leaf_hash(p: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    blake2_256(&preimage(p, c))
}

/// Placeholder leaf for immature / not-yet-admitted slots.
pub fn empty_leaf_hash() -> [u8; 32] {
    blake2_256(EMPTY_LEAF_DOM)
}

/// Internal node: `blake2_256(MERKLE_DOM || left || right)`.
pub fn merkle_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut v = alloc::vec::Vec::with_capacity(MERKLE_DOM.len() + 64);
    v.extend_from_slice(MERKLE_DOM);
    v.extend_from_slice(left);
    v.extend_from_slice(right);
    blake2_256(&v)
}

/// Sentinel for a missing child past `TreeSlots` when padding the tree.
pub fn merkle_empty_child() -> [u8; 32] {
    blake2_256(MERKLE_EMPTY_DOM)
}

/// Root of a tree with zero slots (no leaves grown).
pub fn empty_membership_root() -> [u8; 32] {
    // Defined as the Merkle empty-child sentinel so Building starts from a
    // fixed, domain-separated constant (design: document EMPTY_MEMBERSHIP_ROOT).
    merkle_empty_child()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_lengths_stable() {
        // Documented strings — changing them is a design amend, not a silent edit.
        assert_eq!(LEAF_DOM, b"kohl/fcmp/leaf/v1");
        assert_eq!(EMPTY_LEAF_DOM, b"kohl/fcmp/leaf/empty/v1");
        assert_eq!(MERKLE_DOM, b"kohl/fcmp/merkle/v1");
        assert_eq!(MERKLE_EMPTY_DOM, b"kohl/fcmp/merkle/v1/empty");
    }

    #[test]
    fn empty_leaf_ne_merkle_empty() {
        assert_ne!(empty_leaf_hash(), merkle_empty_child());
    }

    #[test]
    fn leaf_hash_binds_p_and_c() {
        let p = [1u8; 32];
        let c = [2u8; 32];
        let h1 = leaf_hash(&p, &c);
        let mut p2 = p;
        p2[0] ^= 1;
        assert_ne!(h1, leaf_hash(&p2, &c));
        let mut c2 = c;
        c2[0] ^= 1;
        assert_ne!(h1, leaf_hash(&p, &c2));
    }

    #[test]
    fn preimage_layout() {
        let p = [0xAAu8; 32];
        let c = [0xBBu8; 32];
        let v = preimage(&p, &c);
        assert_eq!(&v[..LEAF_DOM.len()], LEAF_DOM);
        assert_eq!(&v[LEAF_DOM.len()..LEAF_DOM.len() + 32], &p);
        assert_eq!(&v[LEAF_DOM.len() + 32..], &c);
        assert_eq!(v.len(), LEAF_DOM.len() + 64);
    }
}
