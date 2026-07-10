//! Path A membership **tree maintenance** (PR-1; freeze PR-0b / PR-10).
//!
//! Pure-runtime blake2 Merkle over sparse slots aligned to global output
//! indices. Production spends are FCMP-only (PR-7); maturity is implied by
//! non-EMPTY admission (D11). Domains are consensus-critical
//! (`docs/fcmp-mainnet-freeze.md`).

use alloc::vec::Vec;
use ringct_primitives::{
    FCMP_EMPTY_LEAF_DOM, FCMP_LEAF_DOM, FCMP_MERKLE_DOM, FCMP_MERKLE_EMPTY_DOM,
};
use sp_io::hashing::blake2_256;

/// Occupied leaf digest: `blake2_256(FCMP_LEAF_DOM || P || C)`.
pub fn leaf_hash(p: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let mut v = Vec::with_capacity(FCMP_LEAF_DOM.len() + 64);
    v.extend_from_slice(FCMP_LEAF_DOM);
    v.extend_from_slice(p);
    v.extend_from_slice(c);
    blake2_256(&v)
}

/// Placeholder leaf for immature / not-yet-admitted slots.
pub fn empty_leaf_hash() -> [u8; 32] {
    blake2_256(FCMP_EMPTY_LEAF_DOM)
}

/// Internal node: `blake2_256(FCMP_MERKLE_DOM || left || right)`.
pub fn merkle_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut v = Vec::with_capacity(FCMP_MERKLE_DOM.len() + 64);
    v.extend_from_slice(FCMP_MERKLE_DOM);
    v.extend_from_slice(left);
    v.extend_from_slice(right);
    blake2_256(&v)
}

/// Sentinel for a missing child when padding to a power of two.
pub fn merkle_empty_child() -> [u8; 32] {
    blake2_256(FCMP_MERKLE_EMPTY_DOM)
}

/// Root of a tree with zero slots.
pub fn empty_membership_root() -> [u8; 32] {
    merkle_empty_child()
}

/// Binary Merkle root over leaf digests `0..n`, padded with
/// [`merkle_empty_child`] to the next power of two.
///
/// PR-1 uses full recompute (O(n)); a frontier structure is a later polish.
pub fn root_from_leaves(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return empty_membership_root();
    }
    let pad = merkle_empty_child();
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let n = level.len().next_power_of_two();
    while level.len() < n {
        level.push(pad);
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(merkle_node_hash(&pair[0], &pair[1]));
        }
        level = next;
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_root_is_merkle_empty_sentinel() {
        assert_eq!(empty_membership_root(), merkle_empty_child());
        assert_ne!(empty_leaf_hash(), merkle_empty_child());
    }

    #[test]
    fn root_changes_when_leaf_fills() {
        let empty = empty_leaf_hash();
        let r0 = root_from_leaves(&[empty]);
        let occupied = leaf_hash(&[1u8; 32], &[2u8; 32]);
        let r1 = root_from_leaves(&[occupied]);
        assert_ne!(r0, r1);
    }

    #[test]
    fn sparse_second_leaf() {
        let e = empty_leaf_hash();
        let l = leaf_hash(&[9u8; 32], &[8u8; 32]);
        // slot0 EMPTY, slot1 L — root differs from both EMPTY
        let r = root_from_leaves(&[e, l]);
        assert_ne!(r, root_from_leaves(&[e, e]));
        assert_ne!(r, root_from_leaves(&[l, l]));
    }
}
