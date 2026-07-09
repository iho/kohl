//! Sparse blake2 Merkle tree (Path A *maintenance*).
//!
//! Models design D11/D16 sparse slots:
//! * `grow_empty` appends a slot with leaf digest `EMPTY`
//! * `admit` overwrites an existing EMPTY slot with `L(P,C)`
//! * Membership root is a binary Merkle root over slot digests, padded with
//!   `merkle_empty_child` to the next power of two
//!
//! Transparent authentication paths are available for tests and size benches
//! only — they are **not** a valid `π` (see [`crate::fcmp_spike::sa_link`]).

use super::leaf::{
    empty_leaf_hash, empty_membership_root, leaf_hash, merkle_empty_child, merkle_node_hash,
    MAX_DEPTH,
};

/// Open Merkle authentication path (D17: **not** a valid membership proof).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentPath {
    /// Global slot index.
    pub index: u64,
    /// Leaf digest at that index (EMPTY or L).
    pub leaf_hash: [u8; 32],
    /// Sibling hashes from leaf level toward root (bottom-up).
    pub siblings: alloc::vec::Vec<[u8; 32]>,
}

impl TransparentPath {
    /// Serialized size if someone naively used this as `π` (rejected).
    pub fn encoded_len(&self) -> usize {
        8 + 32 + 4 + self.siblings.len() * 32
    }

    /// Recompute root from this path (correctness only).
    pub fn compute_root(&self) -> [u8; 32] {
        let mut h = self.leaf_hash;
        let mut idx = self.index;
        for sib in &self.siblings {
            if idx % 2 == 0 {
                h = merkle_node_hash(&h, sib);
            } else {
                h = merkle_node_hash(sib, &h);
            }
            idx /= 2;
        }
        h
    }
}

/// In-memory sparse membership tree for the PR-0 spike.
#[derive(Clone, Debug, Default)]
pub struct SparseMerkleTree {
    /// Leaf digests for slots `0..tree_slots` (EMPTY or L hash).
    leaves: alloc::vec::Vec<[u8; 32]>,
    /// Bitset-like: `true` if slot was admitted (L), `false` if still EMPTY.
    admitted: alloc::vec::Vec<bool>,
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of grown slots (`TreeSlots`).
    pub fn tree_slots(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn is_admitted(&self, index: u64) -> bool {
        self.admitted.get(index as usize).copied().unwrap_or(false)
    }

    /// Lag-aware grow: only valid when `index == tree_slots()` (steady state).
    /// Returns `false` if lagging or out of order (Building mode skips grow).
    pub fn maybe_grow_empty_on_create(&mut self, index: u64) -> bool {
        if index != self.tree_slots() {
            return false;
        }
        self.grow_empty();
        true
    }

    /// Append one EMPTY slot at the tip.
    pub fn grow_empty(&mut self) {
        assert!(
            self.leaves.len() < (1usize << MAX_DEPTH),
            "exceeded MAX_DEPTH slots"
        );
        self.leaves.push(empty_leaf_hash());
        self.admitted.push(false);
    }

    /// Sequential catch-up grow while lagging (`TreeSlots < NextOutputIndex`).
    pub fn catchup_grow_empty(&mut self, max: usize) -> usize {
        // Spike tree has no external NextOutputIndex; caller drives how many.
        let mut n = 0;
        while n < max && self.leaves.len() < (1usize << MAX_DEPTH) {
            self.grow_empty();
            n += 1;
        }
        n
    }

    /// Admit mature leaf at `index`: EMPTY → L(P,C). Fails if missing slot or
    /// already admitted.
    pub fn admit(&mut self, index: u64, p: &[u8; 32], c: &[u8; 32]) -> bool {
        let i = index as usize;
        if i >= self.leaves.len() || self.admitted[i] {
            return false;
        }
        self.leaves[i] = leaf_hash(p, c);
        self.admitted[i] = true;
        true
    }

    /// Membership root over current slots.
    pub fn root(&self) -> [u8; 32] {
        if self.leaves.is_empty() {
            return empty_membership_root();
        }
        let mut level = pad_to_power_of_two(&self.leaves);
        while level.len() > 1 {
            let mut next = alloc::vec::Vec::with_capacity(level.len() / 2);
            for pair in level.chunks_exact(2) {
                next.push(merkle_node_hash(&pair[0], &pair[1]));
            }
            level = next;
        }
        level[0]
    }

    /// Transparent auth path for slot `index` (tests / size baseline only).
    pub fn transparent_path(&self, index: u64) -> Option<TransparentPath> {
        let i = index as usize;
        if i >= self.leaves.len() {
            return None;
        }
        let level = pad_to_power_of_two(&self.leaves);
        let depth = level.len().trailing_zeros() as usize; // log2(len)
        let mut idx = i;
        // When padded, index stays the same at leaf level.
        let mut siblings = alloc::vec::Vec::with_capacity(depth);
        let mut cur = level;
        for _ in 0..depth {
            let sib_idx = idx ^ 1;
            siblings.push(cur[sib_idx]);
            // Build parent level
            let mut next = alloc::vec::Vec::with_capacity(cur.len() / 2);
            for pair in cur.chunks_exact(2) {
                next.push(merkle_node_hash(&pair[0], &pair[1]));
            }
            cur = next;
            idx /= 2;
        }
        Some(TransparentPath {
            index,
            leaf_hash: self.leaves[i],
            siblings,
        })
    }

    /// Verify a transparent path against `expected_root` (test helper).
    pub fn verify_transparent_path(path: &TransparentPath, expected_root: &[u8; 32]) -> bool {
        &path.compute_root() == expected_root
    }
}

fn pad_to_power_of_two(leaves: &[[u8; 32]]) -> alloc::vec::Vec<[u8; 32]> {
    let mut level = leaves.to_vec();
    let pad = merkle_empty_child();
    if level.is_empty() {
        return alloc::vec![pad];
    }
    let mut n = level.len().next_power_of_two();
    // Cap depth
    let max_leaves = 1usize << MAX_DEPTH;
    if n > max_leaves {
        n = max_leaves;
    }
    while level.len() < n {
        level.push(pad);
    }
    level
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fcmp_spike::leaf::empty_leaf_hash;

    fn pc(i: u8) -> ([u8; 32], [u8; 32]) {
        let mut p = [0u8; 32];
        let mut c = [0u8; 32];
        p[0] = i;
        c[0] = i.wrapping_add(100);
        // make them look distinct; validity as Ristretto not required for hash tests
        (p, c)
    }

    #[test]
    fn empty_tree_root_is_constant() {
        let t = SparseMerkleTree::new();
        assert_eq!(t.root(), empty_membership_root());
    }

    #[test]
    fn grow_and_admit_changes_root() {
        let mut t = SparseMerkleTree::new();
        let r0 = t.root();
        assert!(t.maybe_grow_empty_on_create(0));
        let r1 = t.root();
        assert_ne!(r0, r1);
        assert!(!t.is_admitted(0));
        let path0 = t.transparent_path(0).unwrap();
        assert_eq!(path0.leaf_hash, empty_leaf_hash());

        let (p, c) = pc(1);
        assert!(t.admit(0, &p, &c));
        let r2 = t.root();
        assert_ne!(r1, r2);
        assert!(t.is_admitted(0));
    }

    #[test]
    fn lag_mode_skips_out_of_order_grow() {
        let mut t = SparseMerkleTree::new();
        // Tip mint at i=5 while TreeSlots=0 → lag, no grow.
        assert!(!t.maybe_grow_empty_on_create(5));
        assert_eq!(t.tree_slots(), 0);
        // Catch-up grows 0..5
        assert_eq!(t.catchup_grow_empty(5), 5);
        assert_eq!(t.tree_slots(), 5);
        // Now steady-state grow at 5 works.
        assert!(t.maybe_grow_empty_on_create(5));
        assert_eq!(t.tree_slots(), 6);
    }

    #[test]
    fn sparse_admit_no_hol_blocking() {
        // Coinbase at 0 immature (EMPTY); transfer at 1 can still admit.
        let mut t = SparseMerkleTree::new();
        t.grow_empty(); // slot 0 coinbase
        t.grow_empty(); // slot 1 transfer
        let (p, c) = pc(7);
        assert!(t.admit(1, &p, &c));
        assert!(!t.is_admitted(0));
        assert!(t.is_admitted(1));
    }

    #[test]
    fn transparent_path_verifies() {
        let mut t = SparseMerkleTree::new();
        for i in 0..5u8 {
            t.grow_empty();
            let (p, c) = pc(i);
            assert!(t.admit(i as u64, &p, &c));
        }
        let root = t.root();
        for i in 0..5 {
            let path = t.transparent_path(i).expect("path");
            assert!(SparseMerkleTree::verify_transparent_path(&path, &root));
        }
    }

    #[test]
    fn double_admit_rejected() {
        let mut t = SparseMerkleTree::new();
        t.grow_empty();
        let (p, c) = pc(1);
        assert!(t.admit(0, &p, &c));
        assert!(!t.admit(0, &p, &c));
    }
}
