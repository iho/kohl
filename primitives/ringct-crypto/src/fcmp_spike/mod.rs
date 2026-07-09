//! # FCMP research spike (PR-0)
//!
//! Feature-gated experimental modules for Full-Chain Membership Proofs.
//! **Not consensus-critical.** Nothing here is wired into the runtime, host
//! functions, or pallet verification path.
//!
//! ## Scope (design doc PR-0)
//!
//! * Path A: blake2 sparse Merkle tree matching `docs/fcmp-design.md` leaf
//!   domains (tree *maintenance* — the easy half of A5).
//! * Transparent Merkle paths: implemented for tests/benches only; **rejected**
//!   as a membership proof encoding (D17).
//! * SA+L sketch: key-image KAT vs `clsag::key_image`, amount re-blind check.
//! * Path B: Ristretto→cycle embedding notes, literature gate table, MSM cost
//!   proxy (no Helios/Selene cycle implementation in this spike).
//! * Naive full-set ring cost model: why O(n) CLSAG cannot replace FCMP.
//!
//! Enable with `--features fcmp-spike` (implies `std`). See
//! `docs/fcmp-pr0-memo.md` for go/no-go results.

pub mod embedding;
pub mod gates;
pub mod leaf;
pub mod merkle;
pub mod naive_fullset;
pub mod sa_link;

pub use embedding::{EmbeddingSketch, LiteraturePathB, PathBAssessment};
pub use gates::{evaluate_gates, GateResult, GateSet, D2_GATES};
pub use leaf::{
    empty_leaf_hash, empty_membership_root, leaf_hash, merkle_node_hash, preimage, EMPTY_LEAF_DOM,
    LEAF_DOM, MERKLE_DOM, MERKLE_EMPTY_DOM, TREE_ARITY,
};
pub use merkle::{SparseMerkleTree, TransparentPath};
pub use naive_fullset::{estimate_clsag_sig_bytes, naive_fullset_cost};
pub use sa_link::{
    open_reblind_ok, reject_transparent_path_as_proof, sa_link_key_image, OpenSaLinkStatement,
};
