//! Runtime API declarations for the kohl chain.
//!
//! Kept in a standalone crate so the node, the PoW algorithm and wallets can
//! call these APIs without depending on the full runtime, and without a
//! dependency cycle (the runtime *implements* them).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use pallet_ringct::{MembershipBackfillStatus, StoredOutput};
use sp_core::U256;

/// Block number type used across the API surface.
pub type BlockNumber = u32;

sp_api::decl_runtime_apis! {
    /// PoW difficulty for the next block — read by `sc-consensus-pow`.
    pub trait DifficultyApi {
        fn difficulty() -> U256;
    }

    /// Wallet-facing queries for scanning, fees, and membership tree reads
    /// (BLUEPRINT.md §4.4; FCMP PR-3).
    pub trait RingCtApi {
        /// Outputs (with their global indices) created in `[from, to]`.
        /// The wallet-scanning feed: clients pull ranges and test view tags.
        fn outputs_in_range(from: BlockNumber, to: BlockNumber)
            -> Vec<(u64, StoredOutput<BlockNumber>)>;

        /// Number of outputs created per block over `[from, to]` — input to
        /// the wallet's gamma decoy sampler.
        fn output_distribution(from: BlockNumber, to: BlockNumber) -> Vec<u64>;

        /// Total outputs ever created (upper bound for decoy indices).
        fn output_count() -> u64;

        /// Whether a key image has been spent.
        fn is_key_image_spent(key_image: [u8; 32]) -> bool;

        /// Current minimum fee per encoded byte.
        fn min_fee_per_byte() -> u64;

        // ---- Membership tree (Path A scaffolding; PR-3) ----

        /// Current membership Merkle root.
        fn membership_root() -> [u8; 32];

        /// Historical root at the end of `block`, if retained in the window.
        fn membership_root_at(block: BlockNumber) -> Option<[u8; 32]>;

        /// Number of grown tree slots (`TreeSlots`).
        fn tree_slots() -> u64;

        /// Whether slot `index` has been filled with `L(P,C)`.
        fn is_admitted(index: u64) -> bool;

        /// Leaf digest at `index` (`EMPTY` or `L`), if the slot exists.
        fn membership_leaf_digest(index: u64) -> Option<[u8; 32]>;

        /// SCALE `Vec<[u8; 32]>` of digests for `0..tree_slots` (v1 full dump).
        fn membership_frontier() -> Vec<u8>;

        /// Spend-path mode: `1` = Building (CLSAG + tree), `2` = FcmpOnly.
        fn fcmp_mode() -> u8;

        /// Round-robin admit scan cursor.
        fn admit_scan_cursor() -> u64;

        /// Lag / catch-up snapshot for operators and provers.
        fn membership_backfill_status() -> MembershipBackfillStatus;
    }
}
