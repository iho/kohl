//! Runtime API declarations for the kohl chain.
//!
//! Kept in a standalone crate so the node, the PoW algorithm and wallets can
//! call these APIs without depending on the full runtime, and without a
//! dependency cycle (the runtime *implements* them).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use pallet_ringct::StoredOutput;
use sp_core::U256;

/// Block number type used across the API surface.
pub type BlockNumber = u32;

sp_api::decl_runtime_apis! {
    /// PoW difficulty for the next block — read by `sc-consensus-pow`.
    pub trait DifficultyApi {
        fn difficulty() -> U256;
    }

    /// Wallet-facing queries for scanning and fee estimation (BLUEPRINT.md §4.4).
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
    }
}
