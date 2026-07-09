//! RandomX proof-of-work for the kohl chain (BLUEPRINT.md §1.4, §5.1).
//!
//! * [`mining`] — the pure, dependency-light PoW core: seal format,
//!   hash-meets-difficulty predicate, miner loop, and the `Hasher` trait with
//!   a keyed-BLAKE2b dev fallback and a RandomX production hasher
//!   (`randomx` feature). Always built; unit-tested without a node.
//! * [`algorithm`] — the `sc-consensus-pow` `PowAlgorithm` impl wired to the
//!   runtime `DifficultyApi` (`node` feature).

pub mod mining;

#[cfg(feature = "node")]
pub mod algorithm;

pub use mining::{hash_meets_difficulty, mine, verify_seal, BlakeHasher, Hasher, Seal};

#[cfg(feature = "randomx")]
pub use mining::RandomXHasher;

#[cfg(feature = "node")]
pub use algorithm::{
	seed_bytes, seed_for_parent, seed_height, KohlPow, DEFAULT_SEED, EPOCH_LENGTH, SEED_LAG,
};
