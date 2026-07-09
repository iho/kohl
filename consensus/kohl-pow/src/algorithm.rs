//! The `sc-consensus-pow` [`PowAlgorithm`] implementation, wiring the mining
//! core to the runtime's `DifficultyApi`. Behind the `node` feature because
//! it pulls the client stack.
//!
//! ## Epoch seed (RandomX / BlakeHasher domain)
//!
//! Both the importer and the miner must agree on the seed used for a block
//! built on a given parent. Kohl follows a Monero-style schedule:
//!
//! ```text
//! seed_height = floor( (parent_number − SEED_LAG) / EPOCH_LENGTH ) × EPOCH_LENGTH
//! seed_bytes  = "kohl/rx/v1" ‖ hash(block at seed_height)
//! ```
//!
//! When `parent_number ≤ SEED_LAG`, the fixed genesis domain
//! [`DEFAULT_SEED`] is used so early blocks stay well-defined.

use crate::mining::{verify_seal, Hasher};
use kohl_runtime_api::DifficultyApi;
use sc_client_api::backend::AuxStore;
use sc_consensus_pow::{Error, PowAlgorithm};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::U256;
use sp_runtime::{
	generic::BlockId,
	traits::{Block as BlockT, NumberFor},
};
use std::sync::Arc;

/// Domain tag + fixed bytes used before the first epoch seed is available.
pub const DEFAULT_SEED: &[u8] = b"kohl/randomx/seed/genesis";

/// How far behind the parent the seed block sits (reorg safety margin).
pub const SEED_LAG: u32 = 64;

/// Blocks per RandomX / seed epoch. Seed is constant for `EPOCH_LENGTH`
/// consecutive parent heights (after lag).
pub const EPOCH_LENGTH: u32 = 2048;

/// Prefix for seed material derived from a historical block hash.
const SEED_DOMAIN: &[u8] = b"kohl/rx/v1";

/// Height of the block whose hash becomes the epoch seed for a child of
/// `parent_number`, or `None` when the genesis domain seed applies.
pub fn seed_height(parent_number: u32) -> Option<u32> {
	if parent_number <= SEED_LAG {
		return None;
	}
	let lagged = parent_number - SEED_LAG;
	Some((lagged / EPOCH_LENGTH) * EPOCH_LENGTH)
}

/// Encode seed bytes from an optional historical block hash.
pub fn seed_bytes(seed_block_hash: Option<&[u8]>) -> Vec<u8> {
	match seed_block_hash {
		Some(h) if !h.is_empty() => {
			let mut out = Vec::with_capacity(SEED_DOMAIN.len() + h.len());
			out.extend_from_slice(SEED_DOMAIN);
			out.extend_from_slice(h);
			out
		}
		_ => DEFAULT_SEED.to_vec(),
	}
}

/// Resolve the PoW seed for a block built on `parent_hash` using the client's
/// header chain. Shared by the importer (`verify`) and the CPU miner.
pub fn seed_for_parent<B, C>(client: &C, parent_hash: B::Hash) -> Result<Vec<u8>, Error<B>>
where
	B: BlockT,
	C: HeaderBackend<B>,
	NumberFor<B>: TryInto<u32> + TryFrom<u32>,
{
	let parent_number = client
		.number(parent_hash)
		.map_err(|e| Error::Environment(format!("header number: {e}")))?
		.ok_or_else(|| Error::Environment("parent header missing".into()))?;
	// Epoch math is defined on u32 (kohl's BlockNumber).
	let parent_n: u32 = number_as_u32::<B>(parent_number)?;

	let Some(h) = seed_height(parent_n) else {
		return Ok(seed_bytes(None));
	};
	let seed_n = u32_as_number::<B>(h)?;
	let hash = client
		.hash(seed_n)
		.map_err(|e| Error::Environment(format!("seed hash lookup: {e}")))?
		.ok_or_else(|| Error::Environment(format!("no header at seed height {h}")))?;
	Ok(seed_bytes(Some(hash.as_ref())))
}

fn number_as_u32<B: BlockT>(n: NumberFor<B>) -> Result<u32, Error<B>>
where
	NumberFor<B>: TryInto<u32>,
{
	n.try_into().map_err(|_| Error::Environment("block number does not fit u32".into()))
}

fn u32_as_number<B: BlockT>(h: u32) -> Result<NumberFor<B>, Error<B>>
where
	NumberFor<B>: TryFrom<u32>,
{
	NumberFor::<B>::try_from(h)
		.map_err(|_| Error::Environment("seed height conversion failed".into()))
}

/// PoW algorithm parameterized by a [`Hasher`] (as a trait object so the node
/// can swap Blake / RandomX at runtime) and the client for difficulty + seeds.
pub struct KohlPow<C> {
	client: Arc<C>,
	hasher: Arc<dyn Hasher + Send + Sync>,
}

impl<C> Clone for KohlPow<C> {
	fn clone(&self) -> Self {
		Self { client: self.client.clone(), hasher: self.hasher.clone() }
	}
}

impl<C> KohlPow<C> {
	pub fn new(client: Arc<C>, hasher: Arc<dyn Hasher + Send + Sync>) -> Self {
		Self { client, hasher }
	}

	/// Expose the client so the mining thread can resolve epoch seeds.
	pub fn client(&self) -> &Arc<C> {
		&self.client
	}
}

impl<B, C> PowAlgorithm<B> for KohlPow<C>
where
	B: BlockT<Hash = sp_core::H256>,
	C: ProvideRuntimeApi<B> + AuxStore + HeaderBackend<B> + Send + Sync,
	C::Api: DifficultyApi<B>,
{
	type Difficulty = U256;

	fn difficulty(&self, parent: B::Hash) -> Result<Self::Difficulty, Error<B>> {
		self.client
			.runtime_api()
			.difficulty(parent)
			.map_err(|e| Error::Environment(format!("difficulty API failed: {e}")))
	}

	fn verify(
		&self,
		parent: &BlockId<B>,
		pre_hash: &B::Hash,
		_pre_digest: Option<&[u8]>,
		seal: &Vec<u8>,
		difficulty: Self::Difficulty,
	) -> Result<bool, Error<B>> {
		let parent_hash = match parent {
			BlockId::Hash(h) => *h,
			BlockId::Number(n) => self
				.client
				.hash(*n)
				.map_err(|e| Error::Environment(format!("parent hash: {e}")))?
				.ok_or_else(|| Error::Environment("parent number unknown".into()))?,
		};
		let seed = seed_for_parent::<B, C>(&*self.client, parent_hash)?;
		Ok(verify_seal(&*self.hasher, pre_hash.as_ref(), &seed, seal, difficulty))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn seed_height_uses_genesis_domain_early() {
		assert_eq!(seed_height(0), None);
		assert_eq!(seed_height(SEED_LAG), None);
		assert_eq!(seed_height(SEED_LAG + 1), Some(0));
	}

	#[test]
	fn seed_height_floors_to_epoch() {
		// parent 64+2048+10 = 2122 → lagged 2058 → floor to 2048
		assert_eq!(seed_height(SEED_LAG + EPOCH_LENGTH + 10), Some(EPOCH_LENGTH));
		// parent 64+2047 → lagged 2047 → floor to 0
		assert_eq!(seed_height(SEED_LAG + EPOCH_LENGTH - 1), Some(0));
	}

	#[test]
	fn seed_bytes_domain_separate_hashes() {
		let a = seed_bytes(Some(&[1u8; 32]));
		let b = seed_bytes(Some(&[2u8; 32]));
		assert_ne!(a, b);
		assert!(a.starts_with(SEED_DOMAIN));
		assert_eq!(seed_bytes(None), DEFAULT_SEED);
	}
}
