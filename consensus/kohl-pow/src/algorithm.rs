//! The `sc-consensus-pow` [`PowAlgorithm`] implementation, wiring the mining
//! core to the runtime's `DifficultyApi`. Behind the `node` feature because
//! it pulls the client stack.

use crate::mining::{verify_seal, Hasher};
use kohl_runtime_api::DifficultyApi;
use sc_client_api::backend::AuxStore;
use sc_consensus_pow::{Error, PowAlgorithm};
use sp_api::ProvideRuntimeApi;
use sp_core::U256;
use sp_runtime::{generic::BlockId, traits::Block as BlockT};
use std::sync::Arc;

/// Domain-separated RandomX epoch seed. A production node rotates this every
/// epoch off an old block hash (Monero uses ~2048 blocks); the fallback
/// `BlakeHasher` folds it into the work hash. TODO(node): wire epoch rotation.
pub const DEFAULT_SEED: &[u8] = b"kohl/randomx/seed/genesis";

/// PoW algorithm parameterized by a [`Hasher`] and the runtime client that
/// serves the difficulty.
pub struct KohlPow<C, H> {
    client: Arc<C>,
    hasher: Arc<H>,
    seed: Vec<u8>,
}

impl<C, H> Clone for KohlPow<C, H> {
    fn clone(&self) -> Self {
        Self { client: self.client.clone(), hasher: self.hasher.clone(), seed: self.seed.clone() }
    }
}

impl<C, H> KohlPow<C, H> {
    pub fn new(client: Arc<C>, hasher: Arc<H>) -> Self {
        Self { client, hasher, seed: DEFAULT_SEED.to_vec() }
    }

    pub fn with_seed(client: Arc<C>, hasher: Arc<H>, seed: Vec<u8>) -> Self {
        Self { client, hasher, seed }
    }
}

impl<B, C, H> PowAlgorithm<B> for KohlPow<C, H>
where
    B: BlockT<Hash = sp_core::H256>,
    C: ProvideRuntimeApi<B> + AuxStore + Send + Sync,
    C::Api: DifficultyApi<B>,
    H: Hasher + Send + Sync,
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
        _parent: &BlockId<B>,
        pre_hash: &B::Hash,
        _pre_digest: Option<&[u8]>,
        seal: &Vec<u8>,
        difficulty: Self::Difficulty,
    ) -> Result<bool, Error<B>> {
        Ok(verify_seal(
            &*self.hasher,
            pre_hash.as_ref(),
            &self.seed,
            seal,
            difficulty,
        ))
    }
}
