//! Pure proof-of-work mining core — no client or runtime dependencies, so
//! it unit-tests without a node. This is the algorithmic heart: the seal
//! format, the hash-meets-difficulty predicate, and a miner loop.
//!
//! The hasher is pluggable via [`Hasher`]. Production uses RandomX (the
//! `randomx` feature, [`RandomXHasher`]); a keyed BLAKE2b fallback
//! ([`BlakeHasher`]) keeps everything testable without the C++ toolchain and
//! is also handy for dev chains.

use blake2::{digest::consts::U32, Blake2b, Digest};
use codec::{Decode, Encode};
use sp_core::U256;

/// The PoW seal embedded in a block's digest: the winning nonce plus the
/// work hash it produced (the verifier recomputes and checks both).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Seal {
    pub nonce: u64,
    pub work: [u8; 32],
}

impl Seal {
    pub fn encode_seal(&self) -> Vec<u8> {
        self.encode()
    }
    pub fn decode_seal(mut bytes: &[u8]) -> Option<Self> {
        Seal::decode(&mut bytes).ok()
    }
}

/// Something that turns (pre-hash, seed, nonce) into a 32-byte work hash.
/// `seed` is the RandomX epoch key (hash of an old block); ignored by hashers
/// that don't need it.
pub trait Hasher {
    fn hash(&self, pre_hash: &[u8], seed: &[u8], nonce: u64) -> [u8; 32];
}

/// A work hash meets `difficulty` when, interpreted as a big-endian integer,
/// it is `<= U256::MAX / difficulty`. Difficulty is thus the expected number
/// of hashes per solution (Bitcoin/Kulupu convention). Difficulty 0 is
/// treated as 1 (always satisfiable).
pub fn hash_meets_difficulty(work: &[u8; 32], difficulty: U256) -> bool {
    let target = U256::MAX / difficulty.max(U256::one());
    U256::from_big_endian(work) <= target
}

/// Recompute the work from `pre_hash`/`seed`/`seal.nonce` and check it both
/// matches the claimed work and meets `difficulty`. Recomputing (rather than
/// trusting `seal.work`) is what makes the seal unforgeable.
pub fn verify_seal<H: Hasher + ?Sized>(
    hasher: &H,
    pre_hash: &[u8],
    seed: &[u8],
    seal_bytes: &[u8],
    difficulty: U256,
) -> bool {
    let Some(seal) = Seal::decode_seal(seal_bytes) else {
        return false;
    };
    let work = hasher.hash(pre_hash, seed, seal.nonce);
    work == seal.work && hash_meets_difficulty(&work, difficulty)
}

/// Try nonces in `[start, start + rounds)` for a valid seal. Returns the
/// first winning seal, or `None` if the range is exhausted (the miner loop
/// calls this repeatedly with fresh ranges).
pub fn mine<H: Hasher + ?Sized>(
    hasher: &H,
    pre_hash: &[u8],
    seed: &[u8],
    difficulty: U256,
    start: u64,
    rounds: u64,
) -> Option<Seal> {
    (start..start.saturating_add(rounds)).find_map(|nonce| {
        let work = hasher.hash(pre_hash, seed, nonce);
        hash_meets_difficulty(&work, difficulty).then_some(Seal { nonce, work })
    })
}

/// Keyed BLAKE2b hasher — the ASIC-friendly dev/test fallback. **Not** for
/// production mainnet, where RandomX provides the CPU-bound, ASIC-resistant
/// PoW the security model in BLUEPRINT.md §1.4 relies on.
#[derive(Clone, Default)]
pub struct BlakeHasher;

impl Hasher for BlakeHasher {
    fn hash(&self, pre_hash: &[u8], seed: &[u8], nonce: u64) -> [u8; 32] {
        let mut h = Blake2b::<U32>::new();
        h.update(b"kohl/pow/blake/v1");
        h.update(seed);
        h.update(pre_hash);
        h.update(nonce.to_le_bytes());
        h.finalize().into()
    }
}

/// RandomX hasher (production). Rebuilds the VM when the epoch `seed` changes
/// (from [`crate::algorithm::seed_for_parent`]). Construction is expensive —
/// one rebuild per epoch, not per hash.
#[cfg(feature = "randomx")]
pub struct RandomXHasher {
    state: std::sync::Mutex<RandomXState>,
}

#[cfg(feature = "randomx")]
struct RandomXState {
    seed: Vec<u8>,
    vm: randomx_rs::RandomXVM,
}

#[cfg(feature = "randomx")]
impl RandomXHasher {
    pub fn new(seed: &[u8]) -> Result<Self, randomx_rs::RandomXError> {
        Ok(Self {
            state: std::sync::Mutex::new(RandomXState {
                seed: seed.to_vec(),
                vm: Self::build_vm(seed)?,
            }),
        })
    }

    fn build_vm(seed: &[u8]) -> Result<randomx_rs::RandomXVM, randomx_rs::RandomXError> {
        use randomx_rs::{RandomXCache, RandomXFlag, RandomXVM};
        let flags = RandomXFlag::get_recommended_flags();
        let cache = RandomXCache::new(flags, seed)?;
        RandomXVM::new(flags, Some(cache), None)
    }
}

#[cfg(feature = "randomx")]
impl Hasher for RandomXHasher {
    fn hash(&self, pre_hash: &[u8], seed: &[u8], nonce: u64) -> [u8; 32] {
        let mut state = self.state.lock().expect("poisoned");
        if state.seed.as_slice() != seed {
            // Epoch rotated — rebuild the RandomX dataset for the new seed.
            state.vm = Self::build_vm(seed).expect("randomx vm rebuild");
            state.seed = seed.to_vec();
        }
        let mut input = Vec::with_capacity(pre_hash.len() + 8);
        input.extend_from_slice(pre_hash);
        input.extend_from_slice(&nonce.to_le_bytes());
        let out = state.vm.calculate_hash(&input).expect("randomx hash");
        let mut work = [0u8; 32];
        work.copy_from_slice(&out[..32]);
        work
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn easy_difficulty_is_always_met_and_verifies() {
        let h = BlakeHasher;
        let seal = mine(&h, b"pre", b"seed", U256::one(), 0, 10).unwrap();
        assert_eq!(seal.nonce, 0); // difficulty 1 → first nonce wins
        assert!(verify_seal(
            &h,
            b"pre",
            b"seed",
            &seal.encode_seal(),
            U256::one()
        ));
    }

    #[test]
    fn mining_finds_a_seal_meeting_moderate_difficulty() {
        let h = BlakeHasher;
        let difficulty = U256::from(500u64); // ~500 hashes expected
        let mut start = 0u64;
        let seal = loop {
            if let Some(s) = mine(&h, b"block", b"seed", difficulty, start, 1000) {
                break s;
            }
            start += 1000;
        };
        assert!(hash_meets_difficulty(&seal.work, difficulty));
        assert!(verify_seal(
            &h,
            b"block",
            b"seed",
            &seal.encode_seal(),
            difficulty
        ));
    }

    #[test]
    fn verify_rejects_tampering() {
        let h = BlakeHasher;
        let difficulty = U256::from(50u64);
        let mut start = 0;
        let seal = loop {
            if let Some(s) = mine(&h, b"x", b"s", difficulty, start, 500) {
                break s;
            }
            start += 500;
        };
        let good = seal.encode_seal();
        assert!(verify_seal(&h, b"x", b"s", &good, difficulty));

        // Wrong nonce (work no longer matches recomputation).
        let mut forged = seal.clone();
        forged.nonce = forged.nonce.wrapping_add(1);
        assert!(!verify_seal(
            &h,
            b"x",
            b"s",
            &forged.encode_seal(),
            difficulty
        ));

        // Different pre-hash / seed → recomputed work differs.
        assert!(!verify_seal(&h, b"y", b"s", &good, difficulty));
        assert!(!verify_seal(&h, b"x", b"different-seed", &good, difficulty));

        // Garbage seal bytes.
        assert!(!verify_seal(&h, b"x", b"s", b"junk", difficulty));
    }

    #[test]
    fn harder_difficulty_needs_more_work() {
        let h = BlakeHasher;
        // A hash meets low difficulty far more often than high difficulty.
        let work_easy = h.hash(b"a", b"b", 0);
        assert!(hash_meets_difficulty(&work_easy, U256::one()));
        // MAX difficulty (target ~0) is essentially never met by a fixed hash.
        assert!(!hash_meets_difficulty(&[0xff; 32], U256::MAX));
    }

    #[test]
    fn difficulty_zero_treated_as_one() {
        assert!(hash_meets_difficulty(&[0x00; 32], U256::zero()));
    }
}
