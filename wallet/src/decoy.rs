//! Gamma-style decoy selection (BLUEPRINT.md §1.3 / §5.2).
//!
//! Monero's wallet samples ring decoys with a distribution over **output age**
//! so recent outputs are preferred (matching real spend timing) without
//! always picking the newest tip. Kohl mirrors that idea with a discrete
//! inverse-transform sampler:
//!
//! 1. Eligible candidates are mature outputs excluding the real spend.
//! 2. Each candidate at chain-tip age `Δ` (blocks) gets weight
//!    `w = (Δ + 1)^(-α)` with `α ≈ 1.3` (power-law stand-in for the gamma
//!    shape used in production Monero; good enough for a cash-chain v1 and
//!    fully deterministic given a seed).
//! 3. We draw `need` distinct indices without replacement.
//!
//! Using a seeded RNG keeps tests reproducible; the CLI passes OS entropy.

use crate::RingMember;
use std::collections::BTreeSet;

/// Shape parameter for the age power-law weight `age^{-α}`.
/// Higher α → stronger preference for recent outputs.
pub const AGE_POWER: f64 = 1.3;

#[derive(Debug)]
pub enum DecoyError {
    NotEnoughCandidates { need: usize, have: usize },
}

impl core::fmt::Display for DecoyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecoyError::NotEnoughCandidates { need, have } => {
                write!(f, "need {need} decoys, only {have} mature candidates")
            }
        }
    }
}
impl std::error::Error for DecoyError {}

/// A mature output that may be used as a ring decoy.
#[derive(Clone, Debug)]
pub struct DecoyCandidate {
    pub global_index: u64,
    pub one_time_key: [u8; 32],
    pub commitment: [u8; 32],
    /// Block height at which the output was created.
    pub height: u32,
}

/// Sample `need` distinct decoys from `candidates` (already filtered for
/// maturity and excluding the real input). `tip_height` is the current best
/// block number (used as age reference). `rng_seed` drives deterministic
/// draws (pass fresh entropy in production).
pub fn sample_decoys(
    candidates: &[DecoyCandidate],
    need: usize,
    tip_height: u32,
    rng_seed: u64,
) -> Result<Vec<RingMember>, DecoyError> {
    if need == 0 {
        return Ok(Vec::new());
    }
    if candidates.len() < need {
        return Err(DecoyError::NotEnoughCandidates {
            need,
            have: candidates.len(),
        });
    }

    // Precompute weights.
    let mut weights: Vec<f64> = candidates
        .iter()
        .map(|c| {
            let age = tip_height.saturating_sub(c.height) as f64 + 1.0;
            age.powf(-AGE_POWER)
        })
        .collect();

    let mut rng = Rng::new(rng_seed);
    let mut picked: BTreeSet<usize> = BTreeSet::new();
    let mut out = Vec::with_capacity(need);

    while out.len() < need {
        let total: f64 = weights.iter().sum();
        if total <= 0.0 || !total.is_finite() {
            // Fallback: uniform among remaining.
            let remaining: Vec<usize> = (0..candidates.len())
                .filter(|i| !picked.contains(i))
                .collect();
            if remaining.is_empty() {
                break;
            }
            let i = remaining[rng.gen_index(remaining.len())];
            picked.insert(i);
            weights[i] = 0.0;
            let c = &candidates[i];
            out.push(RingMember {
                global_index: c.global_index,
                one_time_key: c.one_time_key,
                commitment: c.commitment,
            });
            continue;
        }

        let mut thr = rng.gen_f64() * total;
        let mut chosen = None;
        for (i, w) in weights.iter().enumerate() {
            if picked.contains(&i) {
                continue;
            }
            thr -= *w;
            if thr <= 0.0 {
                chosen = Some(i);
                break;
            }
        }
        let i = chosen.unwrap_or_else(|| {
            (0..candidates.len())
                .rev()
                .find(|i| !picked.contains(i))
                .expect("candidates remain")
        });
        picked.insert(i);
        weights[i] = 0.0;
        let c = &candidates[i];
        out.push(RingMember {
            global_index: c.global_index,
            one_time_key: c.one_time_key,
            commitment: c.commitment,
        });
    }

    if out.len() < need {
        return Err(DecoyError::NotEnoughCandidates {
            need,
            have: out.len(),
        });
    }
    Ok(out)
}

/// Tiny xorshift64* — no external rand dependency.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // Avoid the all-zero state.
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn gen_f64(&mut self) -> f64 {
        // [0, 1)
        (self.next_u64() >> 11) as f64 / ((1u64 << 53) as f64)
    }

    fn gen_index(&mut self, n: usize) -> usize {
        (self.next_u64() as usize) % n.max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(gi: u64, height: u32) -> DecoyCandidate {
        DecoyCandidate {
            global_index: gi,
            one_time_key: [gi as u8; 32],
            commitment: [(gi + 1) as u8; 32],
            height,
        }
    }

    #[test]
    fn samples_exact_count_distinct() {
        let cs: Vec<_> = (0..20u64).map(|i| cand(i, i as u32 * 10)).collect();
        let decoys = sample_decoys(&cs, 5, 200, 42).unwrap();
        assert_eq!(decoys.len(), 5);
        let mut idxs: Vec<u64> = decoys.iter().map(|d| d.global_index).collect();
        idxs.sort();
        idxs.dedup();
        assert_eq!(idxs.len(), 5);
    }

    #[test]
    fn prefers_recent_outputs() {
        // 100 old outputs at height 0, 10 recent at tip.
        let mut cs = Vec::new();
        for i in 0..100u64 {
            cs.push(cand(i, 0));
        }
        for i in 0..10u64 {
            cs.push(cand(1000 + i, 1000));
        }
        let tip = 1000u32;
        // Many draws: count how often a "recent" index appears.
        let mut recent_hits = 0usize;
        let draws = 200usize;
        for seed in 0..draws as u64 {
            let decoys = sample_decoys(&cs, 1, tip, seed).unwrap();
            if decoys[0].global_index >= 1000 {
                recent_hits += 1;
            }
        }
        // With α=1.3, recent age=1 has weight 1; age=1001 has ~0.0003.
        // Even with 100 old vs 10 recent, recent should dominate heavily.
        assert!(
            recent_hits > draws / 2,
            "expected recent bias, got {recent_hits}/{draws} recent hits"
        );
    }

    #[test]
    fn errors_when_not_enough() {
        let cs = vec![cand(0, 0), cand(1, 1)];
        assert!(matches!(
            sample_decoys(&cs, 3, 10, 1),
            Err(DecoyError::NotEnoughCandidates { need: 3, have: 2 })
        ));
    }

    #[test]
    fn deterministic_for_same_seed() {
        let cs: Vec<_> = (0..30u64).map(|i| cand(i, i as u32)).collect();
        let a = sample_decoys(&cs, 8, 50, 7).unwrap();
        let b = sample_decoys(&cs, 8, 50, 7).unwrap();
        assert_eq!(
            a.iter().map(|d| d.global_index).collect::<Vec<_>>(),
            b.iter().map(|d| d.global_index).collect::<Vec<_>>()
        );
    }
}
