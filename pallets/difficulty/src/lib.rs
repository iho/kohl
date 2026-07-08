//! # pallet-difficulty — LWMA proof-of-work difficulty adjustment
//!
//! Implements zawy's Linear Weighted Moving Average (LWMA-1), the difficulty
//! algorithm used across CryptoNote chains (and the natural fit for kohl's
//! RandomX PoW — BLUEPRINT.md §1.4). Each block's solve time is weighted
//! linearly by recency over a sliding window; the next difficulty targets
//! `TargetBlockTime`:
//!
//! ```text
//! next = avg_difficulty · TargetBlockTime · Σi / Σ(i · solvetime_i)
//! ```
//!
//! so a window that solved faster than target raises difficulty and vice
//! versa. Solve times are clamped to `(0, 6·T]` to blunt timestamp
//! manipulation. The current difficulty is recomputed in `on_finalize` and
//! read by the PoW import pipeline for the next block (via `DifficultyApi`).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use frame_support::pallet_prelude::*;
use frame_system::pallet_prelude::*;
use sp_core::U256;
use sp_runtime::traits::UniqueSaturatedInto;

pub use pallet::*;

#[cfg(test)]
mod tests;

/// A window entry: the block's timestamp (ms) and the difficulty it used.
pub type Sample = (u64, U256);

#[frame_support::pallet]
pub mod pallet {
    use super::*;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_timestamp::Config {
        /// Target time between blocks, in milliseconds.
        #[pallet::constant]
        type TargetBlockTime: Get<u64>;

        /// LWMA window length (number of solve times averaged, e.g. 90).
        #[pallet::constant]
        type BlockWindow: Get<u32>;

        /// Lower bound on difficulty — the chain never drops below this.
        #[pallet::constant]
        type MinDifficulty: Get<u128>;
    }

    /// Difficulty the *next* block must satisfy.
    #[pallet::storage]
    pub type CurrentDifficulty<T> = StorageValue<_, U256, ValueQuery>;

    /// Rolling window of the most recent samples (oldest first), capped at
    /// `BlockWindow + 1` so we always have `BlockWindow` solve-time deltas.
    #[pallet::storage]
    pub type PastSamples<T: Config> =
        StorageValue<_, BoundedVec<Sample, ConstU32<{ u16::MAX as u32 }>>, ValueQuery>;

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        pub initial_difficulty: u128,
        #[serde(skip)]
        pub _marker: core::marker::PhantomData<T>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            let d = self.initial_difficulty.max(T::MinDifficulty::get());
            CurrentDifficulty::<T>::put(U256::from(d));
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_finalize(_n: BlockNumberFor<T>) {
            let now: u64 = pallet_timestamp::Pallet::<T>::get().unique_saturated_into();
            let current = CurrentDifficulty::<T>::get();
            let window = T::BlockWindow::get() as usize;

            PastSamples::<T>::mutate(|samples| {
                samples.force_push((now, current));
                while samples.len() > window + 1 {
                    samples.remove(0);
                }
                if let Some(next) = Self::lwma(samples, window) {
                    CurrentDifficulty::<T>::put(next);
                }
            });
        }
    }

    impl<T: Config> Pallet<T> {
        /// Difficulty required for the next block.
        pub fn difficulty() -> U256 {
            CurrentDifficulty::<T>::get()
        }

        /// Compute the LWMA next difficulty, or `None` if the window is too
        /// short to adjust yet.
        fn lwma(samples: &[Sample], window: usize) -> Option<U256> {
            if samples.len() < 3 {
                return None;
            }
            let target = T::TargetBlockTime::get().max(1);
            let max_solvetime = target.saturating_mul(6);

            // Use the last `window` solve times available.
            let deltas = &samples[samples.len().saturating_sub(window + 1)..];
            let n = deltas.len() - 1; // number of solve-time deltas

            let mut weighted_solvetime: u128 = 0;
            let mut sum_difficulty = U256::zero();
            for i in 1..=n {
                let prev = deltas[i - 1].0;
                let cur = deltas[i].0;
                // Clamp to (0, 6T]: a non-increasing timestamp counts as 1ms.
                let st = cur.saturating_sub(prev).clamp(1, max_solvetime);
                weighted_solvetime += (i as u128) * (st as u128);
                sum_difficulty += deltas[i].1;
            }

            let weight_sum = (n as u128 * (n as u128 + 1)) / 2; // Σ i
            let avg_difficulty = sum_difficulty / U256::from(n as u64);

            // next = avg · T · Σi / Σ(i · st)
            let numerator = avg_difficulty
                .saturating_mul(U256::from(target))
                .saturating_mul(U256::from(weight_sum));
            let next = numerator / U256::from(weighted_solvetime.max(1));

            Some(next.max(U256::from(T::MinDifficulty::get())))
        }
    }
}
