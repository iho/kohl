//! Weight functions for `pallet-ringct`.
//!
//! **Host-crypto ref_time** is calibrated from `cargo bench -p ringct-crypto
//! --bench crypto` on Apple Silicon (2026-07), using Substrate's
//! `WEIGHT_REF_TIME_PER_MILLIS = 10^9`, then applying ≈1.5× safety margin:
//!
//! | Path | Measured (ring/outs) | Budget used |
//! |------|----------------------|-------------|
//! | CLSAG verify | ~2–4 ms @ ring 16 | 6×10⁹ · inputs · (ring/16) |
//! | BP verify | ~1.9 ms @ 2 outs, ~5.5 ms @ 8 | 1.5×10⁹ + 0.7×10⁹ · outs |
//! | Balance | ~44 µs | 1×10⁸ base |
//!
//! Storage I/O uses the runtime's `DbWeight`. Re-generate with:
//! ```text
//! cargo bench -p ringct-crypto --bench crypto
//! cargo test -p pallet-ringct --features runtime-benchmarks
//! frame-omni-bencher v1 benchmark pallet --pallet pallet_ringct ...
//! ```

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(clippy::unnecessary_cast)]

use core::marker::PhantomData;
use frame_support::{
	traits::Get,
	weights::{constants::RocksDbWeight, Weight},
};

/// Weight functions needed for `pallet_ringct`.
pub trait WeightInfo {
	/// Authorize (pool) pre-check for a transfer: fee floor + key-image lookup.
	fn authorize_transfer(inputs: u32) -> Weight;
	/// Full transfer: CLSAG × inputs + balance + range proof + storage.
	fn transfer(inputs: u32, outputs: u32, ring_size: u32) -> Weight;
	/// Coinbase inherent: value commitments + append outputs.
	fn coinbase(outputs: u32) -> Weight;
}

/// ~1 ms of reference CPU time in Substrate weight units.
const MS: u64 = 1_000_000_000;

/// Substrate-node style weights (RocksDb). Used by the production runtime.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	fn authorize_transfer(inputs: u32) -> Weight {
		Weight::from_parts(25_000_000u64, 0)
			.saturating_add(T::DbWeight::get().reads(inputs as u64))
			.saturating_add(Weight::from_parts(2_000_000u64.saturating_mul(inputs as u64), 0))
	}

	fn transfer(inputs: u32, outputs: u32, ring_size: u32) -> Weight {
		// CLSAG verify: ~3.5 ms @ ring 16 → budget 6 ms with margin, scaled by ring.
		let clsag = (6 * MS)
			.saturating_mul(inputs as u64)
			.saturating_mul(ring_size.max(1) as u64)
			/ 16;
		// Aggregated BP: ~1.15 ms (1 out) … ~5.5 ms (8 outs).
		let bp = (1_500 * MS / 1000)
			.saturating_add((700 * MS / 1000).saturating_mul(outputs as u64));
		// Balance equation: ~0.05 ms measured.
		let balance = 100_000_000u64
			.saturating_add(5_000_000u64.saturating_mul((inputs + outputs) as u64));
		let reads = (ring_size as u64 + 1).saturating_mul(inputs as u64).saturating_add(2);
		let writes = (inputs as u64) + (outputs as u64) + 2;

		Weight::from_parts(clsag.saturating_add(bp).saturating_add(balance), 0)
			.saturating_add(T::DbWeight::get().reads_writes(reads, writes))
	}

	fn coinbase(outputs: u32) -> Weight {
		Weight::from_parts(
			30_000_000u64.saturating_add(10_000_000u64.saturating_mul(outputs as u64)),
			0,
		)
		.saturating_add(T::DbWeight::get().reads_writes(3, outputs as u64 + 4))
	}
}

/// Backwards-compatible unit type for tests / mock runtimes.
impl WeightInfo for () {
	fn authorize_transfer(inputs: u32) -> Weight {
		Weight::from_parts(25_000_000u64, 0)
			.saturating_add(RocksDbWeight::get().reads(inputs as u64))
			.saturating_add(Weight::from_parts(2_000_000u64.saturating_mul(inputs as u64), 0))
	}

	fn transfer(inputs: u32, outputs: u32, ring_size: u32) -> Weight {
		let clsag = (6 * MS)
			.saturating_mul(inputs as u64)
			.saturating_mul(ring_size.max(1) as u64)
			/ 16;
		let bp = (1_500 * MS / 1000)
			.saturating_add((700 * MS / 1000).saturating_mul(outputs as u64));
		let balance = 100_000_000u64
			.saturating_add(5_000_000u64.saturating_mul((inputs + outputs) as u64));
		let reads = (ring_size as u64 + 1).saturating_mul(inputs as u64).saturating_add(2);
		let writes = (inputs as u64) + (outputs as u64) + 2;
		Weight::from_parts(clsag.saturating_add(bp).saturating_add(balance), 0)
			.saturating_add(RocksDbWeight::get().reads_writes(reads, writes))
	}

	fn coinbase(outputs: u32) -> Weight {
		Weight::from_parts(
			30_000_000u64.saturating_add(10_000_000u64.saturating_mul(outputs as u64)),
			0,
		)
		.saturating_add(RocksDbWeight::get().reads_writes(3, outputs as u64 + 4))
	}
}
