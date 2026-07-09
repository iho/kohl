//! Weight functions for `pallet-ringct`.
//!
//! These are **engineered estimates** calibrated from the cost structure of
//! native host-function crypto (CLSAG ≈ O(ring_size) scalar mults per input;
//! aggregated Bulletproof ≈ O(log(64·outputs)) multi-exp). They are
//! intentionally conservative until `frame-benchmarking` / criterion numbers
//! replace them. Storage I/O uses the runtime's `DbWeight`.
//!
//! To re-benchmark later:
//! ```text
//! frame-omni-bencher v1 benchmark pallet \
//!   --runtime target/release/wbuild/kohl-runtime/kohl_runtime.wasm \
//!   --pallet pallet_ringct --extrinsic '*'
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

/// Substrate-node style weights (RocksDb). Used by the production runtime.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	fn authorize_transfer(inputs: u32) -> Weight {
		// One contains_key per input + encode/fee arithmetic.
		Weight::from_parts(25_000_000u64, 0)
			.saturating_add(T::DbWeight::get().reads(inputs as u64))
			.saturating_add(Weight::from_parts(2_000_000u64.saturating_mul(inputs as u64), 0))
	}

	fn transfer(inputs: u32, outputs: u32, ring_size: u32) -> Weight {
		// Host CLSAG: ~150µs–1ms native per input at ring 16 on modern CPUs;
		// budget 300M ref_time units per input as a safe upper bound, scaled
		// by ring size relative to 16.
		let clsag_base = 300_000_000u64;
		let clsag = clsag_base
			.saturating_mul(inputs as u64)
			.saturating_mul(ring_size.max(1) as u64)
			/ 16;
		// Aggregated BP verify: ~100–500µs native; budget 200M + 50M/output.
		let bp = 200_000_000u64.saturating_add(50_000_000u64.saturating_mul(outputs as u64));
		// Balance point sum is cheap relative to proofs.
		let balance = 20_000_000u64.saturating_add(5_000_000u64.saturating_mul((inputs + outputs) as u64));
		// Storage: ring_size reads per input + KI write per input + output writes.
		let reads = (ring_size as u64 + 1).saturating_mul(inputs as u64).saturating_add(2);
		let writes = (inputs as u64) + (outputs as u64) + 2;

		Weight::from_parts(clsag.saturating_add(bp).saturating_add(balance), 0)
			.saturating_add(T::DbWeight::get().reads_writes(reads, writes))
	}

	fn coinbase(outputs: u32) -> Weight {
		// value_commitment host call is a cheap scalar mult; storage dominates.
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
		let clsag = 300_000_000u64
			.saturating_mul(inputs as u64)
			.saturating_mul(ring_size.max(1) as u64)
			/ 16;
		let bp = 200_000_000u64.saturating_add(50_000_000u64.saturating_mul(outputs as u64));
		let balance = 20_000_000u64.saturating_add(5_000_000u64.saturating_mul((inputs + outputs) as u64));
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
