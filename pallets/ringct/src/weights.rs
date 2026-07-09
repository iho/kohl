//! Weight functions for `pallet-ringct`.
//!
//! ## Sources
//!
//! 1. **Parametric host-crypto** — `cargo bench -p ringct-crypto --bench crypto`
//! 2. **Machine extrinsic** — `./scripts/benchmark-ringct.sh` →
//!    [`weights_machine.rs`](weights_machine.rs) (do not use that file as
//!    `WeightInfo` directly: it is fixed 1-in/1-out CLSAG, no FCMP params).
//!
//! ### Machine snapshot (2026-07-09, STEPS=50, REPEAT=20, compiled WASM)
//!
//! | Extrinsic | ref_time (ps) | ≈ ms | reads | writes | proof size |
//! |-----------|---------------|------|-------|--------|------------|
//! | `authorize_transfer` | 8_000_000 | 0.008 | 1 | 0 | 3_513 |
//! | `transfer` (1-in/1-out, ring 16) | 6_185_000_000 | 6.19 | 36 | 7 | 43_934 |
//! | `coinbase` (1 out) | 92_000_000 | 0.092 | 5 | 8 | 1_493 |
//!
//! Transfer I/O breakdown (matches PR-1 tree grow + root refresh):
//! `KeyImages`1 + `Outputs`×16 + `BlockFees`1 + `NextOutputIndex`1 +
//! `TreeSlots`1 + `MembershipLeafDigest`×16 → **36 reads**;
//! KI + fees + next + slots + leaf + root + output → **7 writes**.
//!
//! ### Engineered budgets (this file)
//!
//! | Path | Budget |
//! |------|--------|
//! | CLSAG verify | **6 ms · inputs · (ring/16)** (≈ measured 6.2 ms total for 1/1/16) |
//! | BP verify | 1.5 ms + 0.7 ms · outs |
//! | Balance | 0.1 ms + small per point |
//! | FCMP verify @ n | **25 ms · inputs · (n/64)**; floor 6 ms · inputs (D2; host ~18 ms @ 64) |
//! | Tree maintain | fill/grow/root — [`WeightInfo::maintain_membership`] |
//!
//! Re-measure:
//! ```text
//! cargo bench -p ringct-crypto --bench crypto -- fcmp_
//! ./scripts/benchmark-ringct.sh
//! ```

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(clippy::unnecessary_cast)]

use core::marker::PhantomData;
use frame_support::{
	traits::Get,
	weights::{constants::RocksDbWeight, Weight},
};
use ringct_primitives::{
	FCMP_ADMIT_MAX_LEAVES_PER_BLOCK, FCMP_GROW_CATCHUP_MAX_PER_BLOCK, MAX_FCMP_ANON_SET,
};

/// Weight functions needed for `pallet_ringct`.
pub trait WeightInfo {
	/// Authorize (pool) pre-check for a CLSAG transfer: fee floor + key-image lookup.
	fn authorize_transfer(inputs: u32) -> Weight;
	/// Full CLSAG transfer: CLSAG × inputs + balance + range proof + storage + tree grow.
	fn transfer(inputs: u32, outputs: u32, ring_size: u32) -> Weight;
	/// Coinbase inherent: value commitments + append outputs + tree grow.
	fn coinbase(outputs: u32) -> Weight;

	/// Pool authorize for an FCMP transfer (PR-7): fee + KI + root window probes.
	fn authorize_fcmp(inputs: u32) -> Weight;
	/// Full FCMP transfer (PR-7): `verify_fcmp_v1` × inputs + balance + BP + storage.
	/// `tree_slots` is the membership tree size bound into the proof (≤ [`MAX_FCMP_ANON_SET`]).
	fn transfer_fcmp(inputs: u32, outputs: u32, tree_slots: u32) -> Weight;
	/// End-of-block membership maintain (fill + catch-up grow + root recompute).
	/// Used for block-weight accounting / engineering estimates (hook is unmetered today).
	fn maintain_membership(tree_slots: u32, admit_ops: u32, grow_ops: u32) -> Weight;
}

/// ~1 ms of reference CPU time in Substrate weight units.
const MS: u64 = 1_000_000_000;

/// FCMP verify budget per input at full anon set (64): design D2 cap 25 ms.
const FCMP_VERIFY_MS_AT_MAX: u64 = 25;

/// Machine `transfer` ref_time floor (1-in/1-out, ring 16) with ~15% margin.
const MACHINE_TRANSFER_1_1_16: u64 = 7_120_000_000;

/// Machine `coinbase` ref_time for 1 output with ~15% margin.
const MACHINE_COINBASE_1: u64 = 106_000_000;

/// Machine authorize ref_time (single KI) with margin — used as per-input base.
const MACHINE_AUTHORIZE_BASE: u64 = 12_000_000;

fn clsag_component(inputs: u32, ring_size: u32) -> u64 {
	(6 * MS)
		.saturating_mul(inputs as u64)
		.saturating_mul(ring_size.max(1) as u64)
		/ 16
}

fn bp_component(outputs: u32) -> u64 {
	(1_500 * MS / 1000).saturating_add((700 * MS / 1000).saturating_mul(outputs as u64))
}

fn balance_component(inputs: u32, outputs: u32) -> u64 {
	100_000_000u64.saturating_add(5_000_000u64.saturating_mul((inputs + outputs) as u64))
}

/// FCMP host verify: scale from 25 ms @ n=64; floor CLSAG@16 budget.
fn fcmp_verify_component(inputs: u32, tree_slots: u32) -> u64 {
	let n = tree_slots.max(1).min(MAX_FCMP_ANON_SET) as u64;
	let at_max = FCMP_VERIFY_MS_AT_MAX
		.saturating_mul(MS)
		.saturating_mul(inputs as u64);
	let scaled = at_max.saturating_mul(n) / (MAX_FCMP_ANON_SET as u64);
	let floor = (6 * MS).saturating_mul(inputs as u64);
	scaled.max(floor)
}

/// Proof-size estimate for a CLSAG transfer (SCALE + storage proofs).
/// Machine measured ~44 KiB for 1-in/1-out ring 16; scale by ring × inputs + outs.
fn transfer_proof_size(inputs: u32, outputs: u32, ring_size: u32) -> u64 {
	// Base from machine (1,1,16) = 43934; ~2.5 KiB per ring member + outs.
	let per_ring = 2_700u64.saturating_mul(ring_size as u64).saturating_mul(inputs as u64);
	let per_out = 2_700u64.saturating_mul(outputs as u64);
	per_ring.saturating_add(per_out).saturating_add(2_000).max(3_513)
}

/// Substrate-node style weights (RocksDb). Used by the production runtime.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	fn authorize_transfer(inputs: u32) -> Weight {
		// Machine: 8e6 for 1 KI; keep small per-input CPU + 1 read per KI.
		Weight::from_parts(
			MACHINE_AUTHORIZE_BASE.saturating_mul(inputs.max(1) as u64),
			3_513u64.saturating_mul(inputs.max(1) as u64),
		)
		.saturating_add(T::DbWeight::get().reads(inputs.max(1) as u64))
	}

	fn transfer(inputs: u32, outputs: u32, ring_size: u32) -> Weight {
		let clsag = clsag_component(inputs, ring_size);
		let bp = bp_component(outputs);
		let balance = balance_component(inputs, outputs);
		let mut cpu = clsag.saturating_add(bp).saturating_add(balance);
		// Floor: machine 1-in/1-out ring-16, scaled by inputs (conservative).
		let machine_floor = MACHINE_TRANSFER_1_1_16
			.saturating_mul(inputs.max(1) as u64)
			.saturating_mul(ring_size.max(1) as u64)
			/ 16;
		cpu = cpu.max(machine_floor);

		// Apply path: per input ring members + KI; bookkeeping; then for each
		// new output grow EMPTY + full digest walk for root refresh.
		// Worst-case digest walk ≈ outputs · (prior_slots + outs) — without a
		// chain-height param, charge outputs · ring_size as a stand-in floor
		// (machine: 16 digest reads after a ring-16 bed).
		let ring = ring_size.max(1) as u64;
		let ins = inputs as u64;
		let outs = outputs as u64;
		let reads = ring
			.saturating_mul(ins) // Outputs ring members
			.saturating_add(ins) // KeyImages
			.saturating_add(3) // BlockFees, NextOutputIndex, TreeSlots
			.saturating_add(ring.saturating_mul(outs.max(1))); // MembershipLeafDigest root refresh
		let writes = ins // KeyImages
			.saturating_add(outs) // Outputs
			.saturating_add(outs) // MembershipLeafDigest grow
			.saturating_add(4); // fees, next, slots, root

		Weight::from_parts(cpu, transfer_proof_size(inputs, outputs, ring_size))
			.saturating_add(T::DbWeight::get().reads_writes(reads, writes))
	}

	fn coinbase(outputs: u32) -> Weight {
		let outs = outputs.max(1) as u64;
		// Machine ~92 µs for 1 out; scale + margin.
		let cpu = MACHINE_COINBASE_1.saturating_mul(outs);
		// reads: CoinbaseDone, Emitted, BlockFees, Next, TreeSlots (+ digest walk)
		let reads = 5u64.saturating_add(outs.saturating_mul(2));
		// writes: done, emitted, fees, next, slots, root, + out + leaf per out
		let writes = 6u64.saturating_add(outs.saturating_mul(2));
		Weight::from_parts(cpu, 1_493u64.saturating_mul(outs))
			.saturating_add(T::DbWeight::get().reads_writes(reads, writes))
	}

	fn authorize_fcmp(inputs: u32) -> Weight {
		// Fee floor + KI + membership root window probes (≤ root max age).
		Weight::from_parts(
			MACHINE_AUTHORIZE_BASE
				.saturating_mul(2)
				.saturating_mul(inputs.max(1) as u64),
			3_513u64.saturating_mul(inputs.max(1) as u64),
		)
		.saturating_add(T::DbWeight::get().reads((inputs as u64).saturating_add(8)))
	}

	fn transfer_fcmp(inputs: u32, outputs: u32, tree_slots: u32) -> Weight {
		let fcmp = fcmp_verify_component(inputs, tree_slots);
		let bp = bp_component(outputs);
		let balance = balance_component(inputs, outputs);
		let cpu = fcmp.saturating_add(bp).saturating_add(balance);
		// No ring member fetches; proof carries digests. Still grow-on-create + root.
		let slots = tree_slots.max(1) as u64;
		let ins = inputs as u64;
		let outs = outputs as u64;
		let reads = ins // KI
			.saturating_add(4) // fees, next, slots, root window
			.saturating_add(slots.saturating_mul(outs.max(1))); // root refresh
		let writes = ins
			.saturating_add(outs)
			.saturating_add(outs)
			.saturating_add(4);
		// Proof size: digests n·32 + ring + CLSAG — up to ~12 KiB per input + outs.
		let proof = (12_288u64.saturating_mul(ins))
			.saturating_add(2_700u64.saturating_mul(outs))
			.saturating_add(2_000);

		Weight::from_parts(cpu, proof)
			.saturating_add(T::DbWeight::get().reads_writes(reads, writes))
	}

	fn maintain_membership(tree_slots: u32, admit_ops: u32, grow_ops: u32) -> Weight {
		let admit = admit_ops.min(FCMP_ADMIT_MAX_LEAVES_PER_BLOCK);
		let grow = grow_ops.min(FCMP_GROW_CATCHUP_MAX_PER_BLOCK);
		let root_cpu = 50_000u64
			.saturating_mul(tree_slots.max(1) as u64)
			.saturating_add(1_000_000);
		let admit_cpu = 2_000_000u64.saturating_mul(admit as u64);
		let grow_cpu = 1_000_000u64.saturating_mul(grow as u64);
		let reads = (admit as u64)
			.saturating_mul(2)
			.saturating_add(tree_slots as u64)
			.saturating_add(2);
		let writes = (admit as u64)
			.saturating_mul(2)
			.saturating_add(grow as u64)
			.saturating_add(3);

		Weight::from_parts(root_cpu.saturating_add(admit_cpu).saturating_add(grow_cpu), 0)
			.saturating_add(T::DbWeight::get().reads_writes(reads, writes))
	}
}

/// Backwards-compatible unit type for tests / mock runtimes.
impl WeightInfo for () {
	fn authorize_transfer(inputs: u32) -> Weight {
		Weight::from_parts(
			MACHINE_AUTHORIZE_BASE.saturating_mul(inputs.max(1) as u64),
			3_513u64.saturating_mul(inputs.max(1) as u64),
		)
		.saturating_add(RocksDbWeight::get().reads(inputs.max(1) as u64))
	}
	fn transfer(inputs: u32, outputs: u32, ring_size: u32) -> Weight {
		let clsag = clsag_component(inputs, ring_size);
		let bp = bp_component(outputs);
		let balance = balance_component(inputs, outputs);
		let mut cpu = clsag.saturating_add(bp).saturating_add(balance);
		let machine_floor = MACHINE_TRANSFER_1_1_16
			.saturating_mul(inputs.max(1) as u64)
			.saturating_mul(ring_size.max(1) as u64)
			/ 16;
		cpu = cpu.max(machine_floor);
		let ring = ring_size.max(1) as u64;
		let ins = inputs as u64;
		let outs = outputs as u64;
		let reads = ring
			.saturating_mul(ins)
			.saturating_add(ins)
			.saturating_add(3)
			.saturating_add(ring.saturating_mul(outs.max(1)));
		let writes = ins.saturating_add(outs).saturating_add(outs).saturating_add(4);
		Weight::from_parts(cpu, transfer_proof_size(inputs, outputs, ring_size))
			.saturating_add(RocksDbWeight::get().reads_writes(reads, writes))
	}
	fn coinbase(outputs: u32) -> Weight {
		let outs = outputs.max(1) as u64;
		let cpu = MACHINE_COINBASE_1.saturating_mul(outs);
		let reads = 5u64.saturating_add(outs.saturating_mul(2));
		let writes = 6u64.saturating_add(outs.saturating_mul(2));
		Weight::from_parts(cpu, 1_493u64.saturating_mul(outs))
			.saturating_add(RocksDbWeight::get().reads_writes(reads, writes))
	}
	fn authorize_fcmp(inputs: u32) -> Weight {
		Weight::from_parts(
			MACHINE_AUTHORIZE_BASE
				.saturating_mul(2)
				.saturating_mul(inputs.max(1) as u64),
			3_513u64.saturating_mul(inputs.max(1) as u64),
		)
		.saturating_add(RocksDbWeight::get().reads((inputs as u64).saturating_add(8)))
	}
	fn transfer_fcmp(inputs: u32, outputs: u32, tree_slots: u32) -> Weight {
		let fcmp = fcmp_verify_component(inputs, tree_slots);
		let bp = bp_component(outputs);
		let balance = balance_component(inputs, outputs);
		let cpu = fcmp.saturating_add(bp).saturating_add(balance);
		let slots = tree_slots.max(1) as u64;
		let ins = inputs as u64;
		let outs = outputs as u64;
		let reads = ins
			.saturating_add(4)
			.saturating_add(slots.saturating_mul(outs.max(1)));
		let writes = ins.saturating_add(outs).saturating_add(outs).saturating_add(4);
		let proof = (12_288u64.saturating_mul(ins))
			.saturating_add(2_700u64.saturating_mul(outs))
			.saturating_add(2_000);
		Weight::from_parts(cpu, proof)
			.saturating_add(RocksDbWeight::get().reads_writes(reads, writes))
	}
	fn maintain_membership(tree_slots: u32, admit_ops: u32, grow_ops: u32) -> Weight {
		let admit = admit_ops.min(FCMP_ADMIT_MAX_LEAVES_PER_BLOCK);
		let grow = grow_ops.min(FCMP_GROW_CATCHUP_MAX_PER_BLOCK);
		let root_cpu = 50_000u64
			.saturating_mul(tree_slots.max(1) as u64)
			.saturating_add(1_000_000);
		let admit_cpu = 2_000_000u64.saturating_mul(admit as u64);
		let grow_cpu = 1_000_000u64.saturating_mul(grow as u64);
		let reads = (admit as u64)
			.saturating_mul(2)
			.saturating_add(tree_slots as u64)
			.saturating_add(2);
		let writes = (admit as u64)
			.saturating_mul(2)
			.saturating_add(grow as u64)
			.saturating_add(3);
		Weight::from_parts(root_cpu.saturating_add(admit_cpu).saturating_add(grow_cpu), 0)
			.saturating_add(RocksDbWeight::get().reads_writes(reads, writes))
	}
}

#[cfg(test)]
mod machine_merge_tests {
	use super::*;

	#[test]
	fn engineered_transfer_covers_machine_1_1_16() {
		let w = <() as WeightInfo>::transfer(1, 1, 16);
		// ref_time ≥ machine measurement
		assert!(
			w.ref_time() >= 6_185_000_000,
			"engineered {} < machine 6185ms-units",
			w.ref_time()
		);
		// proof size present
		assert!(w.proof_size() >= 3_513);
	}

	#[test]
	fn engineered_coinbase_covers_machine_1() {
		let w = <() as WeightInfo>::coinbase(1);
		assert!(w.ref_time() >= 92_000_000);
	}

	#[test]
	fn engineered_authorize_covers_machine() {
		let w = <() as WeightInfo>::authorize_transfer(1);
		assert!(w.ref_time() >= 8_000_000);
	}
}
