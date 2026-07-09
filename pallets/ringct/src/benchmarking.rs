//! Extrinsic weight benchmarks for `pallet-ringct`.
//!
//! Setup builds valid RingCT material via **host functions** so the WASM
//! runtime never pulls in `rand`/OsRng. Measured dispatch still exercises
//! native CLSAG + Bulletproof verification through the same host interface.
//!
//! ## Running (production WASM)
//!
//! Stock `frame-omni-bencher` does **not** register kohl's `ringct_crypto`
//! host functions. Use the node CLI (which does):
//!
//! ```text
//! ./scripts/benchmark-ringct.sh
//! ```

#![cfg(feature = "runtime-benchmarks")]

use super::*;
use crate::Pallet as RingCt;
use alloc::vec;
use alloc::vec::Vec;
use codec::Decode;
use frame_benchmarking::v2::*;
use frame_system::RawOrigin;
use ringct_crypto::ringct_crypto as crypto_host;
use ringct_primitives::MAX_OUTPUTS;

/// Split `random_secret_key_v1` host output into (secret, public).
fn host_keypair() -> ([u8; 32], [u8; 32]) {
	let blob = crypto_host::random_secret_key_v1();
	let mut sk = [0u8; 32];
	let mut pk = [0u8; 32];
	sk.copy_from_slice(&blob[..32]);
	pk.copy_from_slice(&blob[32..]);
	(sk, pk)
}

/// Mint `n` matured outputs with known secrets (multiple coinbases if needed).
fn mint_owned_bed<T: Config>(n: u32) -> Vec<(u64, [u8; 32], u64)> {
	use frame_support::traits::Hooks;
	use sp_runtime::traits::SaturatedConversion;

	let first = NextOutputIndex::<T>::get();
	let mut secrets_amounts: Vec<([u8; 32], u64)> = Vec::with_capacity(n as usize);
	let mut remaining = n;

	while remaining > 0 {
		let now: u32 = frame_system::Pallet::<T>::block_number().saturated_into();
		let next: BlockNumberFor<T> = (now + 1).into();
		frame_system::Pallet::<T>::set_block_number(next);
		RingCt::<T>::on_initialize(next);

		let batch = remaining.min(MAX_OUTPUTS);
		let reward = block_reward(Emitted::<T>::get());
		let keys: Vec<([u8; 32], [u8; 32])> = (0..batch).map(|_| host_keypair()).collect();
		let mut amounts = vec![reward / batch as u64; batch as usize];
		if batch > 0 {
			amounts[batch as usize - 1] =
				reward - (batch as u64 - 1) * (reward / batch as u64);
		}
		let outputs: Vec<CoinbaseOutput> = keys
			.iter()
			.zip(&amounts)
			.map(|((_, pk), a)| CoinbaseOutput {
				one_time_key: *pk,
				amount: *a,
				view_tag: 0,
			})
			.collect();
		let outs = BoundedVec::try_from(outputs).expect("fits MAX_OUTPUTS");
		let (_, r) = host_keypair();
		RingCt::<T>::coinbase(RawOrigin::None.into(), outs, r).expect("coinbase");

		for ((secret, _), amount) in keys.into_iter().zip(amounts) {
			secrets_amounts.push((secret, amount));
		}
		remaining -= batch;
	}

	let now: u32 = frame_system::Pallet::<T>::block_number().saturated_into();
	let maturity: u32 = T::CoinbaseMaturity::get().saturated_into();
	let target: BlockNumberFor<T> = (now + maturity + 1).into();
	frame_system::Pallet::<T>::set_block_number(target);
	RingCt::<T>::on_initialize(target);

	secrets_amounts
		.into_iter()
		.enumerate()
		.map(|(i, (secret, amount))| (first + i as u64, secret, amount))
		.collect()
}

fn build_ring_spend<T: Config>(
	bed: &[(u64, [u8; 32], u64)],
	real: usize,
	fee: u64,
) -> TransferTx {
	let ring_size = T::RingSize::get() as usize;
	assert!(bed.len() >= ring_size, "need at least RingSize outputs");
	let (real_idx, secret, amount) = bed[real];
	assert!(amount > fee, "coinbase amount must exceed fee");
	let ring: Vec<u64> = bed.iter().take(ring_size).map(|(i, _, _)| *i).collect();
	let position = ring.iter().position(|i| *i == real_idx).expect("real in ring");

	let mut ring_blob = Vec::with_capacity(ring_size * 64);
	for gi in &ring {
		let stored = Outputs::<T>::get(gi).expect("exists");
		ring_blob.extend_from_slice(&stored.one_time_key);
		ring_blob.extend_from_slice(&stored.commitment);
	}

	let indices_enc = ring.encode();
	let in_blinding = [0u8; 32];
	let bytes = crypto_host::bench_make_transfer_v1(
		&indices_enc,
		&ring_blob,
		position as u32,
		&secret,
		amount,
		fee,
		&in_blinding,
	);
	assert!(!bytes.is_empty(), "host failed to build transfer");
	TransferTx::decode(&mut &bytes[..]).expect("decode TransferTx from host")
}

/// Fee large enough for the per-byte floor on a max-sized transfer.
fn ample_fee<T: Config>() -> u64 {
	T::MinFeePerByte::get().saturating_mul(8_000).max(10_000)
}

#[benchmarks]
mod benchmarks {
	use super::*;

	/// Pool-side authorize path (fee floor + key-image lookups).
	#[benchmark]
	fn authorize_transfer() {
		let bed = mint_owned_bed::<T>(T::RingSize::get().max(4));
		let fee = ample_fee::<T>();
		let real = bed.iter().position(|(_, _, a)| *a > fee).expect("cover fee");
		let tx = build_ring_spend::<T>(&bed, real, fee);
		#[block]
		{
			RingCt::<T>::authorize_transfer(&tx).expect("authorize ok");
		}
	}

	/// Full transfer including host CLSAG + Bulletproof verification.
	#[benchmark]
	fn transfer() {
		let n = T::RingSize::get().max(4);
		let bed = mint_owned_bed::<T>(n);
		let fee = ample_fee::<T>();
		let real = bed.iter().position(|(_, _, a)| *a > fee).expect("cover fee");
		let tx = build_ring_spend::<T>(&bed, real, fee);

		#[extrinsic_call]
		_(RawOrigin::Authorized, tx);

		assert!(NextOutputIndex::<T>::get() > n as u64);
	}

	#[benchmark]
	fn coinbase() {
		let reward = block_reward(Emitted::<T>::get());
		let (_, public) = host_keypair();
		let outputs = BoundedVec::try_from(vec![CoinbaseOutput {
			one_time_key: public,
			amount: reward,
			view_tag: 0,
		}])
		.expect("bound");
		let (_, r) = host_keypair();

		#[extrinsic_call]
		_(RawOrigin::None, outputs, r);

		assert!(CoinbaseDone::<T>::get());
	}

	impl_benchmark_test_suite!(RingCt, crate::mock::new_test_ext(), crate::mock::Test);
}
