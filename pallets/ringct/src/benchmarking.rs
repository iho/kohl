//! Extrinsic weight benchmarks for `pallet-ringct`.
//!
//! Enable with `--features runtime-benchmarks` on the runtime and run via
//! `frame-omni-bencher` (or the node binary once the runtime is wired). These
//! benchmarks construct **valid** RingCT material with `ringct-crypto` so the
//! measured path includes host-function CLSAG + Bulletproof verification.
//!
//! ```text
//! # once the runtime exports benchmarks:
//! frame-omni-bencher v1 benchmark pallet \
//!   --runtime target/release/wbuild/kohl-runtime/kohl_runtime.wasm \
//!   --pallet pallet_ringct --extrinsic '*' --steps 20 --repeat 10
//! ```

#![cfg(feature = "runtime-benchmarks")]

use super::*;
use crate::Pallet as RingCt;
use frame_benchmarking::v2::*;
use frame_system::RawOrigin;
use ringct_crypto::{clsag, native as crypto};

/// Mint `n` matured coinbase-style outputs with known secrets (ring bed).
fn mint_owned_bed<T: Config>(n: u32) -> Vec<(u64, [u8; 32], u64)> {
	use frame_support::traits::Hooks;
	use sp_runtime::traits::SaturatedConversion;
	let reward = block_reward(Emitted::<T>::get());
	let first = NextOutputIndex::<T>::get();
	let keys: Vec<([u8; 32], [u8; 32])> =
		(0..n).map(|_| crypto::random_secret_key()).collect();
	let mut amounts = vec![reward / n as u64; n as usize];
	if n > 0 {
		amounts[n as usize - 1] = reward - (n as u64 - 1) * (reward / n as u64);
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
	RingCt::<T>::coinbase(RawOrigin::None.into(), outs, crypto::random_secret_key().1)
		.expect("coinbase");
	// Mature past CoinbaseMaturity.
	let now: u32 = frame_system::Pallet::<T>::block_number().saturated_into();
	let maturity: u32 = T::CoinbaseMaturity::get().saturated_into();
	let target: BlockNumberFor<T> = (now + maturity + 1).into();
	frame_system::Pallet::<T>::set_block_number(target);
	RingCt::<T>::on_initialize(target);

	keys.into_iter()
		.zip(amounts)
		.enumerate()
		.map(|(i, ((secret, _), amount))| (first + i as u64, secret, amount))
		.collect()
}

fn build_ring_spend<T: Config>(
	bed: &[(u64, [u8; 32], u64)],
	real: usize,
	fee: u64,
) -> TransferTx {
	let ring_size = T::RingSize::get() as usize;
	assert!(bed.len() >= ring_size);
	let (real_idx, secret, amount) = bed[real];
	let ring: Vec<u64> = bed.iter().take(ring_size).map(|(i, _, _)| *i).collect();
	let position = ring.iter().position(|i| *i == real_idx).expect("real in ring");

	let mut ring_blob = Vec::with_capacity(ring_size * 64);
	for gi in &ring {
		let stored = Outputs::<T>::get(gi).expect("exists");
		ring_blob.extend_from_slice(&stored.one_time_key);
		ring_blob.extend_from_slice(&stored.commitment);
	}

	let out_amount = amount.saturating_sub(fee);
	let in_blinding = [0u8; 32];
	let pseudo_blinding = crypto::random_blinding();
	let out_blinding = pseudo_blinding;
	let (proof, commits) =
		crypto::prove_range(&[out_amount], &[out_blinding]).expect("range proof");

	let mut tx = TransferTx {
		inputs: BoundedVec::try_from(vec![RingInput {
			ring: BoundedVec::try_from(ring).expect("ring bound"),
			key_image: clsag::key_image(&secret).expect("ki"),
			pseudo_commitment: crypto::commit(amount, &pseudo_blinding).expect("commit"),
			clsag: Default::default(),
		}])
		.expect("inputs"),
		outputs: BoundedVec::try_from(vec![Output {
			one_time_key: crypto::random_secret_key().1,
			commitment: commits[0],
			view_tag: 0,
			payload: Default::default(),
		}])
		.expect("outputs"),
		tx_pubkey: crypto::random_secret_key().1,
		range_proof: BoundedVec::try_from(proof).expect("proof"),
		fee,
	};
	let msg = crate::signing_hash(&tx);
	let sig = clsag::sign(&msg, &ring_blob, position, &secret, &in_blinding, &pseudo_blinding)
		.expect("sign");
	tx.inputs[0].clsag = BoundedVec::try_from(sig.signature).expect("clsag bound");
	tx
}

#[benchmarks]
mod benchmarks {
	use super::*;

	/// Pool-side authorize path (fee floor + key-image lookups).
	#[benchmark]
	fn authorize_transfer() {
		let bed = mint_owned_bed::<T>(T::RingSize::get().max(4));
		let fee = 10_000u64;
		let tx = build_ring_spend::<T>(&bed, 0, fee);
		#[block]
		{
			RingCt::<T>::authorize_transfer(&tx).expect("authorize ok");
		}
	}

	/// Full transfer with a production-sized ring when `RingSize` allows.
	#[benchmark]
	fn transfer() {
		let n = T::RingSize::get().max(4);
		let bed = mint_owned_bed::<T>(n);
		let fee = 10_000u64;
		let tx = build_ring_spend::<T>(&bed, 0, fee);

		#[extrinsic_call]
		_(RawOrigin::Authorized, tx);

		assert!(NextOutputIndex::<T>::get() > n as u64);
	}

	#[benchmark]
	fn coinbase() {
		let reward = block_reward(Emitted::<T>::get());
		let (_, public) = crypto::random_secret_key();
		let outputs = BoundedVec::try_from(vec![CoinbaseOutput {
			one_time_key: public,
			amount: reward,
			view_tag: 0,
		}])
		.expect("bound");
		let r = crypto::random_secret_key().1;

		#[extrinsic_call]
		_(RawOrigin::None, outputs, r);

		assert!(CoinbaseDone::<T>::get());
	}

	impl_benchmark_test_suite!(RingCt, crate::mock::new_test_ext(), crate::mock::Test);
}
