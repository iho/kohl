//! Extrinsic weight benchmarks for `pallet-ringct` (FCMP-only).
//!
//! ```text
//! ./scripts/benchmark-ringct.sh
//! ```

#![cfg(feature = "runtime-benchmarks")]

use super::*;
use crate::Pallet as RingCt;
use alloc::vec;
use alloc::vec::Vec;
use codec::{Decode, Encode};
use frame_benchmarking::v2::*;
use frame_system::RawOrigin;
use ringct_crypto::ringct_crypto as crypto_host;
use ringct_primitives::MAX_OUTPUTS;

fn host_keypair() -> ([u8; 32], [u8; 32]) {
    let blob = crypto_host::random_secret_key_v1();
    let mut sk = [0u8; 32];
    let mut pk = [0u8; 32];
    sk.copy_from_slice(&blob[..32]);
    pk.copy_from_slice(&blob[32..]);
    (sk, pk)
}

fn host_blinding() -> [u8; 32] {
    crypto_host::random_blinding_v1()
}

fn mint_admitted_bed<T: Config>(n: u32) -> Vec<(u64, [u8; 32], u64)> {
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
            amounts[batch as usize - 1] = reward - (batch as u64 - 1) * (reward / batch as u64);
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
        let outs = BoundedVec::try_from(outputs).expect("fits");
        let (_, r) = host_keypair();
        RingCt::<T>::coinbase(RawOrigin::None.into(), outs, r).expect("coinbase");

        for ((secret, _), amount) in keys.into_iter().zip(amounts) {
            secrets_amounts.push((secret, amount));
        }
        remaining -= batch;
    }

    let now: u32 = frame_system::Pallet::<T>::block_number().saturated_into();
    let maturity: u32 = T::CoinbaseMaturity::get().saturated_into();
    let target_n = now + maturity + 2;
    for b in (now + 1)..=target_n {
        let bn: BlockNumberFor<T> = b.into();
        let prev: BlockNumberFor<T> = (b - 1).into();
        RingCt::<T>::on_finalize(prev);
        frame_system::Pallet::<T>::set_block_number(bn);
        RingCt::<T>::on_initialize(bn);
    }

    secrets_amounts
        .into_iter()
        .enumerate()
        .map(|(i, (secret, amount))| (first + i as u64, secret, amount))
        .collect()
}

fn ample_fee<T: Config>() -> u64 {
    T::MinFeePerByte::get().saturating_mul(20_000).max(10_000)
}

/// Build a valid 1-in/2-out FCMP transfer via host prove helpers.
fn build_fcmp_transfer<T: Config>(
    bed: &[(u64, [u8; 32], u64)],
    real: usize,
    fee: u64,
) -> TransferTx {
    let slots = TreeSlots::<T>::get();
    let mut digests = Vec::new();
    let mut admitted: Vec<(u64, [u8; 32], [u8; 32])> = Vec::new();
    for i in 0..slots {
        let d = MembershipLeafDigest::<T>::get(i).unwrap_or_else(membership::empty_leaf_hash);
        digests.push(d);
        if Admitted::<T>::contains_key(i) {
            let out = Outputs::<T>::get(i).expect("admitted");
            admitted.push((i, out.one_time_key, out.commitment));
        }
    }
    let root = MembershipRoot::<T>::get();
    let (idx, secret, amount) = bed[real];
    assert!(amount > fee + 1_000);
    let real_index = admitted
        .iter()
        .position(|(i, _, _)| *i == idx)
        .expect("admitted") as u32;

    // 1-in / 1-out: amount = out + fee, blinings x' = x_out (coinbase in_b = 0).
    let only = amount - fee;
    let out_b = host_blinding();
    let pr_args = (vec![only], vec![out_b]).encode();
    let pr_bytes = crypto_host::prove_range_v1(&pr_args);
    assert!(!pr_bytes.is_empty(), "prove_range");
    let (range_proof, commits): (Vec<u8>, Vec<[u8; 32]>) =
        Decode::decode(&mut &pr_bytes[..]).expect("decode range 1");
    let pb = out_b;
    let in_b = [0u8; 32];

    let ki = {
        let blob = crypto_host::key_image_v1(&secret);
        let mut k = [0u8; 32];
        k.copy_from_slice(&blob);
        k
    };
    let c_prime = crypto_host::commit_v1(amount, &pb);
    let (_, otk) = host_keypair();
    let (_, tx_pk) = host_keypair();

    let skeleton = TransferTx {
        membership_root: root,
        inputs: BoundedVec::try_from(vec![FcmpInput {
            key_image: ki,
            pseudo_commitment: c_prime,
            fcmp_proof: BoundedVec::try_from(vec![0u8; 32]).unwrap(),
        }])
        .unwrap(),
        outputs: BoundedVec::try_from(vec![Output {
            one_time_key: otk,
            commitment: commits[0],
            view_tag: 0,
            payload: Default::default(),
        }])
        .unwrap(),
        tx_pubkey: tx_pk,
        range_proof: BoundedVec::try_from(range_proof).unwrap(),
        fee,
    };
    let msg = RingCt::<T>::signing_hash(&skeleton);
    let prove_args = (msg, digests, admitted, real_index, secret, in_b, pb).encode();
    let proved = crypto_host::fcmp_prove_v1(&prove_args);
    assert!(!proved.is_empty(), "fcmp prove");
    let (proof, ki2, c2): (Vec<u8>, [u8; 32], [u8; 32]) =
        Decode::decode(&mut &proved[..]).expect("decode fcmp");
    assert_eq!(ki2, ki);
    assert_eq!(c2, c_prime);

    TransferTx {
        membership_root: root,
        inputs: BoundedVec::try_from(vec![FcmpInput {
            key_image: ki,
            pseudo_commitment: c_prime,
            fcmp_proof: BoundedVec::try_from(proof).unwrap(),
        }])
        .unwrap(),
        outputs: skeleton.outputs,
        tx_pubkey: skeleton.tx_pubkey,
        range_proof: skeleton.range_proof,
        fee,
    }
}

#[benchmarks]
mod benchmarks {
    use super::*;

    #[benchmark]
    fn authorize_transfer() {
        let bed = mint_admitted_bed::<T>(4);
        let fee = ample_fee::<T>();
        let real = bed
            .iter()
            .position(|(_, _, a)| *a > fee + 1_000)
            .expect("cover");
        let tx = build_fcmp_transfer::<T>(&bed, real, fee);
        #[block]
        {
            RingCt::<T>::authorize_transfer(&tx).expect("authorize");
        }
    }

    #[benchmark]
    fn transfer() {
        let bed = mint_admitted_bed::<T>(4);
        let fee = ample_fee::<T>();
        let real = bed
            .iter()
            .position(|(_, _, a)| *a > fee + 1_000)
            .expect("cover");
        let tx = build_fcmp_transfer::<T>(&bed, real, fee);
        #[extrinsic_call]
        _(RawOrigin::Authorized, tx);
        assert!(NextOutputIndex::<T>::get() > 4);
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
