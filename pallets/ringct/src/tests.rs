//! FCMP-only transfer tests (PR-7).

use crate::{membership, mock::*, CoinbaseOutput, Error, Event, FcmpInput, Output, TransferTx};
use frame_support::{assert_noop, assert_ok, traits::Authorize, BoundedVec};
use frame_system::RawOrigin;
use ringct_crypto::{
    fcmp::{self, ProveWitness, RingMember as FcmpRingMember},
    native as crypto,
};
use ringct_primitives::block_reward;
use sp_runtime::transaction_validity::TransactionSource;

fn authorized() -> RuntimeOrigin {
    RawOrigin::Authorized.into()
}

const FEE: u64 = 10_000;
/// Coinbase bed size (must stay ≤ MAX_FCMP_ANON_SET).
const BED: usize = 4;

fn bounded<T: Clone + core::fmt::Debug, const N: u32>(
    v: Vec<T>,
) -> BoundedVec<T, frame_support::traits::ConstU32<N>> {
    BoundedVec::try_from(v).expect("fits bound")
}

#[derive(Clone)]
struct Owned {
    index: u64,
    secret: [u8; 32],
    amount: u64,
    blinding: [u8; 32],
}

fn mint_ring_bed(n: usize) -> Vec<Owned> {
    let reward = block_reward(crate::Emitted::<Test>::get());
    let first = crate::NextOutputIndex::<Test>::get();
    let keys: Vec<([u8; 32], [u8; 32])> = (0..n).map(|_| crypto::random_secret_key()).collect();
    let mut amounts = vec![reward / n as u64; n];
    amounts[n - 1] = reward - (n as u64 - 1) * (reward / n as u64);

    let outputs: Vec<CoinbaseOutput> = keys
        .iter()
        .zip(&amounts)
        .map(|((_, public), amount)| CoinbaseOutput {
            one_time_key: *public,
            amount: *amount,
            view_tag: 0,
        })
        .collect();
    assert_ok!(RingCt::coinbase(
        RuntimeOrigin::none(),
        bounded::<_, 8>(outputs),
        crypto::random_secret_key().1,
    ));

    keys.into_iter()
        .zip(amounts)
        .enumerate()
        .map(|(i, ((secret, _), amount))| Owned {
            index: first + i as u64,
            secret,
            amount,
            blinding: [0u8; 32],
        })
        .collect()
}

/// Mature coinbases and admit them into the membership tree.
fn mature_bed(bed: &[Owned]) {
    run_to_block(62);
    for o in bed {
        assert!(
            RingCt::is_admitted(o.index),
            "output {} not admitted",
            o.index
        );
    }
}

/// Snapshot digests + admitted ring members from chain storage.
fn chain_membership_witness() -> ([u8; 32], Vec<[u8; 32]>, Vec<FcmpRingMember>) {
    let slots = RingCt::tree_slots();
    let mut digests = Vec::with_capacity(slots as usize);
    let mut admitted = Vec::new();
    let empty = membership::empty_leaf_hash();
    for i in 0..slots {
        let d = crate::MembershipLeafDigest::<Test>::get(i).unwrap_or(empty);
        digests.push(d);
        if crate::Admitted::<Test>::contains_key(i) {
            let out = crate::Outputs::<Test>::get(i).expect("admitted has output");
            admitted.push(FcmpRingMember {
                one_time_key: out.one_time_key,
                commitment: out.commitment,
                tree_index: i,
            });
        }
    }
    let root = RingCt::membership_root();
    assert_eq!(fcmp::root_from_leaves(&digests), root);
    (root, digests, admitted)
}

fn build_fcmp_spend(spends: &[&Owned], out_amounts: &[u64], fee: u64) -> TransferTx {
    assert!(!spends.is_empty());
    let (root, digests, admitted) = chain_membership_witness();
    assert!(!admitted.is_empty(), "need admitted leaves");

    // Output blindings free; last input pseudo closes Σ x' = Σ x_out.
    let out_blindings: Vec<[u8; 32]> = (0..out_amounts.len())
        .map(|_| crypto::random_blinding())
        .collect();
    let mut free_pseudos: Vec<[u8; 32]> = (0..spends.len().saturating_sub(1))
        .map(|_| crypto::random_blinding())
        .collect();
    let last_pseudo =
        crypto::balancing_blinding(&out_blindings, &free_pseudos).expect("balance blindings");
    free_pseudos.push(last_pseudo);
    let pseudo_blindings = free_pseudos;

    let (proof, commitments) = crypto::prove_range(out_amounts, &out_blindings).unwrap();
    let outputs: Vec<Output> = commitments
        .into_iter()
        .map(|commitment| Output {
            one_time_key: crypto::random_secret_key().1,
            commitment,
            view_tag: 0,
            payload: Default::default(),
        })
        .collect();

    // Stage spends with KI order (canonical).
    let mut staged: Vec<(Owned, [u8; 32], usize, [u8; 32], [u8; 32])> = spends
        .iter()
        .zip(pseudo_blindings.iter())
        .map(|(spend, pb)| {
            let real_index = admitted
                .iter()
                .position(|m| m.tree_index == spend.index)
                .expect("spend must be admitted");
            let ki = ringct_crypto::clsag::key_image(&spend.secret).unwrap();
            let c_prime = crypto::commit(spend.amount, pb).unwrap();
            ((*spend).clone(), *pb, real_index, ki, c_prime)
        })
        .collect();
    staged.sort_by_key(|s| s.3);

    let skeleton: Vec<FcmpInput> = staged
        .iter()
        .map(|(_, _, _, ki, c_prime)| FcmpInput {
            key_image: *ki,
            pseudo_commitment: *c_prime,
            fcmp_proof: bounded::<_, 12288>(vec![0u8; 32]),
        })
        .collect();

    let mut tx = TransferTx {
        membership_root: root,
        inputs: bounded::<_, 4>(skeleton),
        outputs: bounded::<_, 8>(outputs),
        tx_pubkey: crypto::random_secret_key().1,
        range_proof: bounded::<_, 1024>(proof),
        fee,
    };
    let msg = RingCt::signing_hash(&tx);

    let final_inputs: Vec<FcmpInput> = staged
        .iter()
        .map(|(spend, pb, real_index, ki, c_prime)| {
            let witness = ProveWitness {
                digests: digests.clone(),
                admitted: admitted.clone(),
                real_index: *real_index,
                secret_key: spend.secret,
                input_blinding: spend.blinding,
                pseudo_blinding: *pb,
            };
            let res = fcmp::prove(&msg, &witness).expect("fcmp prove");
            assert_eq!(res.key_image, *ki);
            assert_eq!(res.pseudo_commitment, *c_prime);
            FcmpInput {
                key_image: *ki,
                pseudo_commitment: *c_prime,
                fcmp_proof: bounded::<_, 12288>(res.proof),
            }
        })
        .collect();
    tx.inputs = bounded::<_, 4>(final_inputs);
    tx
}

fn bed_and_spend(real: usize) -> (Vec<Owned>, TransferTx) {
    let bed = mint_ring_bed(BED);
    mature_bed(&bed);
    let owned = &bed[real];
    let tx = build_fcmp_spend(&[owned], &[1_000, owned.amount - 1_000 - FEE], FEE);
    (bed, tx)
}

#[test]
fn fcmp_spend_happy_path() {
    new_test_ext().execute_with(|| {
        let (bed, tx) = bed_and_spend(2);
        let key_image = tx.inputs[0].key_image;
        assert_ok!(RingCt::transfer(authorized(), tx));
        assert!(crate::KeyImages::<Test>::contains_key(key_image));
        assert_eq!(crate::NextOutputIndex::<Test>::get(), BED as u64 + 2);
        let hidden = crate::Outputs::<Test>::get(BED as u64).unwrap();
        assert_eq!(hidden.amount, None);
        assert!(!hidden.coinbase);
        assert_eq!(crate::BlockFees::<Test>::get(), FEE);
        System::assert_last_event(
            Event::Transferred {
                key_images: vec![key_image],
                first_output_index: BED as u64,
                output_count: 2,
                fee: FEE,
            }
            .into(),
        );
        drop(bed);
    });
}

#[test]
fn key_image_links_double_spends() {
    new_test_ext().execute_with(|| {
        let bed = mint_ring_bed(BED);
        mature_bed(&bed);
        let tx_a = build_fcmp_spend(&[&bed[0]], &[1_000, bed[0].amount - 1_000 - FEE], FEE);
        let ki = tx_a.inputs[0].key_image;
        assert_ok!(RingCt::transfer(authorized(), tx_a));
        // Re-prove same secret under new root after first spend.
        run_to_block(System::block_number() + 1);
        // bed[0] still admitted (spent leaves stay); double-spend fails on KI.
        let tx_b = build_fcmp_spend(&[&bed[0]], &[500, bed[0].amount - 500 - FEE], FEE);
        assert_eq!(tx_b.inputs[0].key_image, ki);
        assert_noop!(
            RingCt::transfer(authorized(), tx_b),
            Error::<Test>::KeyImageAlreadySpent
        );
    });
}

#[test]
fn fee_below_floor_fails() {
    new_test_ext().execute_with(|| {
        let bed = mint_ring_bed(BED);
        mature_bed(&bed);
        let mut tx = build_fcmp_spend(&[&bed[0]], &[1_000, bed[0].amount - 1_000 - 1], 1);
        // Force fee below floor after building (proof still valid for old fee in msg — fails fee check first)
        tx.fee = 0;
        assert_noop!(RingCt::transfer(authorized(), tx), Error::<Test>::FeeTooLow);
    });
}

#[test]
fn root_stale_rejected() {
    new_test_ext().execute_with(|| {
        let bed = mint_ring_bed(BED);
        mature_bed(&bed);
        let mut tx = build_fcmp_spend(&[&bed[1]], &[1_000, bed[1].amount - 1_000 - FEE], FEE);
        tx.membership_root = [0xEE; 32];
        assert_noop!(RingCt::transfer(authorized(), tx), Error::<Test>::RootStale);
    });
}

#[test]
fn bad_fcmp_proof_rejected() {
    new_test_ext().execute_with(|| {
        let bed = mint_ring_bed(BED);
        mature_bed(&bed);
        let mut tx = build_fcmp_spend(&[&bed[0]], &[1_000, bed[0].amount - 1_000 - FEE], FEE);
        let mut bad = tx.inputs[0].fcmp_proof.to_vec();
        if let Some(b) = bad.last_mut() {
            *b ^= 0xff;
        }
        tx.inputs[0].fcmp_proof = bounded::<_, 12288>(bad);
        assert_noop!(
            RingCt::transfer(authorized(), tx),
            Error::<Test>::FcmpInvalid
        );
    });
}

#[test]
fn multi_input_transfer() {
    new_test_ext().execute_with(|| {
        let bed = mint_ring_bed(BED);
        mature_bed(&bed);
        let total = bed[0].amount + bed[1].amount;
        let tx = build_fcmp_spend(&[&bed[0], &bed[1]], &[1_000, total - 1_000 - FEE], FEE);
        assert_eq!(tx.inputs.len(), 2);
        assert!(tx.inputs[0].key_image < tx.inputs[1].key_image);
        assert_ok!(RingCt::transfer(authorized(), tx));
    });
}

#[test]
fn authorize_provides_key_image_tags() {
    new_test_ext().execute_with(|| {
        let bed = mint_ring_bed(BED);
        mature_bed(&bed);
        let tx = build_fcmp_spend(&[&bed[0]], &[1_000, bed[0].amount - 1_000 - FEE], FEE);
        let call = crate::Call::<Test>::transfer { tx: tx.clone() };
        let (validity, _) = call
            .authorize(TransactionSource::External)
            .expect("authorizeable")
            .expect("ok");
        assert_eq!(validity.provides.len(), 1);
        assert_ok!(RingCt::transfer(authorized(), tx));
    });
}

#[test]
fn empty_inputs_fail() {
    new_test_ext().execute_with(|| {
        let tx = TransferTx {
            membership_root: RingCt::membership_root(),
            inputs: Default::default(),
            outputs: bounded::<_, 8>(vec![Output {
                one_time_key: crypto::random_secret_key().1,
                commitment: crypto::value_commitment(1),
                view_tag: 0,
                payload: Default::default(),
            }]),
            tx_pubkey: crypto::random_secret_key().1,
            range_proof: Default::default(),
            fee: FEE,
        };
        assert_noop!(
            RingCt::transfer(authorized(), tx),
            Error::<Test>::EmptyInputsOrOutputs
        );
    });
}

#[test]
fn invalid_point_rejected() {
    new_test_ext().execute_with(|| {
        let bed = mint_ring_bed(BED);
        mature_bed(&bed);
        let mut tx = build_fcmp_spend(&[&bed[0]], &[1_000, bed[0].amount - 1_000 - FEE], FEE);
        tx.outputs[0].one_time_key = [0xff; 32];
        assert_noop!(
            RingCt::transfer(authorized(), tx),
            Error::<Test>::InvalidPoint
        );
    });
}

#[test]
fn balance_failure() {
    new_test_ext().execute_with(|| {
        let bed = mint_ring_bed(BED);
        mature_bed(&bed);
        // Over-claim outputs — prove with wrong amounts vs input.
        // build_fcmp_spend balances correctly; force bad by changing output
        // commitment after prove → range/balance fails.
        let mut tx = build_fcmp_spend(&[&bed[0]], &[1_000, bed[0].amount - 1_000 - FEE], FEE);
        tx.outputs[0].commitment = crypto::value_commitment(u64::MAX);
        // FCMP still verifies (doesn't bind output amounts into membership);
        // balance or range fails.
        assert!(RingCt::transfer(authorized(), tx).is_err());
    });
}

#[test]
fn fcmp_mode_is_fcmp_only() {
    new_test_ext().execute_with(|| {
        assert_eq!(RingCt::fcmp_mode(), crate::FCMP_MODE_FCMP_ONLY);
    });
}

#[test]
fn coinbase_and_membership_still_work() {
    new_test_ext().execute_with(|| {
        let bed = mint_ring_bed(2);
        assert_eq!(RingCt::tree_slots(), 2);
        mature_bed(&bed);
        assert!(RingCt::is_admitted(0));
        assert!(RingCt::is_admitted(1));
    });
}

#[test]
fn signed_origin_rejected() {
    new_test_ext().execute_with(|| {
        let bed = mint_ring_bed(BED);
        mature_bed(&bed);
        let tx = build_fcmp_spend(&[&bed[0]], &[1_000, bed[0].amount - 1_000 - FEE], FEE);
        assert_noop!(
            RingCt::transfer(RuntimeOrigin::signed(1), tx),
            // ensure_authorized fails
            sp_runtime::DispatchError::BadOrigin
        );
    });
}
