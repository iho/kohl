// ValidateUnsigned is deprecated in stable2606; migration to
// `#[pallet::authorize]` is tracked for Phase 4 (see lib.rs).
#![allow(deprecated)]

use crate::{mock::*, CoinbaseOutput, Error, Event, Output, RingInput, TransferTx};
use codec::Encode;
use frame_support::{assert_noop, assert_ok, BoundedVec};
use ringct_crypto::{clsag, native as crypto, stealth};
use ringct_primitives::block_reward;
use sp_runtime::{
    traits::ValidateUnsigned,
    transaction_validity::{InvalidTransaction, TransactionSource},
};

const FEE: u64 = 10_000;
/// Mock runtime ring size (see mock.rs).
const RING: usize = 4;

fn bounded<T: Clone + core::fmt::Debug, const N: u32>(
    v: Vec<T>,
) -> BoundedVec<T, frame_support::traits::ConstU32<N>> {
    BoundedVec::try_from(v).expect("fits bound")
}

/// An output we control: its global index and everything needed to spend it.
#[derive(Clone)]
struct Owned {
    index: u64,
    secret: [u8; 32],
    amount: u64,
    blinding: [u8; 32],
}

/// Mint one coinbase whose reward is split across `n` outputs with known
/// one-time secrets — the "ring bed" every test spends against.
/// Coinbase commitments have zero blinding.
fn mint_ring_bed(n: usize) -> Vec<Owned> {
    let reward = block_reward(crate::Emitted::<Test>::get());
    let first = crate::NextOutputIndex::<Test>::get();
    let keys: Vec<([u8; 32], [u8; 32])> = (0..n).map(|_| crypto::random_secret_key()).collect();
    let mut amounts = vec![reward / n as u64; n];
    amounts[n - 1] = reward - (n as u64 - 1) * (reward / n as u64);

    let outputs: Vec<CoinbaseOutput> = keys
        .iter()
        .zip(&amounts)
        .map(|((_, public), amount)| CoinbaseOutput { one_time_key: *public, amount: *amount })
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

/// Concatenate (one_time_key ‖ commitment) for the given ring indices,
/// straight from chain storage.
fn ring_blob(ring: &[u64]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(ring.len() * 64);
    for index in ring {
        let stored = crate::Outputs::<Test>::get(index).expect("ring member exists");
        blob.extend_from_slice(&stored.one_time_key);
        blob.extend_from_slice(&stored.commitment);
    }
    blob
}

/// One input to assemble into a multi-spend transfer.
struct SpendSpec<'a> {
    real: &'a Owned,
    ring: Vec<u64>,
}

/// Build a fully valid ring transfer spending one or more reals (each hidden
/// in its own ring), creating outputs of `out_amounts` to fresh random keys.
/// Inputs are sorted by key image as required by consensus.
fn build_ring_spends(spends: &[SpendSpec], out_amounts: &[u64], fee: u64) -> TransferTx {
    assert!(!spends.is_empty());
    // Note: callers may deliberately unbalance amounts to test the on-chain
    // balance equation; we do not assert amount conservation here.

    // Pseudo commitments first (need their blindings for the output balancer).
    let mut prepared = Vec::with_capacity(spends.len());
    for spec in spends {
        let position =
            spec.ring.iter().position(|i| *i == spec.real.index).expect("real in ring");
        let pseudo_blinding = crypto::random_blinding();
        let pseudo_commitment = crypto::commit(spec.real.amount, &pseudo_blinding).unwrap();
        let key_image = clsag::key_image(&spec.real.secret).unwrap();
        prepared.push((spec, position, pseudo_blinding, pseudo_commitment, key_image));
    }
    // Canonical input order by key image.
    prepared.sort_by(|a, b| a.4.cmp(&b.4));

    let pseudo_blindings: Vec<[u8; 32]> = prepared.iter().map(|p| p.2).collect();
    let mut out_blindings: Vec<[u8; 32]> =
        (1..out_amounts.len()).map(|_| crypto::random_blinding()).collect();
    out_blindings
        .push(crypto::balancing_blinding(&pseudo_blindings, &out_blindings).unwrap());
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

    let mut inputs: Vec<RingInput> = prepared
        .iter()
        .map(|(spec, _, _, pseudo_commitment, key_image)| RingInput {
            ring: bounded::<_, 16>(spec.ring.clone()),
            key_image: *key_image,
            pseudo_commitment: *pseudo_commitment,
            clsag: Default::default(),
        })
        .collect();

    let mut tx = TransferTx {
        inputs: bounded::<_, 8>(inputs.clone()),
        outputs: bounded::<_, 8>(outputs),
        tx_pubkey: crypto::random_secret_key().1,
        range_proof: bounded::<_, 1024>(proof),
        fee,
    };
    let msg = RingCt::signing_hash(&tx);
    for (i, (spec, position, pseudo_blinding, pseudo_commitment, key_image)) in
        prepared.iter().enumerate()
    {
        let blob = ring_blob(&spec.ring);
        let sig = clsag::sign(
            &msg,
            &blob,
            *position,
            &spec.real.secret,
            &spec.real.blinding,
            pseudo_blinding,
        )
        .expect("valid signing inputs");
        assert_eq!(sig.key_image, *key_image);
        assert_eq!(sig.pseudo_commitment, *pseudo_commitment);
        inputs[i].clsag = bounded::<_, 576>(sig.signature);
    }
    tx.inputs = bounded::<_, 8>(inputs);
    tx
}

/// Single-input convenience wrapper around [`build_ring_spends`].
fn build_ring_spend(real: &Owned, ring: Vec<u64>, out_amounts: &[u64], fee: u64) -> TransferTx {
    build_ring_spends(&[SpendSpec { real, ring }], out_amounts, fee)
}

/// Standard scenario: 4 matured coinbase outputs, spend `bed[real]` through
/// a ring of all four into two hidden outputs.
fn bed_and_spend(real: usize) -> (Vec<Owned>, TransferTx) {
    let bed = mint_ring_bed(RING);
    run_to_block(100); // past coinbase maturity (1 + 60)
    let owned = &bed[real];
    let ring: Vec<u64> = bed.iter().map(|o| o.index).collect();
    let tx = build_ring_spend(owned, ring, &[1_000, owned.amount - 1_000 - FEE], FEE);
    (bed, tx)
}

#[test]
fn ring_spend_happy_path() {
    new_test_ext().execute_with(|| {
        let (bed, tx) = bed_and_spend(2);
        let key_image = tx.inputs[0].key_image;
        assert_ok!(RingCt::transfer(RuntimeOrigin::none(), tx));

        assert!(crate::KeyImages::<Test>::contains_key(key_image));
        // No per-output spent flag exists: the chain cannot know which of
        // the 4 ring members was really spent.
        assert_eq!(crate::NextOutputIndex::<Test>::get(), RING as u64 + 2);
        let hidden = crate::Outputs::<Test>::get(RING as u64).unwrap();
        assert_eq!(hidden.amount, None);
        assert!(!hidden.coinbase);
        assert_eq!(crate::BlockFees::<Test>::get(), FEE);
        System::assert_last_event(
            Event::Transferred {
                key_images: vec![key_image],
                first_output_index: RING as u64,
                output_count: 2,
                fee: FEE,
            }
            .into(),
        );
        drop(bed);
    });
}

#[test]
fn key_image_links_double_spends_across_different_rings() {
    new_test_ext().execute_with(|| {
        let bed = mint_ring_bed(RING);
        run_to_block(2);
        let bed2 = mint_ring_bed(RING); // more outputs for a different ring
        run_to_block(100);

        let real = &bed[1];
        let ring_a: Vec<u64> = bed.iter().map(|o| o.index).collect();
        let tx_a = build_ring_spend(real, ring_a, &[real.amount - FEE], FEE);
        assert_ok!(RingCt::transfer(RuntimeOrigin::none(), tx_a));

        // Same real output, completely different decoys: the key image is
        // identical, so the double spend is caught without knowing which
        // ring member was real.
        let ring_b = vec![real.index, bed2[0].index, bed2[1].index, bed2[2].index];
        let mut ring_b_sorted = ring_b.clone();
        ring_b_sorted.sort();
        let tx_b = build_ring_spend(real, ring_b_sorted, &[real.amount - FEE], FEE);
        assert_noop!(
            RingCt::transfer(RuntimeOrigin::none(), tx_b),
            Error::<Test>::KeyImageAlreadySpent
        );
    });
}

#[test]
fn wrong_ring_size_fails() {
    new_test_ext().execute_with(|| {
        let bed = mint_ring_bed(RING);
        run_to_block(100);
        let real = &bed[0];
        let ring: Vec<u64> = bed[..3].iter().map(|o| o.index).collect(); // only 3
        let tx = build_ring_spend(real, ring, &[real.amount - FEE], FEE);
        assert_noop!(RingCt::transfer(RuntimeOrigin::none(), tx), Error::<Test>::RingSizeInvalid);
    });
}

#[test]
fn unknown_ring_member_fails() {
    new_test_ext().execute_with(|| {
        let bed = mint_ring_bed(RING);
        run_to_block(100);
        let real = &bed[0];
        // Chain-side lookup must fail before any crypto runs, so build the
        // tx against a hand-rolled blob containing a fabricated member.
        let ring = vec![real.index, bed[1].index, bed[2].index, 99];
        let mut blob = ring_blob(&ring[..3]);
        blob.extend_from_slice(&crypto::random_secret_key().1);
        blob.extend_from_slice(&crypto::commit(1, &crypto::random_blinding()).unwrap());

        let pseudo_blinding = crypto::random_blinding();
        let (proof, commitments) =
            crypto::prove_range(&[real.amount - FEE], &[pseudo_blinding]).unwrap();
        let mut tx = TransferTx {
            inputs: bounded::<_, 8>(vec![RingInput {
                ring: bounded::<_, 16>(ring),
                key_image: clsag::key_image(&real.secret).unwrap(),
                pseudo_commitment: crypto::commit(real.amount, &pseudo_blinding).unwrap(),
                clsag: Default::default(),
            }]),
            outputs: bounded::<_, 8>(vec![Output {
                one_time_key: crypto::random_secret_key().1,
                commitment: commitments[0],
                view_tag: 0,
                payload: Default::default(),
            }]),
            tx_pubkey: crypto::random_secret_key().1,
            range_proof: bounded::<_, 1024>(proof),
            fee: FEE,
        };
        let msg = RingCt::signing_hash(&tx);
        let sig = clsag::sign(&msg, &blob, 0, &real.secret, &real.blinding, &pseudo_blinding)
            .unwrap();
        tx.inputs[0].clsag = bounded::<_, 576>(sig.signature);
        assert_noop!(RingCt::transfer(RuntimeOrigin::none(), tx), Error::<Test>::UnknownOutput);
    });
}

#[test]
fn immature_ring_member_poisons_the_ring() {
    new_test_ext().execute_with(|| {
        let bed = mint_ring_bed(3);
        run_to_block(50);
        let late = mint_ring_bed(3); // matures at block 110
        run_to_block(100); // bed mature, late not

        let real = &bed[0];
        let mut ring = vec![real.index, bed[1].index, bed[2].index, late[0].index];
        ring.sort();
        let tx = build_ring_spend(real, ring, &[real.amount - FEE], FEE);
        assert_noop!(RingCt::transfer(RuntimeOrigin::none(), tx), Error::<Test>::OutputImmature);
    });
}

#[test]
fn tampering_any_signed_field_invalidates_the_clsag() {
    new_test_ext().execute_with(|| {
        // Commitment swap.
        let (_, mut tx) = bed_and_spend(0);
        tx.outputs[0].commitment[0] ^= 1;
        assert_noop!(RingCt::transfer(RuntimeOrigin::none(), tx), Error::<Test>::ClsagInvalid);
    });
    new_test_ext().execute_with(|| {
        // Receiver swap (one-time key).
        let (_, mut tx) = bed_and_spend(0);
        tx.outputs[0].one_time_key = crypto::random_secret_key().1;
        assert_noop!(RingCt::transfer(RuntimeOrigin::none(), tx), Error::<Test>::ClsagInvalid);
    });
    new_test_ext().execute_with(|| {
        // Fee swap.
        let (_, mut tx) = bed_and_spend(0);
        tx.fee += 1;
        assert_noop!(RingCt::transfer(RuntimeOrigin::none(), tx), Error::<Test>::ClsagInvalid);
    });
    new_test_ext().execute_with(|| {
        // Garbage signature bytes.
        let (_, mut tx) = bed_and_spend(0);
        let mut sig = tx.inputs[0].clsag.to_vec();
        sig[33] ^= 1;
        tx.inputs[0].clsag = bounded::<_, 576>(sig);
        assert_noop!(RingCt::transfer(RuntimeOrigin::none(), tx), Error::<Test>::ClsagInvalid);
    });
}

#[test]
fn pseudo_commitment_to_wrong_amount_fails_balance() {
    new_test_ext().execute_with(|| {
        let bed = mint_ring_bed(RING);
        run_to_block(100);
        let real = &bed[0];
        let ring: Vec<u64> = bed.iter().map(|o| o.index).collect();
        // Outputs claim 1 unit more than the input holds; the CLSAG still
        // verifies (its pseudo commits the *real* amount) but the balance
        // equation must catch it.
        let tx = build_ring_spend(real, ring, &[real.amount - FEE + 1], FEE);
        assert_noop!(
            RingCt::transfer(RuntimeOrigin::none(), tx),
            Error::<Test>::BalanceCheckFailed
        );
    });
}

#[test]
fn duplicate_key_images_in_one_tx_fail() {
    new_test_ext().execute_with(|| {
        let bed = mint_ring_bed(RING);
        run_to_block(100);
        let real = &bed[0];
        let ring: Vec<u64> = bed.iter().map(|o| o.index).collect();
        let single = build_ring_spend(real, ring, &[real.amount - FEE], FEE);
        let mut tx = single.clone();
        tx.inputs = bounded::<_, 8>(vec![single.inputs[0].clone(), single.inputs[0].clone()]);
        assert_noop!(
            RingCt::transfer(RuntimeOrigin::none(), tx),
            Error::<Test>::InputsNotSortedUnique
        );
    });
}

#[test]
fn validate_unsigned_provides_key_image_tags() {
    new_test_ext().execute_with(|| {
        let (_, tx) = bed_and_spend(1);
        let key_image = tx.inputs[0].key_image;

        let validity = <RingCt as ValidateUnsigned>::validate_unsigned(
            TransactionSource::External,
            &crate::Call::transfer { tx: tx.clone() },
        )
        .expect("valid");
        assert_eq!(validity.provides, vec![(b"kohl/ki", key_image).encode()]);
        assert!(validity.propagate);

        // After inclusion the key image is stale in the pool.
        assert_ok!(RingCt::transfer(RuntimeOrigin::none(), tx.clone()));
        assert_eq!(
            <RingCt as ValidateUnsigned>::validate_unsigned(
                TransactionSource::External,
                &crate::Call::transfer { tx },
            ),
            Err(InvalidTransaction::Stale.into())
        );

        // Coinbase never enters the pool.
        assert_eq!(
            <RingCt as ValidateUnsigned>::validate_unsigned(
                TransactionSource::External,
                &crate::Call::coinbase {
                    outputs: bounded::<_, 8>(vec![CoinbaseOutput {
                        one_time_key: crypto::random_secret_key().1,
                        amount: 1,
                    }]),
                    tx_pubkey: [0u8; 32],
                },
            ),
            Err(InvalidTransaction::Call.into())
        );
    });
}

#[test]
fn coinbase_inherent_computes_reward_from_state() {
    use frame_support::inherent::ProvideInherent;
    use sp_inherents::InherentData;
    new_test_ext().execute_with(|| {
        let mut data = InherentData::new();
        let dest: crate::CoinbaseInherent = ([9u8; 32], [8u8; 32]);
        data.put_data(crate::INHERENT_IDENTIFIER, &dest).unwrap();

        let call = <RingCt as ProvideInherent>::create_inherent(&data).expect("inherent built");
        match call {
            crate::Call::coinbase { outputs, tx_pubkey } => {
                assert_eq!(tx_pubkey, [8u8; 32]);
                assert_eq!(outputs.len(), 1);
                assert_eq!(outputs[0].one_time_key, [9u8; 32]);
                // Miner cannot influence the amount: it is reward + fees.
                assert_eq!(outputs[0].amount, block_reward(0));
            }
            _ => panic!("expected coinbase call"),
        }
        // And the produced inherent actually applies.
        assert_ok!(<RingCt as ProvideInherent>::create_inherent(&data)
            .and_then(|c| match c {
                crate::Call::coinbase { outputs, tx_pubkey } =>
                    Some(RingCt::coinbase(RuntimeOrigin::none(), outputs, tx_pubkey)),
                _ => None,
            })
            .unwrap());
        assert_eq!(crate::Emitted::<Test>::get(), block_reward(0));
    });
}

#[test]
fn coinbase_sum_and_double_mint_rules_hold() {
    new_test_ext().execute_with(|| {
        let reward = block_reward(0);
        let key = crypto::random_secret_key().1;
        assert_noop!(
            RingCt::coinbase(
                RuntimeOrigin::none(),
                bounded::<_, 8>(vec![CoinbaseOutput { one_time_key: key, amount: reward + 1 }]),
                [0u8; 32],
            ),
            Error::<Test>::CoinbaseAmountInvalid
        );
        mint_ring_bed(2);
        assert_noop!(
            RingCt::coinbase(
                RuntimeOrigin::none(),
                bounded::<_, 8>(vec![CoinbaseOutput { one_time_key: key, amount: reward }]),
                [0u8; 32],
            ),
            Error::<Test>::CoinbaseAlreadyIncluded
        );
        run_to_block(2);
        mint_ring_bed(2); // flag reset, new block mints fine
    });
}

/// The flagship test: a full stealth payment lifecycle. Miner mints to a
/// stealth-derived one-time key; the receiver's wallet scans the chain with
/// only its view key, recovers the spend secret, and spends through a ring —
/// address never on chain, sender hidden among 4, amounts hidden.
#[test]
fn stealth_end_to_end() {
    new_test_ext().execute_with(|| {
        // Receiver wallet.
        let (keys, addr) = stealth::keypair();

        // Miner derives a stealth output for the receiver (e.g. a pool
        // payout): coinbase output 0 of 4.
        let reward = block_reward(0);
        let (tx_secret, tx_pubkey) = stealth::tx_keypair();
        let shared = stealth::sender_shared_secret(&tx_secret, &addr.view_public).unwrap();
        let (otk, _tag) = stealth::derive_one_time_key(&shared, &addr.spend_public, 0).unwrap();

        let mut outputs = vec![CoinbaseOutput { one_time_key: otk, amount: reward / 2 }];
        for _ in 0..3 {
            outputs.push(CoinbaseOutput {
                one_time_key: crypto::random_secret_key().1,
                amount: reward / 6,
            });
        }
        outputs[3].amount = reward - reward / 2 - 2 * (reward / 6);
        assert_ok!(RingCt::coinbase(RuntimeOrigin::none(), bounded::<_, 8>(outputs), tx_pubkey));

        // Receiver scans the chain with the view key only.
        let mut found = None;
        for index in 0..crate::NextOutputIndex::<Test>::get() {
            let stored = crate::Outputs::<Test>::get(index).unwrap();
            // Coinbase view tags default to 0 in this test; check via full
            // derivation (local output index within the tx is the position).
            if stealth::matches_output(
                &keys.view_secret,
                &addr.spend_public,
                &stored.tx_pubkey,
                index as u32,
                &stored.one_time_key,
                stealth::view_tag(
                    &stealth::receiver_shared_secret(&keys.view_secret, &stored.tx_pubkey)
                        .unwrap(),
                    index as u32,
                ),
            ) {
                found = Some((index, stored));
            }
        }
        let (index, stored) = found.expect("wallet finds its output");
        assert_eq!(index, 0);
        assert_eq!(stored.amount, Some(reward / 2));

        // Recover the one-time spend secret and spend through a ring.
        let secret = stealth::recover_spend_secret(&keys, &stored.tx_pubkey, 0).unwrap();
        run_to_block(100);
        let owned =
            Owned { index: 0, secret, amount: reward / 2, blinding: [0u8; 32] };
        let tx = build_ring_spend(&owned, vec![0, 1, 2, 3], &[reward / 2 - FEE], FEE);
        assert_ok!(RingCt::transfer(RuntimeOrigin::none(), tx));
    });
}

// ---- §3.4 verification coverage (shape, multi-input, crypto edge cases) ----

#[test]
fn multi_input_transfer_happy_path() {
    new_test_ext().execute_with(|| {
        let bed = mint_ring_bed(RING);
        run_to_block(100);
        let ring: Vec<u64> = bed.iter().map(|o| o.index).collect();
        let a = &bed[0];
        let b = &bed[1];
        let total = a.amount + b.amount;
        let tx = build_ring_spends(
            &[
                SpendSpec { real: a, ring: ring.clone() },
                SpendSpec { real: b, ring: ring.clone() },
            ],
            &[total / 2 - FEE, total - total / 2],
            FEE,
        );
        assert_eq!(tx.inputs.len(), 2);
        // Canonical form: strictly increasing key images.
        assert!(tx.inputs[0].key_image < tx.inputs[1].key_image);

        let kis: Vec<_> = tx.inputs.iter().map(|i| i.key_image).collect();
        assert_ok!(RingCt::transfer(RuntimeOrigin::none(), tx));
        for ki in &kis {
            assert!(crate::KeyImages::<Test>::contains_key(ki));
        }
        assert_eq!(crate::BlockFees::<Test>::get(), FEE);
        assert_eq!(crate::NextOutputIndex::<Test>::get(), RING as u64 + 2);
    });
}

#[test]
fn multi_input_unsorted_key_images_fail() {
    new_test_ext().execute_with(|| {
        let bed = mint_ring_bed(RING);
        run_to_block(100);
        let ring: Vec<u64> = bed.iter().map(|o| o.index).collect();
        let mut tx = build_ring_spends(
            &[
                SpendSpec { real: &bed[0], ring: ring.clone() },
                SpendSpec { real: &bed[1], ring: ring.clone() },
            ],
            &[bed[0].amount + bed[1].amount - FEE],
            FEE,
        );
        // Reverse a valid sorted pair → InputsNotSortedUnique.
        tx.inputs.as_mut().swap(0, 1);
        assert_noop!(
            RingCt::transfer(RuntimeOrigin::none(), tx),
            Error::<Test>::InputsNotSortedUnique
        );
    });
}

#[test]
fn unsorted_or_duplicate_ring_indices_fail() {
    new_test_ext().execute_with(|| {
        let bed = mint_ring_bed(RING);
        run_to_block(100);
        let real = &bed[0];

        // Unsorted but otherwise a valid spend against a sorted signing ring.
        let sorted: Vec<u64> = bed.iter().map(|o| o.index).collect();
        let mut tx = build_ring_spend(real, sorted.clone(), &[real.amount - FEE], FEE);
        tx.inputs[0].ring = bounded::<_, 16>(vec![sorted[0], sorted[2], sorted[1], sorted[3]]);
        assert_noop!(
            RingCt::transfer(RuntimeOrigin::none(), tx),
            Error::<Test>::RingIndicesInvalid
        );

        // Duplicate indices (not strictly increasing).
        let mut tx = build_ring_spend(real, sorted.clone(), &[real.amount - FEE], FEE);
        tx.inputs[0].ring =
            bounded::<_, 16>(vec![sorted[0], sorted[1], sorted[1], sorted[2]]);
        assert_noop!(
            RingCt::transfer(RuntimeOrigin::none(), tx),
            Error::<Test>::RingIndicesInvalid
        );
    });
}

#[test]
fn empty_inputs_or_outputs_fail() {
    new_test_ext().execute_with(|| {
        let (_, mut tx) = bed_and_spend(0);
        tx.inputs = bounded::<_, 8>(vec![]);
        assert_noop!(
            RingCt::transfer(RuntimeOrigin::none(), tx),
            Error::<Test>::EmptyInputsOrOutputs
        );

        let (_, mut tx) = bed_and_spend(0);
        tx.outputs = bounded::<_, 8>(vec![]);
        // Empty outputs: shape check fails before crypto (fee still present).
        assert_noop!(
            RingCt::transfer(RuntimeOrigin::none(), tx),
            Error::<Test>::EmptyInputsOrOutputs
        );
    });
}

#[test]
fn fee_below_per_byte_floor_fails() {
    new_test_ext().execute_with(|| {
        let bed = mint_ring_bed(RING);
        run_to_block(100);
        let real = &bed[0];
        let ring: Vec<u64> = bed.iter().map(|o| o.index).collect();
        // MinFeePerByte = 1 in the mock, so fee 0 is always below the floor.
        let tx = build_ring_spend(real, ring, &[real.amount], 0);
        assert_noop!(RingCt::transfer(RuntimeOrigin::none(), tx), Error::<Test>::FeeTooLow);
    });
}

#[test]
fn invalid_range_proof_fails_after_clsag() {
    new_test_ext().execute_with(|| {
        // Range proof is *not* in the CLSAG message; tampering it leaves the
        // signature valid and must be caught by the Bulletproof check.
        let (_, mut tx) = bed_and_spend(0);
        let mut proof = tx.range_proof.to_vec();
        proof[0] ^= 0xff;
        tx.range_proof = bounded::<_, 1024>(proof);
        assert_noop!(
            RingCt::transfer(RuntimeOrigin::none(), tx),
            Error::<Test>::RangeProofInvalid
        );
    });
}

#[test]
fn identity_and_garbage_key_images_fail_clsag() {
    new_test_ext().execute_with(|| {
        // Ristretto identity (canonical all-zero encoding).
        let (_, mut tx) = bed_and_spend(0);
        tx.inputs[0].key_image = [0u8; 32];
        assert_noop!(RingCt::transfer(RuntimeOrigin::none(), tx), Error::<Test>::ClsagInvalid);
    });
    new_test_ext().execute_with(|| {
        // Non-canonical / non-decompressible point bytes.
        let (_, mut tx) = bed_and_spend(0);
        tx.inputs[0].key_image = [0xff; 32];
        assert_noop!(RingCt::transfer(RuntimeOrigin::none(), tx), Error::<Test>::ClsagInvalid);
    });
}

#[test]
fn non_canonical_pseudo_commitment_fails() {
    new_test_ext().execute_with(|| {
        let (_, mut tx) = bed_and_spend(0);
        tx.inputs[0].pseudo_commitment = [0xff; 32];
        // Bound into the CLSAG message + ring equation → ClsagInvalid first.
        assert_noop!(RingCt::transfer(RuntimeOrigin::none(), tx), Error::<Test>::ClsagInvalid);
    });
}

#[test]
fn non_coinbase_spendable_age_is_enforced() {
    new_test_ext().execute_with(|| {
        let bed = mint_ring_bed(RING);
        run_to_block(100);

        // Controlled spend so we retain the one-time secret of the new output.
        let real = &bed[0];
        let ring: Vec<u64> = bed.iter().map(|o| o.index).collect();
        let out_amount = real.amount - FEE;
        let (out_secret, out_public) = crypto::random_secret_key();
        // Single output absorbs the full pseudo blinding (balance equation).
        let pseudo_blinding = crypto::random_blinding();
        let out_blinding = pseudo_blinding;
        let (proof, _) = crypto::prove_range(&[out_amount], &[out_blinding]).unwrap();

        let mut tx = TransferTx {
            inputs: bounded::<_, 8>(vec![RingInput {
                ring: bounded::<_, 16>(ring.clone()),
                key_image: clsag::key_image(&real.secret).unwrap(),
                pseudo_commitment: crypto::commit(real.amount, &pseudo_blinding).unwrap(),
                clsag: Default::default(),
            }]),
            outputs: bounded::<_, 8>(vec![Output {
                one_time_key: out_public,
                commitment: crypto::commit(out_amount, &out_blinding).unwrap(),
                view_tag: 0,
                payload: Default::default(),
            }]),
            tx_pubkey: crypto::random_secret_key().1,
            range_proof: bounded::<_, 1024>(proof),
            fee: FEE,
        };
        let msg = RingCt::signing_hash(&tx);
        let sig = clsag::sign(
            &msg,
            &ring_blob(&ring),
            0,
            &real.secret,
            &real.blinding,
            &pseudo_blinding,
        )
        .unwrap();
        tx.inputs[0].clsag = bounded::<_, 576>(sig.signature);
        let first_out = crate::NextOutputIndex::<Test>::get();
        assert_ok!(RingCt::transfer(RuntimeOrigin::none(), tx));

        // Height 100, SpendableAge 10 → spendable at block ≥ 110.
        let owned = Owned {
            index: first_out,
            secret: out_secret,
            amount: out_amount,
            blinding: out_blinding,
        };
        let mut re_ring = vec![owned.index, bed[1].index, bed[2].index, bed[3].index];
        re_ring.sort();
        let early = build_ring_spend(&owned, re_ring.clone(), &[out_amount - FEE], FEE);
        assert_noop!(
            RingCt::transfer(RuntimeOrigin::none(), early),
            Error::<Test>::OutputImmature
        );

        run_to_block(110);
        let ready = build_ring_spend(&owned, re_ring, &[out_amount - FEE], FEE);
        assert_ok!(RingCt::transfer(RuntimeOrigin::none(), ready));
    });
}

#[test]
fn fees_carry_into_next_coinbase() {
    new_test_ext().execute_with(|| {
        let (_, tx) = bed_and_spend(0);
        assert_ok!(RingCt::transfer(RuntimeOrigin::none(), tx));
        assert_eq!(crate::BlockFees::<Test>::get(), FEE);

        run_to_block(101);
        let reward = block_reward(crate::Emitted::<Test>::get());
        let key = crypto::random_secret_key().1;
        assert_ok!(RingCt::coinbase(
            RuntimeOrigin::none(),
            bounded::<_, 8>(vec![CoinbaseOutput {
                one_time_key: key,
                amount: reward + FEE,
            }]),
            [0u8; 32],
        ));
        assert_eq!(crate::BlockFees::<Test>::get(), 0);
        System::assert_last_event(
            Event::CoinbaseMinted {
                first_output_index: RING as u64 + 2,
                output_count: 1,
                reward,
                fees: FEE,
            }
            .into(),
        );
    });
}

#[test]
fn signed_origin_is_rejected() {
    new_test_ext().execute_with(|| {
        let (_, tx) = bed_and_spend(0);
        assert_noop!(
            RingCt::transfer(RuntimeOrigin::signed(1), tx),
            sp_runtime::DispatchError::BadOrigin
        );
    });
}

#[test]
fn invalid_otk_as_ring_member_fails_clsag() {
    new_test_ext().execute_with(|| {
        // Coinbase may currently store a non-decompressible OTK (no point
        // hygiene on create). Using it as a decoy must fail CLSAG verify.
        let reward = block_reward(0);
        let keys: Vec<_> = (0..3).map(|_| crypto::random_secret_key()).collect();
        let share = reward / 4;
        assert_ok!(RingCt::coinbase(
            RuntimeOrigin::none(),
            bounded::<_, 8>(vec![
                CoinbaseOutput { one_time_key: keys[0].1, amount: share },
                CoinbaseOutput { one_time_key: keys[1].1, amount: share },
                CoinbaseOutput { one_time_key: keys[2].1, amount: share },
                CoinbaseOutput {
                    one_time_key: [0xff; 32],
                    amount: reward - 3 * share,
                },
            ]),
            [0u8; 32],
        ));
        run_to_block(100);

        let real = Owned {
            index: 0,
            secret: keys[0].0,
            amount: share,
            blinding: [0u8; 32],
        };
        // Sign against a fully valid ring, then swap a decoy for the garbage OTK
        // index so signing succeeds and chain-side verify hits the bad point.
        run_to_block(101);
        let extra = mint_ring_bed(1);
        run_to_block(200);
        let mut signing_ring = vec![0, 1, 2, extra[0].index];
        signing_ring.sort();
        let mut tx = build_ring_spend(&real, signing_ring, &[real.amount - FEE], FEE);

        // Replace the extra decoy with the garbage-OTK output (index 3).
        let mut poisoned = tx.inputs[0].ring.to_vec();
        poisoned.retain(|&i| i != extra[0].index);
        poisoned.push(3);
        poisoned.sort();
        tx.inputs[0].ring = bounded::<_, 16>(poisoned);
        assert_noop!(RingCt::transfer(RuntimeOrigin::none(), tx), Error::<Test>::ClsagInvalid);
    });
}

#[test]
fn tx_pubkey_and_payload_are_bound_by_clsag() {
    new_test_ext().execute_with(|| {
        let (_, mut tx) = bed_and_spend(0);
        tx.tx_pubkey = crypto::random_secret_key().1;
        assert_noop!(RingCt::transfer(RuntimeOrigin::none(), tx), Error::<Test>::ClsagInvalid);
    });
    new_test_ext().execute_with(|| {
        let (_, mut tx) = bed_and_spend(0);
        tx.outputs[0].payload = bounded::<_, 80>(vec![1, 2, 3, 4]);
        assert_noop!(RingCt::transfer(RuntimeOrigin::none(), tx), Error::<Test>::ClsagInvalid);
    });
    new_test_ext().execute_with(|| {
        let (_, mut tx) = bed_and_spend(0);
        tx.outputs[0].view_tag ^= 0xaa;
        assert_noop!(RingCt::transfer(RuntimeOrigin::none(), tx), Error::<Test>::ClsagInvalid);
    });
}
