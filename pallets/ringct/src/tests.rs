use crate::{mock::*, CoinbaseOutput, Error, Event, Output, RingInput, TransferTx};
use codec::Encode;
use frame_support::{assert_noop, assert_ok, traits::Authorize, BoundedVec};
use frame_system::RawOrigin;
use ringct_crypto::{clsag, native as crypto, stealth};
use ringct_primitives::block_reward;
use sp_runtime::transaction_validity::{InvalidTransaction, TransactionSource};

/// Origin produced by `frame_system::AuthorizeCall` after a successful authorize.
fn authorized() -> RuntimeOrigin {
    RawOrigin::Authorized.into()
}

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
        let position = spec
            .ring
            .iter()
            .position(|i| *i == spec.real.index)
            .expect("real in ring");
        let pseudo_blinding = crypto::random_blinding();
        let pseudo_commitment = crypto::commit(spec.real.amount, &pseudo_blinding).unwrap();
        let key_image = clsag::key_image(&spec.real.secret).unwrap();
        prepared.push((
            spec,
            position,
            pseudo_blinding,
            pseudo_commitment,
            key_image,
        ));
    }
    // Canonical input order by key image.
    prepared.sort_by_key(|p| p.4);

    let pseudo_blindings: Vec<[u8; 32]> = prepared.iter().map(|p| p.2).collect();
    let mut out_blindings: Vec<[u8; 32]> = (1..out_amounts.len())
        .map(|_| crypto::random_blinding())
        .collect();
    out_blindings.push(crypto::balancing_blinding(&pseudo_blindings, &out_blindings).unwrap());
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
        assert_ok!(RingCt::transfer(authorized(), tx));

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
        assert_ok!(RingCt::transfer(authorized(), tx_a));

        // Same real output, completely different decoys: the key image is
        // identical, so the double spend is caught without knowing which
        // ring member was real.
        let ring_b = vec![real.index, bed2[0].index, bed2[1].index, bed2[2].index];
        let mut ring_b_sorted = ring_b.clone();
        ring_b_sorted.sort();
        let tx_b = build_ring_spend(real, ring_b_sorted, &[real.amount - FEE], FEE);
        assert_noop!(
            RingCt::transfer(authorized(), tx_b),
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
        assert_noop!(
            RingCt::transfer(authorized(), tx),
            Error::<Test>::RingSizeInvalid
        );
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
        let sig = clsag::sign(
            &msg,
            &blob,
            0,
            &real.secret,
            &real.blinding,
            &pseudo_blinding,
        )
        .unwrap();
        tx.inputs[0].clsag = bounded::<_, 576>(sig.signature);
        assert_noop!(
            RingCt::transfer(authorized(), tx),
            Error::<Test>::UnknownOutput
        );
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
        assert_noop!(
            RingCt::transfer(authorized(), tx),
            Error::<Test>::OutputImmature
        );
    });
}

#[test]
fn tampering_any_signed_field_invalidates_the_clsag() {
    new_test_ext().execute_with(|| {
        // Commitment swap.
        let (_, mut tx) = bed_and_spend(0);
        tx.outputs[0].commitment[0] ^= 1;
        assert_noop!(
            RingCt::transfer(authorized(), tx),
            Error::<Test>::ClsagInvalid
        );
    });
    new_test_ext().execute_with(|| {
        // Receiver swap (one-time key).
        let (_, mut tx) = bed_and_spend(0);
        tx.outputs[0].one_time_key = crypto::random_secret_key().1;
        assert_noop!(
            RingCt::transfer(authorized(), tx),
            Error::<Test>::ClsagInvalid
        );
    });
    new_test_ext().execute_with(|| {
        // Fee swap.
        let (_, mut tx) = bed_and_spend(0);
        tx.fee += 1;
        assert_noop!(
            RingCt::transfer(authorized(), tx),
            Error::<Test>::ClsagInvalid
        );
    });
    new_test_ext().execute_with(|| {
        // Garbage signature bytes.
        let (_, mut tx) = bed_and_spend(0);
        let mut sig = tx.inputs[0].clsag.to_vec();
        sig[33] ^= 1;
        tx.inputs[0].clsag = bounded::<_, 576>(sig);
        assert_noop!(
            RingCt::transfer(authorized(), tx),
            Error::<Test>::ClsagInvalid
        );
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
            RingCt::transfer(authorized(), tx),
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
            RingCt::transfer(authorized(), tx),
            Error::<Test>::InputsNotSortedUnique
        );
    });
}

#[test]
fn authorize_transfer_provides_key_image_tags() {
    new_test_ext().execute_with(|| {
        let (_, tx) = bed_and_spend(1);
        let key_image = tx.inputs[0].key_image;

        let call = crate::Call::<Test>::transfer { tx: tx.clone() };
        let (validity, _refund) = call
            .authorize(TransactionSource::External)
            .expect("transfer is authorizeable")
            .expect("valid");
        assert_eq!(validity.provides, vec![(b"kohl/ki", key_image).encode()]);
        assert!(validity.propagate);

        // After inclusion the key image is stale in the pool.
        assert_ok!(RingCt::transfer(authorized(), tx.clone()));
        let call = crate::Call::<Test>::transfer { tx };
        assert_eq!(
            call.authorize(TransactionSource::External)
                .expect("authorizeable")
                .map(|(v, _)| v),
            Err(InvalidTransaction::Stale.into())
        );

        // Coinbase has no authorize path (bare inherent only).
        let call = crate::Call::<Test>::coinbase {
            outputs: bounded::<_, 8>(vec![CoinbaseOutput {
                one_time_key: crypto::random_secret_key().1,
                amount: 1,
                view_tag: 0,
            }]),
            tx_pubkey: crypto::random_secret_key().1,
        };
        assert!(call.authorize(TransactionSource::External).is_none());
    });
}

#[test]
fn coinbase_inherent_computes_reward_from_state() {
    use frame_support::inherent::ProvideInherent;
    use sp_inherents::InherentData;
    new_test_ext().execute_with(|| {
        let mut data = InherentData::new();
        let otk = crypto::random_secret_key().1;
        let r = crypto::random_secret_key().1;
        let dest: crate::CoinbaseInherent = (otk, r, 0);
        data.put_data(crate::INHERENT_IDENTIFIER, &dest).unwrap();

        let call = <RingCt as ProvideInherent>::create_inherent(&data).expect("inherent built");
        match call {
            crate::Call::coinbase { outputs, tx_pubkey } => {
                assert_eq!(tx_pubkey, r);
                assert_eq!(outputs.len(), 1);
                assert_eq!(outputs[0].one_time_key, otk);
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
        let r = crypto::random_secret_key().1;
        assert_noop!(
            RingCt::coinbase(
                RuntimeOrigin::none(),
                bounded::<_, 8>(vec![CoinbaseOutput {
                    one_time_key: key,
                    amount: reward + 1,
                    view_tag: 0
                }]),
                r,
            ),
            Error::<Test>::CoinbaseAmountInvalid
        );
        mint_ring_bed(2);
        assert_noop!(
            RingCt::coinbase(
                RuntimeOrigin::none(),
                bounded::<_, 8>(vec![CoinbaseOutput {
                    one_time_key: key,
                    amount: reward,
                    view_tag: 0
                }]),
                r,
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
        let (otk, tag) = stealth::derive_one_time_key(&shared, &addr.spend_public, 0).unwrap();

        let mut outputs = vec![CoinbaseOutput {
            one_time_key: otk,
            amount: reward / 2,
            view_tag: tag,
        }];
        for _ in 0..3 {
            outputs.push(CoinbaseOutput {
                one_time_key: crypto::random_secret_key().1,
                amount: reward / 6,
                view_tag: 0,
            });
        }
        outputs[3].amount = reward - reward / 2 - 2 * (reward / 6);
        assert_ok!(RingCt::coinbase(
            RuntimeOrigin::none(),
            bounded::<_, 8>(outputs),
            tx_pubkey
        ));

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
                    &stealth::receiver_shared_secret(&keys.view_secret, &stored.tx_pubkey).unwrap(),
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
        let owned = Owned {
            index: 0,
            secret,
            amount: reward / 2,
            blinding: [0u8; 32],
        };
        let tx = build_ring_spend(&owned, vec![0, 1, 2, 3], &[reward / 2 - FEE], FEE);
        assert_ok!(RingCt::transfer(authorized(), tx));
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
                SpendSpec {
                    real: a,
                    ring: ring.clone(),
                },
                SpendSpec {
                    real: b,
                    ring: ring.clone(),
                },
            ],
            &[total / 2 - FEE, total - total / 2],
            FEE,
        );
        assert_eq!(tx.inputs.len(), 2);
        // Canonical form: strictly increasing key images.
        assert!(tx.inputs[0].key_image < tx.inputs[1].key_image);

        let kis: Vec<_> = tx.inputs.iter().map(|i| i.key_image).collect();
        assert_ok!(RingCt::transfer(authorized(), tx));
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
                SpendSpec {
                    real: &bed[0],
                    ring: ring.clone(),
                },
                SpendSpec {
                    real: &bed[1],
                    ring: ring.clone(),
                },
            ],
            &[bed[0].amount + bed[1].amount - FEE],
            FEE,
        );
        // Reverse a valid sorted pair → InputsNotSortedUnique.
        tx.inputs.as_mut().swap(0, 1);
        assert_noop!(
            RingCt::transfer(authorized(), tx),
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
            RingCt::transfer(authorized(), tx),
            Error::<Test>::RingIndicesInvalid
        );

        // Duplicate indices (not strictly increasing).
        let mut tx = build_ring_spend(real, sorted.clone(), &[real.amount - FEE], FEE);
        tx.inputs[0].ring = bounded::<_, 16>(vec![sorted[0], sorted[1], sorted[1], sorted[2]]);
        assert_noop!(
            RingCt::transfer(authorized(), tx),
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
            RingCt::transfer(authorized(), tx),
            Error::<Test>::EmptyInputsOrOutputs
        );

        let (_, mut tx) = bed_and_spend(0);
        tx.outputs = bounded::<_, 8>(vec![]);
        // Empty outputs: shape check fails before crypto (fee still present).
        assert_noop!(
            RingCt::transfer(authorized(), tx),
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
        assert_noop!(RingCt::transfer(authorized(), tx), Error::<Test>::FeeTooLow);
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
            RingCt::transfer(authorized(), tx),
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
        assert_noop!(
            RingCt::transfer(authorized(), tx),
            Error::<Test>::ClsagInvalid
        );
    });
    new_test_ext().execute_with(|| {
        // Non-canonical / non-decompressible point bytes.
        let (_, mut tx) = bed_and_spend(0);
        tx.inputs[0].key_image = [0xff; 32];
        assert_noop!(
            RingCt::transfer(authorized(), tx),
            Error::<Test>::ClsagInvalid
        );
    });
}

#[test]
fn non_canonical_pseudo_commitment_fails() {
    new_test_ext().execute_with(|| {
        let (_, mut tx) = bed_and_spend(0);
        tx.inputs[0].pseudo_commitment = [0xff; 32];
        // Bound into the CLSAG message + ring equation → ClsagInvalid first.
        assert_noop!(
            RingCt::transfer(authorized(), tx),
            Error::<Test>::ClsagInvalid
        );
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
        assert_ok!(RingCt::transfer(authorized(), tx));

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
            RingCt::transfer(authorized(), early),
            Error::<Test>::OutputImmature
        );

        run_to_block(110);
        let ready = build_ring_spend(&owned, re_ring, &[out_amount - FEE], FEE);
        assert_ok!(RingCt::transfer(authorized(), ready));
    });
}

#[test]
fn fees_carry_into_next_coinbase() {
    new_test_ext().execute_with(|| {
        let (_, tx) = bed_and_spend(0);
        assert_ok!(RingCt::transfer(authorized(), tx));
        assert_eq!(crate::BlockFees::<Test>::get(), FEE);

        run_to_block(101);
        let reward = block_reward(crate::Emitted::<Test>::get());
        let key = crypto::random_secret_key().1;
        assert_ok!(RingCt::coinbase(
            RuntimeOrigin::none(),
            bounded::<_, 8>(vec![CoinbaseOutput {
                one_time_key: key,
                amount: reward + FEE,
                view_tag: 0,
            }]),
            crypto::random_secret_key().1,
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
fn invalid_otk_rejected_at_coinbase_and_transfer() {
    new_test_ext().execute_with(|| {
        let reward = block_reward(0);
        let good = crypto::random_secret_key().1;
        let r = crypto::random_secret_key().1;
        // Garbage one-time key cannot be minted.
        assert_noop!(
            RingCt::coinbase(
                RuntimeOrigin::none(),
                bounded::<_, 8>(vec![CoinbaseOutput {
                    one_time_key: [0xff; 32],
                    amount: reward,
                    view_tag: 0,
                }]),
                r,
            ),
            Error::<Test>::InvalidPoint
        );
        // Identity tx_pubkey rejected.
        assert_noop!(
            RingCt::coinbase(
                RuntimeOrigin::none(),
                bounded::<_, 8>(vec![CoinbaseOutput {
                    one_time_key: good,
                    amount: reward,
                    view_tag: 0
                }]),
                [0u8; 32],
            ),
            Error::<Test>::InvalidPoint
        );
    });
    new_test_ext().execute_with(|| {
        // Transfer with a garbage output OTK fails before crypto effects.
        let (_, mut tx) = bed_and_spend(0);
        tx.outputs[0].one_time_key = [0xff; 32];
        // CLSAG message binds OTK, so either ClsagInvalid or InvalidPoint —
        // InvalidPoint is checked first on outputs.
        assert_noop!(
            RingCt::transfer(authorized(), tx),
            Error::<Test>::InvalidPoint
        );
    });
}

#[test]
fn tx_pubkey_and_payload_are_bound_by_clsag() {
    new_test_ext().execute_with(|| {
        let (_, mut tx) = bed_and_spend(0);
        tx.tx_pubkey = crypto::random_secret_key().1;
        assert_noop!(
            RingCt::transfer(authorized(), tx),
            Error::<Test>::ClsagInvalid
        );
    });
    new_test_ext().execute_with(|| {
        let (_, mut tx) = bed_and_spend(0);
        tx.outputs[0].payload = bounded::<_, 80>(vec![1, 2, 3, 4]);
        assert_noop!(
            RingCt::transfer(authorized(), tx),
            Error::<Test>::ClsagInvalid
        );
    });
    new_test_ext().execute_with(|| {
        let (_, mut tx) = bed_and_spend(0);
        tx.outputs[0].view_tag ^= 0xaa;
        assert_noop!(
            RingCt::transfer(authorized(), tx),
            Error::<Test>::ClsagInvalid
        );
    });
}

// ---- PR-1 membership tree scaffolding ------------------------------------

use crate::membership;
use crate::StoredOutput;

#[test]
fn membership_tree_grows_with_coinbase_and_matches_next_index() {
    new_test_ext().execute_with(|| {
        assert_eq!(RingCt::tree_slots(), 0);
        assert_eq!(
            RingCt::membership_root(),
            membership::empty_membership_root()
        );
        let bed = mint_ring_bed(RING);
        assert_eq!(RingCt::tree_slots(), RING as u64);
        assert_eq!(crate::NextOutputIndex::<Test>::get(), RingCt::tree_slots());
        // Immature coinbases are EMPTY slots, not admitted.
        for o in &bed {
            assert!(!RingCt::is_admitted(o.index));
        }
        // Mint height=1 → mature when now >= 61; need on_finalize at 61.
        run_to_block(62);
        for o in &bed {
            assert!(
                RingCt::is_admitted(o.index),
                "coinbase {} should admit at maturity",
                o.index
            );
        }
        assert_ne!(
            RingCt::membership_root(),
            membership::empty_membership_root()
        );
    });
}

#[test]
fn membership_sparse_admit_transfer_not_blocked_by_immature_coinbase() {
    new_test_ext().execute_with(|| {
        // Synthetic slots: coinbase at 0 immature; non-coinbase at 1 mature.
        let now = 100u64;
        System::set_block_number(now);
        let (p0, _) = (crypto::random_secret_key().1, ());
        let (p1, _) = (crypto::random_secret_key().1, ());
        let c0 = crypto::value_commitment(50);
        let c1 = crypto::commit(40, &crypto::random_blinding()).unwrap();

        crate::Outputs::<Test>::insert(
            0,
            StoredOutput {
                one_time_key: p0,
                commitment: c0,
                tx_pubkey: crypto::random_secret_key().1,
                view_tag: 0,
                payload: Default::default(),
                amount: Some(50),
                height: now, // coinbase needs +60
                coinbase: true,
            },
        );
        crate::Outputs::<Test>::insert(
            1,
            StoredOutput {
                one_time_key: p1,
                commitment: c1,
                tx_pubkey: crypto::random_secret_key().1,
                view_tag: 0,
                payload: Default::default(),
                amount: None,
                height: now - 10, // exactly SpendableAge
                coinbase: false,
            },
        );
        crate::NextOutputIndex::<Test>::put(2);
        crate::MembershipLeafDigest::<Test>::insert(0, membership::empty_leaf_hash());
        crate::MembershipLeafDigest::<Test>::insert(1, membership::empty_leaf_hash());
        crate::TreeSlots::<Test>::put(2);

        let (adm, grown) = RingCt::maintain_membership_tree();
        assert_eq!(grown, 0);
        assert_eq!(adm, 1);
        assert!(!RingCt::is_admitted(0), "immature coinbase must stay EMPTY");
        assert!(RingCt::is_admitted(1), "mature transfer leaf admits");
    });
}

#[test]
fn membership_coinbase_not_admitted_before_maturity() {
    new_test_ext().execute_with(|| {
        let bed = mint_ring_bed(1);
        // Finalize through block 60: now=60 < height 1 + 60 → still immature.
        run_to_block(61);
        assert!(
            !RingCt::is_admitted(bed[0].index),
            "coinbase must not admit before CoinbaseMaturity"
        );
        // Finalize block 61: now=61 >= 61 → admit.
        run_to_block(62);
        assert!(RingCt::is_admitted(bed[0].index));
    });
}

#[test]
fn membership_lag_tip_mint_no_panic_and_catchup() {
    new_test_ext().execute_with(|| {
        let _ = mint_ring_bed(RING);
        assert_eq!(RingCt::tree_slots(), RING as u64);
        run_to_block(System::block_number() + 1); // clear CoinbaseDone

        // Simulate Building HF: tree wiped while outputs remain.
        crate::TreeSlots::<Test>::put(0);
        for i in 0..RING as u64 {
            crate::MembershipLeafDigest::<Test>::remove(i);
            crate::Admitted::<Test>::remove(i);
        }

        // Tip mint while lagging: TreeSlots=0, index=RING — grow no-ops.
        let reward = block_reward(crate::Emitted::<Test>::get());
        let tip = crate::NextOutputIndex::<Test>::get();
        assert_ok!(RingCt::coinbase(
            RuntimeOrigin::none(),
            bounded::<_, 8>(vec![CoinbaseOutput {
                one_time_key: crypto::random_secret_key().1,
                amount: reward,
                view_tag: 0,
            }]),
            crypto::random_secret_key().1,
        ));
        assert_eq!(
            crate::NextOutputIndex::<Test>::get(),
            tip + 1,
            "output still minted"
        );
        assert_eq!(
            RingCt::tree_slots(),
            0,
            "lagging tip mint must not grow out of order"
        );

        // Catch-up grow on finalize path.
        let (_adm, grown) = RingCt::maintain_membership_tree();
        assert!(grown > 0);
        assert!(RingCt::tree_slots() > 0);
        assert!(RingCt::tree_slots() <= crate::NextOutputIndex::<Test>::get());
    });
}

#[test]
fn membership_fill_budget_does_not_block_steady_state_grow() {
    new_test_ext().execute_with(|| {
        // 80 mature EMPTY slots + fill budget 64; second maintain finishes rest.
        let n = 80u64;
        let now = 50u64;
        System::set_block_number(now);
        for i in 0..n {
            let pk = crypto::random_secret_key().1;
            let c = crypto::commit(i + 1, &crypto::random_blinding()).unwrap();
            crate::Outputs::<Test>::insert(
                i,
                StoredOutput {
                    one_time_key: pk,
                    commitment: c,
                    tx_pubkey: [1u8; 32],
                    view_tag: 0,
                    payload: Default::default(),
                    amount: None,
                    height: now - 10,
                    coinbase: false,
                },
            );
            crate::MembershipLeafDigest::<Test>::insert(i, membership::empty_leaf_hash());
        }
        crate::NextOutputIndex::<Test>::put(n);
        crate::TreeSlots::<Test>::put(n);

        let (a1, g1) = RingCt::maintain_membership_tree();
        assert_eq!(g1, 0);
        assert_eq!(a1, 64);
        let admitted: u64 = (0..n).filter(|i| RingCt::is_admitted(*i)).count() as u64;
        assert_eq!(admitted, 64);

        // Steady-state mint of 3 more outputs still grows tree (not starved).
        for j in 0..3u64 {
            let idx = n + j;
            crate::Outputs::<Test>::insert(
                idx,
                StoredOutput {
                    one_time_key: crypto::random_secret_key().1,
                    commitment: crypto::commit(1, &crypto::random_blinding()).unwrap(),
                    tx_pubkey: [1u8; 32],
                    view_tag: 0,
                    payload: Default::default(),
                    amount: None,
                    height: now,
                    coinbase: false,
                },
            );
            RingCt::maybe_grow_empty_on_create(idx);
        }
        crate::NextOutputIndex::<Test>::put(n + 3);
        assert_eq!(RingCt::tree_slots(), n + 3);

        let (a2, _) = RingCt::maintain_membership_tree();
        assert_eq!(a2, 16); // remaining fills from the original 80
        assert_eq!((0..n).filter(|i| RingCt::is_admitted(*i)).count(), 80);
    });
}

#[test]
fn membership_transfer_grows_slots_for_new_outputs() {
    new_test_ext().execute_with(|| {
        let (bed, tx) = bed_and_spend(0);
        let slots_before = RingCt::tree_slots();
        assert_ok!(RingCt::transfer(authorized(), tx));
        assert_eq!(RingCt::tree_slots(), slots_before + 2);
        assert_eq!(RingCt::tree_slots(), crate::NextOutputIndex::<Test>::get());
        drop(bed);
    });
}

// ---- PR-2 lag catch-up / AdmitScanCursor --------------------------------

/// Plant `n` outputs with no tree slots (simulate mid-dev tree enable).
fn plant_outputs_without_tree(n: u64, height: u64, coinbase: bool) {
    System::set_block_number(height);
    for i in 0..n {
        let pk = crypto::random_secret_key().1;
        let c = if coinbase {
            crypto::value_commitment(i + 1)
        } else {
            crypto::commit(i + 1, &crypto::random_blinding()).unwrap()
        };
        crate::Outputs::<Test>::insert(
            i,
            StoredOutput {
                one_time_key: pk,
                commitment: c,
                tx_pubkey: [2u8; 32],
                view_tag: 0,
                payload: Default::default(),
                amount: if coinbase { Some(i + 1) } else { None },
                height,
                coinbase,
            },
        );
    }
    crate::NextOutputIndex::<Test>::put(n);
    crate::TreeSlots::<Test>::put(0);
    crate::AdmitScanCursor::<Test>::kill();
}

#[test]
fn membership_multiblock_catchup_reaches_tip() {
    new_test_ext().execute_with(|| {
        let n = 200u64;
        plant_outputs_without_tree(n, 1, false);
        assert!(RingCt::is_membership_lagging());
        assert!(!RingCt::is_membership_slot_caught_up());

        let mut total_grown = 0u32;
        // 200 / 64 = 4 blocks of catch-up (ceil).
        for _ in 0..4 {
            let (_a, g) = RingCt::maintain_membership_tree();
            total_grown += g;
            assert!(g <= ringct_primitives::FCMP_GROW_CATCHUP_MAX_PER_BLOCK);
        }
        assert_eq!(total_grown as u64, n);
        assert_eq!(RingCt::tree_slots(), n);
        assert!(!RingCt::is_membership_lagging());
        assert!(RingCt::is_membership_slot_caught_up());

        let st = RingCt::membership_backfill_status();
        assert_eq!(st.tree_slots, n);
        assert_eq!(st.next_output_index, n);
        assert!(!st.lagging);
    });
}

#[test]
fn membership_fill_before_catchup_grow_same_block() {
    new_test_ext().execute_with(|| {
        // 10 mature EMPTY slots (need fill) + lag of 50 unplanted tree slots.
        let mature_slots = 10u64;
        let tip = 60u64;
        let now = 50u64;
        System::set_block_number(now);

        for i in 0..tip {
            let pk = crypto::random_secret_key().1;
            let c = crypto::commit(i + 1, &crypto::random_blinding()).unwrap();
            crate::Outputs::<Test>::insert(
                i,
                StoredOutput {
                    one_time_key: pk,
                    commitment: c,
                    tx_pubkey: [3u8; 32],
                    view_tag: 0,
                    payload: Default::default(),
                    amount: None,
                    // First 10 mature; rest immature (height = now).
                    height: if i < mature_slots { now - 10 } else { now },
                    coinbase: false,
                },
            );
        }
        crate::NextOutputIndex::<Test>::put(tip);
        // Tree only knows first 10 (EMPTY), lagging for 50.
        for i in 0..mature_slots {
            crate::MembershipLeafDigest::<Test>::insert(i, membership::empty_leaf_hash());
        }
        crate::TreeSlots::<Test>::put(mature_slots);
        crate::AdmitScanCursor::<Test>::put(0);

        let (adm, grown) = RingCt::maintain_membership_tree();
        // Fill first: all 10 mature slots admitted.
        assert_eq!(adm, 10);
        // Then catch-up grow up to budget (64) but only 50 lagging.
        assert_eq!(grown, 50);
        assert_eq!(RingCt::tree_slots(), tip);
        assert!(!RingCt::is_membership_lagging());
        for i in 0..mature_slots {
            assert!(RingCt::is_admitted(i));
        }
        // Newly grown slots still EMPTY (immature) — fill next time they mature.
        for i in mature_slots..tip {
            assert!(!RingCt::is_admitted(i));
        }
    });
}

#[test]
fn membership_admit_cursor_wraps_and_admits_sparse() {
    new_test_ext().execute_with(|| {
        let now = 100u64;
        System::set_block_number(now);
        // slot 0 immature coinbase; slots 1..5 mature transfers; cursor starts at 0
        for i in 0..6u64 {
            let coinbase = i == 0;
            crate::Outputs::<Test>::insert(
                i,
                StoredOutput {
                    one_time_key: crypto::random_secret_key().1,
                    commitment: if coinbase {
                        crypto::value_commitment(1)
                    } else {
                        crypto::commit(i, &crypto::random_blinding()).unwrap()
                    },
                    tx_pubkey: [4u8; 32],
                    view_tag: 0,
                    payload: Default::default(),
                    amount: if coinbase { Some(1) } else { None },
                    height: if coinbase { now } else { now - 10 },
                    coinbase,
                },
            );
            crate::MembershipLeafDigest::<Test>::insert(i, membership::empty_leaf_hash());
        }
        crate::NextOutputIndex::<Test>::put(6);
        crate::TreeSlots::<Test>::put(6);
        crate::AdmitScanCursor::<Test>::put(0);

        let (adm, g) = RingCt::maintain_membership_tree();
        assert_eq!(g, 0);
        assert_eq!(adm, 5);
        assert!(!RingCt::is_admitted(0));
        for i in 1..6 {
            assert!(RingCt::is_admitted(i));
        }
        // Cursor advanced through a full pass.
        assert!(RingCt::admit_scan_cursor() < 6);
    });
}

#[test]
fn membership_event_reports_lag_fields() {
    new_test_ext().execute_with(|| {
        plant_outputs_without_tree(100, 1, false);
        // One finalize via run_to_block step.
        run_to_block(2);
        let st = RingCt::membership_backfill_status();
        // After one catch-up block: 64 grown, still lagging.
        assert_eq!(st.tree_slots, 64);
        assert!(st.lagging);
        System::assert_has_event(
            Event::MembershipTreeUpdated {
                tree_slots: 64,
                next_output_index: 100,
                root: RingCt::membership_root(),
                admitted_this_block: 0, // immature at height 1
                catchup_grown: 64,
                lagging: true,
                admit_scan_cursor: RingCt::admit_scan_cursor(),
            }
            .into(),
        );
    });
}

#[test]
fn membership_steady_state_not_lagging_after_mint() {
    new_test_ext().execute_with(|| {
        let _ = mint_ring_bed(RING);
        assert!(!RingCt::is_membership_lagging());
        let st = RingCt::membership_backfill_status();
        assert_eq!(st.tree_slots, st.next_output_index);
        assert!(!st.lagging);
    });
}

// ---- PR-6 weight budgets ------------------------------------------------

#[test]
fn fcmp_weights_scale_and_dominate_clsag_at_full_set() {
    use crate::weights::WeightInfo;
    use frame_support::weights::Weight;

    let clsag_1 = <() as WeightInfo>::transfer(1, 2, 16);
    let fcmp_small = <() as WeightInfo>::transfer_fcmp(1, 2, 16);
    let fcmp_full = <() as WeightInfo>::transfer_fcmp(1, 2, 64);
    let fcmp_4in = <() as WeightInfo>::transfer_fcmp(4, 2, 64);

    // Full-set interim is at least as heavy as CLSAG-16 (25 ms budget @ 64).
    assert!(fcmp_full.ref_time() >= clsag_1.ref_time());
    assert!(fcmp_full.ref_time() >= fcmp_small.ref_time());
    assert!(fcmp_4in.ref_time() >= fcmp_full.ref_time());

    // Maintain worst-case is bounded and non-zero.
    let m = <() as WeightInfo>::maintain_membership(64, 64, 64);
    assert!(m.ref_time() > 0);
    assert!(m != Weight::zero());

    // Authorize FCMP includes root-window reads.
    let a = <() as WeightInfo>::authorize_fcmp(2);
    assert!(a.ref_time() > 0);
}

#[test]
fn engineered_weights_cover_machine_benchmarks() {
    use crate::weights::WeightInfo;
    // From weights_machine.rs (2026-07-09).
    assert!(<() as WeightInfo>::transfer(1, 1, 16).ref_time() >= 6_185_000_000);
    assert!(<() as WeightInfo>::coinbase(1).ref_time() >= 92_000_000);
    assert!(<() as WeightInfo>::authorize_transfer(1).ref_time() >= 8_000_000);
}

// ---- PR-3 runtime-facing pallet helpers --------------------------------

#[test]
fn membership_api_helpers_match_storage() {
    use codec::Decode;
    new_test_ext().execute_with(|| {
        let bed = mint_ring_bed(RING);
        run_to_block(62);

        assert_eq!(RingCt::fcmp_mode(), crate::FCMP_MODE_BUILDING);
        assert_eq!(RingCt::tree_slots(), RING as u64);
        assert_eq!(
            RingCt::membership_root(),
            RingCt::membership_backfill_status().membership_root
        );

        for o in &bed {
            assert!(RingCt::is_admitted(o.index));
            let d = RingCt::membership_leaf_digest(o.index).expect("digest");
            let stored = crate::Outputs::<Test>::get(o.index).unwrap();
            assert_eq!(
                d,
                membership::leaf_hash(&stored.one_time_key, &stored.commitment)
            );
        }

        // Frontier is SCALE Vec of digests for 0..TreeSlots.
        let raw = RingCt::membership_frontier();
        let digests: Vec<[u8; 32]> = Decode::decode(&mut &raw[..]).expect("frontier SCALE");
        assert_eq!(digests.len(), RING);
        assert_eq!(
            membership::root_from_leaves(&digests),
            RingCt::membership_root()
        );

        // Root retained at a finalized block.
        let at = System::block_number() - 1;
        assert_eq!(
            RingCt::membership_root_at(at),
            Some(RingCt::membership_root())
        );
    });
}
