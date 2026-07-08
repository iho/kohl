// ValidateUnsigned is deprecated in stable2606; migration to
// `#[pallet::authorize]` is tracked for Phase 4 (see lib.rs).
#![allow(deprecated)]

use crate::{mock::*, CoinbaseOutput, Error, Event, Input, Output, TransferTx};
use codec::Encode;
use frame_support::{assert_noop, assert_ok, BoundedVec};
use ringct_crypto::native as crypto;
use ringct_primitives::block_reward;
use sp_core::{sr25519, Pair};
use sp_runtime::{
    traits::ValidateUnsigned,
    transaction_validity::{InvalidTransaction, TransactionSource},
};

const FEE: u64 = 10_000;

fn alice() -> sr25519::Pair {
    sr25519::Pair::from_seed(&[1u8; 32])
}

fn bob() -> sr25519::Pair {
    sr25519::Pair::from_seed(&[2u8; 32])
}

fn bounded<T: Clone + core::fmt::Debug, const N: u32>(
    v: Vec<T>,
) -> BoundedVec<T, frame_support::traits::ConstU32<N>> {
    BoundedVec::try_from(v).expect("fits bound")
}

/// Mint the full first block reward to `miner` and return (index, amount).
/// Coinbase outputs have zero blinding, so the caller can treat the input
/// blinding sum as zero when building a spend.
fn mint_coinbase_to(miner: &sr25519::Pair) -> (u64, u64) {
    let reward = block_reward(crate::Emitted::<Test>::get());
    let index = crate::NextOutputIndex::<Test>::get();
    assert_ok!(RingCt::coinbase(
        RuntimeOrigin::none(),
        bounded::<_, 8>(vec![CoinbaseOutput { owner: miner.public().0, amount: reward }])
    ));
    (index, reward)
}

/// Build confidential outputs for `amounts` (owners all `to`), with
/// blindings chosen so the tx balances against zero-blinding inputs.
/// Returns (outputs, range_proof).
fn conf_outputs(to: &sr25519::Pair, amounts: &[u64]) -> (Vec<Output>, Vec<u8>) {
    let mut blindings: Vec<[u8; 32]> =
        (1..amounts.len()).map(|_| crypto::random_blinding()).collect();
    // Input blindings sum to zero (coinbase), so Σ output blindings must too.
    blindings.push(crypto::balancing_blinding(&[], &blindings).unwrap());
    let (proof, commitments) = crypto::prove_range(amounts, &blindings).unwrap();
    let outputs = commitments
        .into_iter()
        .map(|commitment| Output {
            owner: to.public().0,
            commitment,
            payload: Default::default(),
        })
        .collect();
    (outputs, proof)
}

/// Sign and assemble a 1-input confidential transfer spending `index`.
fn build_transfer(
    owner: &sr25519::Pair,
    index: u64,
    outputs: Vec<Output>,
    proof: Vec<u8>,
    fee: u64,
) -> TransferTx {
    let msg = RingCt::signing_hash(&[index], &outputs, fee);
    let sig = owner.sign(&msg);
    TransferTx {
        inputs: bounded::<_, 8>(vec![Input { index, signature: sig.0 }]),
        outputs: bounded::<_, 8>(outputs),
        range_proof: bounded::<_, 1024>(proof),
        fee,
    }
}

/// Coinbase to `owner`, matured, spent into `amounts` (must sum to
/// reward − fee for the happy path).
fn matured_coinbase_spend(owner: &sr25519::Pair, amounts: &[u64], fee: u64) -> (u64, TransferTx) {
    let (index, _reward) = mint_coinbase_to(owner);
    run_to_block(100); // past coinbase maturity (1 + 60)
    let (outputs, proof) = conf_outputs(&bob(), amounts);
    (index, build_transfer(owner, index, outputs, proof, fee))
}

#[test]
fn coinbase_mints_reward_with_public_commitment() {
    new_test_ext().execute_with(|| {
        let (index, reward) = mint_coinbase_to(&alice());
        assert_eq!(index, 0);
        assert_eq!(crate::Emitted::<Test>::get(), reward);
        let stored = crate::Outputs::<Test>::get(0).unwrap();
        assert!(stored.coinbase);
        assert_eq!(stored.amount, Some(reward));
        // The chain-derived commitment is amount·B with zero blinding.
        assert_eq!(stored.commitment, crypto::value_commitment(reward));
        System::assert_last_event(
            Event::CoinbaseMinted { first_output_index: 0, output_count: 1, reward, fees: 0 }
                .into(),
        );
    });
}

#[test]
fn coinbase_rejects_wrong_sum_and_double_mint() {
    new_test_ext().execute_with(|| {
        let reward = block_reward(0);
        let bad = CoinbaseOutput { owner: alice().public().0, amount: reward + 1 };
        assert_noop!(
            RingCt::coinbase(RuntimeOrigin::none(), bounded::<_, 8>(vec![bad])),
            Error::<Test>::CoinbaseAmountInvalid
        );
        mint_coinbase_to(&alice());
        let again = CoinbaseOutput { owner: alice().public().0, amount: reward };
        assert_noop!(
            RingCt::coinbase(RuntimeOrigin::none(), bounded::<_, 8>(vec![again])),
            Error::<Test>::CoinbaseAlreadyIncluded
        );
        // A new block resets the flag.
        run_to_block(2);
        mint_coinbase_to(&alice());
    });
}

#[test]
fn confidential_transfer_happy_path() {
    new_test_ext().execute_with(|| {
        let (index, reward) = mint_coinbase_to(&alice());
        run_to_block(100);

        let amounts = [1_000, reward - 1_000 - FEE];
        let (outputs, proof) = conf_outputs(&bob(), &amounts);
        let tx = build_transfer(&alice(), index, outputs, proof, FEE);
        assert_ok!(RingCt::transfer(RuntimeOrigin::none(), tx));

        assert!(crate::SpentOutputs::<Test>::contains_key(index));
        assert_eq!(crate::NextOutputIndex::<Test>::get(), 3);
        let stored = crate::Outputs::<Test>::get(1).unwrap();
        assert_eq!(stored.amount, None); // amount is hidden
        assert!(!stored.coinbase);
        assert_eq!(crate::BlockFees::<Test>::get(), FEE);
        System::assert_last_event(
            Event::Transferred { spent: vec![index], first_output_index: 1, output_count: 2, fee: FEE }
                .into(),
        );

        // Next coinbase claims reward + the accumulated (public) fee.
        run_to_block(101);
        let next_reward = block_reward(crate::Emitted::<Test>::get());
        assert_ok!(RingCt::coinbase(
            RuntimeOrigin::none(),
            bounded::<_, 8>(vec![CoinbaseOutput {
                owner: alice().public().0,
                amount: next_reward + FEE,
            }])
        ));
        assert_eq!(crate::BlockFees::<Test>::get(), 0);
    });
}

#[test]
fn hidden_outputs_can_be_respent() {
    new_test_ext().execute_with(|| {
        // Coinbase → confidential outputs → spend a confidential output on.
        let (index, reward) = mint_coinbase_to(&alice());
        run_to_block(100);

        // Alice keeps the whole remainder in one output she controls,
        // with a blinding she knows.
        let amount1 = reward - FEE;
        let blinding1 = crypto::random_blinding();
        let b_last = crypto::balancing_blinding(&[], &[blinding1]).unwrap();
        // Single output needs Σ blindings == 0, so use two outputs.
        let amounts = [amount1 - 500, 500];
        let (proof, commitments) =
            crypto::prove_range(&amounts, &[blinding1, b_last]).unwrap();
        let outputs: Vec<Output> = commitments
            .iter()
            .map(|c| Output { owner: alice().public().0, commitment: *c, payload: Default::default() })
            .collect();
        let tx = build_transfer(&alice(), index, outputs, proof, FEE);
        assert_ok!(RingCt::transfer(RuntimeOrigin::none(), tx));

        // Spend the first hidden output (global index 1, amount1 - 500,
        // blinding blinding1) after it matures.
        run_to_block(200);
        let spend_amounts = [amounts[0] - FEE];
        let out_blinding = [blinding1]; // Σ in-blindings == Σ out-blindings
        let (proof2, commitments2) =
            crypto::prove_range(&spend_amounts, &out_blinding).unwrap();
        let outputs2 = vec![Output {
            owner: bob().public().0,
            commitment: commitments2[0],
            payload: Default::default(),
        }];
        let tx2 = build_transfer(&alice(), 1, outputs2, proof2, FEE);
        assert_ok!(RingCt::transfer(RuntimeOrigin::none(), tx2));
        assert!(crate::SpentOutputs::<Test>::contains_key(1));
    });
}

#[test]
fn unbalanced_amounts_fail_balance_check() {
    new_test_ext().execute_with(|| {
        let (index, reward) = mint_coinbase_to(&alice());
        run_to_block(100);
        // Tries to mint 1 extra atomic unit; blindings balance, amounts don't.
        let amounts = [1_000, reward - 1_000 - FEE + 1];
        let (outputs, proof) = conf_outputs(&bob(), &amounts);
        let tx = build_transfer(&alice(), index, outputs, proof, FEE);
        assert_noop!(
            RingCt::transfer(RuntimeOrigin::none(), tx),
            Error::<Test>::BalanceCheckFailed
        );
    });
}

#[test]
fn unbalanced_blindings_fail_balance_check() {
    new_test_ext().execute_with(|| {
        let (index, reward) = mint_coinbase_to(&alice());
        run_to_block(100);
        // Correct amounts but random (non-balancing) blindings.
        let amounts = [reward - FEE];
        let blindings = [crypto::random_blinding()];
        let (proof, commitments) = crypto::prove_range(&amounts, &blindings).unwrap();
        let outputs = vec![Output {
            owner: bob().public().0,
            commitment: commitments[0],
            payload: Default::default(),
        }];
        let tx = build_transfer(&alice(), index, outputs, proof, FEE);
        assert_noop!(
            RingCt::transfer(RuntimeOrigin::none(), tx),
            Error::<Test>::BalanceCheckFailed
        );
    });
}

#[test]
fn mutated_range_proof_fails() {
    new_test_ext().execute_with(|| {
        let amounts_total = block_reward(0) - FEE;
        let (_, mut tx) = matured_coinbase_spend(&alice(), &[1_000, amounts_total - 1_000], FEE);
        // The proof is not covered by the signature (bound to commitments by
        // its transcript instead) — mutating it must fail proof verification.
        let mut proof = tx.range_proof.to_vec();
        proof[7] ^= 1;
        tx.range_proof = bounded::<_, 1024>(proof);
        assert_noop!(
            RingCt::transfer(RuntimeOrigin::none(), tx),
            Error::<Test>::RangeProofInvalid
        );
    });
}

#[test]
fn proof_for_other_commitments_fails() {
    new_test_ext().execute_with(|| {
        let total = block_reward(0) - FEE;
        let (index, _) = mint_coinbase_to(&alice());
        run_to_block(100);
        let (outputs, _own_proof) = conf_outputs(&bob(), &[1_000, total - 1_000]);
        // A valid proof — but over different commitments.
        let (other_proof, _) = crypto::prove_range(&[5], &[crypto::random_blinding()]).unwrap();
        let tx = build_transfer(&alice(), index, outputs, other_proof, FEE);
        assert_noop!(
            RingCt::transfer(RuntimeOrigin::none(), tx),
            Error::<Test>::RangeProofInvalid
        );
    });
}

#[test]
fn double_spend_fails() {
    new_test_ext().execute_with(|| {
        let total = block_reward(0) - FEE;
        let (_, tx) = matured_coinbase_spend(&alice(), &[1_000, total - 1_000], FEE);
        assert_ok!(RingCt::transfer(RuntimeOrigin::none(), tx.clone()));
        assert_noop!(
            RingCt::transfer(RuntimeOrigin::none(), tx),
            Error::<Test>::OutputAlreadySpent
        );
    });
}

#[test]
fn wrong_key_cannot_spend() {
    new_test_ext().execute_with(|| {
        let (index, reward) = mint_coinbase_to(&alice());
        run_to_block(100);
        let (outputs, proof) = conf_outputs(&bob(), &[reward - FEE]);
        // Bob signs for Alice's output.
        let tx = build_transfer(&bob(), index, outputs, proof, FEE);
        assert_noop!(RingCt::transfer(RuntimeOrigin::none(), tx), Error::<Test>::BadSignature);
    });
}

#[test]
fn signature_binds_commitments() {
    new_test_ext().execute_with(|| {
        let total = block_reward(0) - FEE;
        let (_, mut tx) = matured_coinbase_spend(&alice(), &[1_000, total - 1_000], FEE);
        // Tamper with a commitment after signing.
        tx.outputs[0].commitment[0] ^= 1;
        assert_noop!(RingCt::transfer(RuntimeOrigin::none(), tx), Error::<Test>::BadSignature);
    });
}

#[test]
fn immature_outputs_cannot_be_spent() {
    new_test_ext().execute_with(|| {
        let (index, reward) = mint_coinbase_to(&alice());
        run_to_block(30); // > SpendableAge but < CoinbaseMaturity (60)
        let (outputs, proof) = conf_outputs(&bob(), &[reward - FEE]);
        let tx = build_transfer(&alice(), index, outputs, proof, FEE);
        assert_noop!(RingCt::transfer(RuntimeOrigin::none(), tx), Error::<Test>::OutputImmature);
    });
}

#[test]
fn fee_floor_is_enforced() {
    new_test_ext().execute_with(|| {
        let (index, reward) = mint_coinbase_to(&alice());
        run_to_block(100);
        // MinFeePerByte = 1, the tx encodes to several hundred bytes → fee 100 is too low.
        let (outputs, proof) = conf_outputs(&bob(), &[reward - 100]);
        let tx = build_transfer(&alice(), index, outputs, proof, 100);
        assert!(100 < tx.encoded_size());
        assert_noop!(RingCt::transfer(RuntimeOrigin::none(), tx), Error::<Test>::FeeTooLow);
    });
}

#[test]
fn validate_unsigned_provides_spend_tags_and_rejects_coinbase() {
    new_test_ext().execute_with(|| {
        let total = block_reward(0) - FEE;
        let (index, tx) = matured_coinbase_spend(&alice(), &[1_000, total - 1_000], FEE);

        let validity = <RingCt as ValidateUnsigned>::validate_unsigned(
            TransactionSource::External,
            &crate::Call::transfer { tx: tx.clone() },
        )
        .expect("valid");
        assert_eq!(validity.provides, vec![(b"kohl/out", index).encode()]);
        assert!(validity.propagate);

        // Spent output → stale in the pool.
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
                        owner: alice().public().0,
                        amount: 1,
                    }])
                },
            ),
            Err(InvalidTransaction::Call.into())
        );
    });
}

#[test]
fn unsorted_or_duplicate_inputs_fail() {
    new_test_ext().execute_with(|| {
        let (index, reward) = mint_coinbase_to(&alice());
        run_to_block(100);
        let (outputs, proof) = conf_outputs(&bob(), &[2 * reward - FEE]);
        let msg = RingCt::signing_hash(&[index, index], &outputs, FEE);
        let sig = alice().sign(&msg);
        let dup = Input { index, signature: sig.0 };
        let tx = TransferTx {
            inputs: bounded::<_, 8>(vec![dup.clone(), dup]),
            outputs: bounded::<_, 8>(outputs),
            range_proof: bounded::<_, 1024>(proof),
            fee: FEE,
        };
        assert_noop!(
            RingCt::transfer(RuntimeOrigin::none(), tx),
            Error::<Test>::InputsNotSortedUnique
        );
    });
}
