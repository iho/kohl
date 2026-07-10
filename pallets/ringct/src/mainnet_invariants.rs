//! Mainnet encoding / policy invariants (PR-10 / D14).
//!
//! These tests guard the freeze recorded in `docs/fcmp-mainnet-freeze.md`.
//! Failing any of them means the mainnet-candidate surface drifted without a
//! coordinated version bump and freeze doc update.

#![cfg(test)]

use super::*;
use crate::mock::*;
use codec::{Decode, Encode};
use ringct_primitives::{
    MAX_FCMP_ANON_SET, MAX_FCMP_INPUTS, MAX_FCMP_PROOF_BYTES, MAX_OUTPUTS, MAX_RANGE_PROOF_BYTES,
};

#[test]
fn fcmp_mode_is_always_fcmp_only() {
    new_test_ext().execute_with(|| {
        assert_eq!(RingCt::fcmp_mode(), FCMP_MODE_FCMP_ONLY);
        assert_eq!(FCMP_MODE_FCMP_ONLY, 2);
        // Building mode must not be returned on production path.
        assert_ne!(RingCt::fcmp_mode(), FCMP_MODE_BUILDING);
    });
}

#[test]
fn signing_domain_is_v4() {
    assert_eq!(&SIGNING_DOMAIN, b"kohl/transfer/v4");
    assert_eq!(SIGNING_DOMAIN, FCMP_SIGNING_DOMAIN);
    assert_eq!(SIGNING_DOMAIN.len(), 16);
}

#[test]
fn transfer_tx_encoding_shape_frozen() {
    // Field order and types are consensus: root, inputs, outputs, tx_pubkey, range, fee.
    let tx = TransferTx {
        membership_root: [0u8; 32],
        inputs: Default::default(),
        outputs: Default::default(),
        tx_pubkey: [0u8; 32],
        range_proof: Default::default(),
        fee: 0,
    };
    let encoded = tx.encode();
    assert!(!encoded.is_empty());
    let decoded = TransferTx::decode(&mut &encoded[..]).expect("TransferTx decodes");
    assert_eq!(decoded.membership_root, [0u8; 32]);
    assert_eq!(decoded.fee, 0);
    assert!(decoded.inputs.is_empty());
}

#[test]
fn fcmp_input_has_no_ring_indices_field() {
    // Production input is key image + pseudo + proof only (no ring: Vec<u64>).
    let input = FcmpInput {
        key_image: [1u8; 32],
        pseudo_commitment: [2u8; 32],
        fcmp_proof: Default::default(),
    };
    let bytes = input.encode();
    let back = FcmpInput::decode(&mut &bytes[..]).expect("FcmpInput");
    assert_eq!(back.key_image, [1u8; 32]);
    assert_eq!(back.pseudo_commitment, [2u8; 32]);
    assert!(back.fcmp_proof.is_empty());
}

#[test]
fn frozen_caps_match_design_d15() {
    assert_eq!(MAX_FCMP_INPUTS, 4);
    assert_eq!(MAX_FCMP_PROOF_BYTES, 12_288);
    assert_eq!(MAX_FCMP_ANON_SET, 64);
    assert_eq!(MAX_OUTPUTS, 8);
    assert_eq!(MAX_RANGE_PROOF_BYTES, 1024);
}

#[test]
fn transfer_fcmp_weights_are_non_zero() {
    // Mock uses WeightInfo = (); engineered () impl must remain calibrated.
    let w = <() as weights::WeightInfo>::transfer_fcmp(1, 2, 16);
    assert!(
        w.ref_time() > 1_000_000,
        "transfer_fcmp weight too small: {}",
        w.ref_time()
    );
    let a = <() as weights::WeightInfo>::authorize_fcmp(1);
    assert!(a.ref_time() > 0);
}

#[test]
fn worst_case_proof_budget_fits_block() {
    // Engineering formula from design: 4 * 12288 + BP headroom << 300 KiB.
    let body = (MAX_FCMP_INPUTS as u64)
        .saturating_mul(MAX_FCMP_PROOF_BYTES as u64)
        .saturating_add(MAX_RANGE_PROOF_BYTES as u64)
        .saturating_add(4096); // outs + overhead allowance
    assert!(
        body < 300 * 1024,
        "worst-case FCMP body {body} must fit under 300 KiB block cap"
    );
}

/// PR-11: pallet Path A digests must match host `fcmp::leaf_hash` (composition glue).
#[test]
fn membership_leaf_digest_matches_host_fcmp() {
    let p = [0x11u8; 32];
    let c = [0x22u8; 32];
    let pallet = membership::leaf_hash(&p, &c);
    let host = ringct_crypto::fcmp::leaf_hash(&p, &c);
    assert_eq!(pallet, host);
    assert_eq!(
        membership::empty_leaf_hash(),
        ringct_crypto::fcmp::empty_leaf_hash()
    );
}

/// Production transfer extrinsic has only FCMP fields (no CLSAG ring list).
#[test]
fn transfer_call_variant_is_fcmp_only_surface() {
    // SCALE type name stability: FcmpInput fields only.
    let input = FcmpInput {
        key_image: [9u8; 32],
        pseudo_commitment: [8u8; 32],
        fcmp_proof: BoundedVec::try_from(vec![1u8, 2, 3]).unwrap(),
    };
    let enc = input.encode();
    let dec = FcmpInput::decode(&mut &enc[..]).unwrap();
    assert_eq!(dec.fcmp_proof.as_slice(), &[1, 2, 3]);
    // Document intentional absence of a `ring: Vec<u64>` field in production.
    let _ = dec.key_image;
}
