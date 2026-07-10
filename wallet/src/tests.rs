use super::*;
use ringct_crypto::{fcmp, native as crypto, stealth};

fn mint_to(address: &stealth::StealthAddress, gi: u64, amount: u64) -> StoredOut {
    let (tx_secret, tx_pubkey) = stealth::tx_keypair();
    let shared = stealth::sender_shared_secret(&tx_secret, &address.view_public).unwrap();
    let (one_time_key, view_tag) =
        stealth::derive_one_time_key(&shared, &address.spend_public, 0).unwrap();
    StoredOutput {
        one_time_key,
        commitment: crypto::value_commitment(amount),
        tx_pubkey,
        view_tag,
        payload: Default::default(),
        amount: Some(amount),
        height: gi as u32,
        coinbase: true,
    }
}

fn snapshot_from_outputs(outputs: &[(u64, StoredOut)]) -> MembershipSnapshot {
    let mut digests = Vec::new();
    let mut admitted = Vec::new();
    let mut max_i = 0u64;
    for (i, _) in outputs {
        max_i = max_i.max(*i);
    }
    let n = max_i + 1;
    for i in 0..n {
        if let Some((_, out)) = outputs.iter().find(|(gi, _)| *gi == i) {
            let d = fcmp::leaf_hash(&out.one_time_key, &out.commitment);
            digests.push(d);
            admitted.push(ringct_crypto::fcmp::RingMember {
                one_time_key: out.one_time_key,
                commitment: out.commitment,
                tree_index: i,
            });
        } else {
            digests.push(fcmp::empty_leaf_hash());
        }
    }
    MembershipSnapshot {
        root: fcmp::root_from_leaves(&digests),
        digests,
        admitted,
    }
}

fn chain_accepts(tx: &TransferTx) -> bool {
    let msg = pallet_ringct::signing_hash(tx);
    let mut pseudo_concat = Vec::new();
    for input in &tx.inputs {
        if !fcmp::verify(
            &msg,
            &tx.membership_root,
            &input.pseudo_commitment,
            &input.key_image,
            &input.fcmp_proof,
        ) {
            return false;
        }
        pseudo_concat.extend_from_slice(&input.pseudo_commitment);
    }
    let out_concat: Vec<u8> = tx.outputs.iter().flat_map(|o| o.commitment).collect();
    crypto::verify_balance(&pseudo_concat, &out_concat, tx.fee)
        && crypto::verify_range_proof(&tx.range_proof, &out_concat)
}

#[test]
fn scan_finds_owned_coinbase_and_ignores_others() {
    let wallet = Wallet::from_seed(&[1u8; 32]);
    let stranger = Wallet::from_seed(&[2u8; 32]);

    let outputs = vec![
        (0u64, mint_to(&wallet.address, 0, 100_000)),
        (1, mint_to(&stranger.address, 1, 50_000)),
        (2, mint_to(&wallet.address, 2, 25_000)),
    ];

    let owned = wallet.scan(&outputs);
    let indices: Vec<u64> = owned.iter().map(|o| o.global_index).collect();
    assert_eq!(indices, vec![0, 2]);
    assert_eq!(owned[0].amount, 100_000);
    assert_eq!(owned[1].amount, 25_000);
    assert_eq!(stranger.scan(&outputs).len(), 1);
}

#[test]
fn built_fcmp_transfer_is_chain_valid() {
    let alice = Wallet::from_seed(&[1u8; 32]);
    let bob = Wallet::from_seed(&[9u8; 32]);

    // Small mature set: Alice owns 0; others fill the set.
    let outputs = vec![
        (0u64, mint_to(&alice.address, 0, 200_000)),
        (1, mint_to(&bob.address, 1, 10_000)),
        (2, mint_to(&bob.address, 2, 10_000)),
        (3, mint_to(&bob.address, 3, 10_000)),
    ];
    let membership = snapshot_from_outputs(&outputs);
    let owned = alice.scan(&outputs);
    assert_eq!(owned.len(), 1);

    let fee = 1_000;
    let tx = alice
        .build_transfer(&owned[0], &membership, &bob.address, 50_000, fee)
        .expect("build");
    assert_eq!(tx.membership_root, membership.root);
    assert!(chain_accepts(&tx));
}

#[test]
fn multi_input_fcmp_transfer() {
    let alice = Wallet::from_seed(&[3u8; 32]);
    let bob = Wallet::from_seed(&[4u8; 32]);
    let outputs = vec![
        (0u64, mint_to(&alice.address, 0, 80_000)),
        (1, mint_to(&alice.address, 1, 80_000)),
        (2, mint_to(&bob.address, 2, 1_000)),
    ];
    let membership = snapshot_from_outputs(&outputs);
    let owned = alice.scan(&outputs);
    assert_eq!(owned.len(), 2);
    let fee = 500;
    let tx = alice
        .build_transfer_multi(&owned, &membership, &bob.address, 100_000, fee)
        .expect("build multi");
    assert_eq!(tx.inputs.len(), 2);
    assert!(tx.inputs[0].key_image < tx.inputs[1].key_image);
    assert!(chain_accepts(&tx));
}
