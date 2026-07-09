use super::*;
use ringct_crypto::{clsag, native as crypto, stealth};
use std::collections::BTreeMap;

/// Mint a coinbase-style output of `amount` to `address` at global index
/// `gi`, as the node's coinbase provider would (stealth one-time key, public
/// amount, zero-blinding commitment). Returns the stored output.
fn mint_to(address: &stealth::StealthAddress, gi: u64, amount: u64) -> StoredOut {
    let (tx_secret, tx_pubkey) = stealth::tx_keypair();
    let shared = stealth::sender_shared_secret(&tx_secret, &address.view_public).unwrap();
    let (one_time_key, _tag) =
        stealth::derive_one_time_key(&shared, &address.spend_public, 0).unwrap();
    StoredOutput {
        one_time_key,
        commitment: crypto::value_commitment(amount),
        tx_pubkey,
        view_tag: 0,
        payload: Default::default(),
        amount: Some(amount),
        height: gi as u32,
        coinbase: true,
    }
}

/// A random decoy output (keys we don't control).
fn random_decoy(gi: u64) -> StoredOut {
    let (_s, one_time_key) = crypto::random_secret_key();
    StoredOutput {
        one_time_key,
        commitment: crypto::value_commitment(gi * 7 + 3),
        tx_pubkey: crypto::random_secret_key().1,
        view_tag: 0,
        payload: Default::default(),
        amount: Some(gi * 7 + 3),
        height: gi as u32,
        coinbase: true,
    }
}

/// Reproduce the runtime's full verification of a transfer, so a passing
/// test means the chain would accept the transaction.
fn chain_accepts(tx: &TransferTx, set: &BTreeMap<u64, StoredOut>) -> bool {
    let msg = pallet_ringct::signing_hash(tx);
    let mut pseudo_concat = Vec::new();
    for input in &tx.inputs {
        let mut ring_blob = Vec::new();
        for gi in input.ring.iter() {
            let m = &set[gi];
            ring_blob.extend_from_slice(&m.one_time_key);
            ring_blob.extend_from_slice(&m.commitment);
        }
        if !clsag::verify(
            &msg,
            &ring_blob,
            &input.pseudo_commitment,
            &input.key_image,
            &input.clsag,
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
        (1, random_decoy(1)),
        (2, mint_to(&stranger.address, 2, 50_000)),
        (3, mint_to(&wallet.address, 3, 25_000)),
    ];

    let owned = wallet.scan(&outputs);
    let indices: Vec<u64> = owned.iter().map(|o| o.global_index).collect();
    assert_eq!(indices, vec![0, 3]);
    assert_eq!(owned[0].amount, 100_000);
    assert_eq!(owned[1].amount, 25_000);
    // Stranger sees only their own.
    assert_eq!(stranger.scan(&outputs).len(), 1);
}

#[test]
fn built_transfer_is_chain_valid() {
    let alice = Wallet::from_seed(&[1u8; 32]);
    let bob = Wallet::from_seed(&[9u8; 32]);

    // Alice owns index 5 (200k); everything else is a decoy.
    let mut set = BTreeMap::new();
    for gi in 0..8u64 {
        let out = if gi == 5 { mint_to(&alice.address, gi, 200_000) } else { random_decoy(gi) };
        set.insert(gi, out);
    }
    let outputs: Vec<(u64, StoredOut)> = set.iter().map(|(k, v)| (*k, v.clone())).collect();

    let owned = alice.scan(&outputs);
    assert_eq!(owned.len(), 1);
    let input = &owned[0];

    // Ring of 4: 3 decoys + the real input.
    let decoys: Vec<RingMember> = [1u64, 3, 6]
        .iter()
        .map(|gi| RingMember {
            global_index: *gi,
            one_time_key: set[gi].one_time_key,
            commitment: set[gi].commitment,
        })
        .collect();

    let fee = 1_000;
    let send = 120_000;
    let tx = alice.build_transfer(input, &decoys, &bob.address, send, fee).unwrap();

    // Shape.
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.inputs[0].ring.len(), 4);
    assert_eq!(tx.outputs.len(), 2);
    assert_eq!(tx.inputs[0].key_image, input.key_image);

    // The chain would accept it.
    assert!(chain_accepts(&tx, &set), "runtime verification failed");

    // Bob can find his payment; the change is scannable by Alice.
    let created: Vec<(u64, StoredOut)> = tx
        .outputs
        .iter()
        .enumerate()
        .map(|(i, o)| {
            (
                100 + i as u64,
                StoredOutput {
                    one_time_key: o.one_time_key,
                    commitment: o.commitment,
                    tx_pubkey: tx.tx_pubkey,
                    view_tag: o.view_tag,
                    payload: o.payload.clone(),
                    amount: None,
                    height: 1,
                    coinbase: false,
                },
            )
        })
        .collect();
    let bob_found = bob.scan(&created);
    assert_eq!(bob_found.len(), 1);
    assert_eq!(bob_found[0].amount, send);
    let alice_change = alice.scan(&created);
    assert_eq!(alice_change.len(), 1);
    assert_eq!(alice_change[0].amount, 200_000 - send - fee);
}

#[test]
fn tampering_a_built_transfer_is_rejected() {
    let alice = Wallet::from_seed(&[1u8; 32]);
    let bob = Wallet::from_seed(&[9u8; 32]);
    let mut set = BTreeMap::new();
    for gi in 0..4u64 {
        let out = if gi == 0 { mint_to(&alice.address, gi, 100_000) } else { random_decoy(gi) };
        set.insert(gi, out);
    }
    let outputs: Vec<(u64, StoredOut)> = set.iter().map(|(k, v)| (*k, v.clone())).collect();
    let input = alice.scan(&outputs).remove(0);
    let decoys: Vec<RingMember> = [1u64, 2, 3]
        .iter()
        .map(|gi| RingMember {
            global_index: *gi,
            one_time_key: set[gi].one_time_key,
            commitment: set[gi].commitment,
        })
        .collect();
    let tx = alice.build_transfer(&input, &decoys, &bob.address, 50_000, 1_000).unwrap();
    assert!(chain_accepts(&tx, &set));

    // Redirect an output after signing → CLSAG breaks.
    let mut bad = tx.clone();
    bad.outputs[0].commitment[0] ^= 1;
    assert!(!chain_accepts(&bad, &set));

    // Inflate the fee (claim more than the inputs cover) → balance breaks.
    let mut bad = tx.clone();
    bad.fee += 1;
    assert!(!chain_accepts(&bad, &set));
}

#[test]
fn insufficient_funds_is_reported() {
    let alice = Wallet::from_seed(&[1u8; 32]);
    let bob = Wallet::from_seed(&[9u8; 32]);
    let set: Vec<(u64, StoredOut)> =
        (0..4u64).map(|gi| (gi, mint_to(&alice.address, gi, 10_000))).collect();
    let input = alice.scan(&set).remove(0);
    let decoys: Vec<RingMember> = set[1..4]
        .iter()
        .map(|(gi, o)| RingMember {
            global_index: *gi,
            one_time_key: o.one_time_key,
            commitment: o.commitment,
        })
        .collect();
    let err = alice.build_transfer(&input, &decoys, &bob.address, 10_000, 1_000).unwrap_err();
    assert!(matches!(err, WalletError::NotEnoughFunds { .. }));
}
