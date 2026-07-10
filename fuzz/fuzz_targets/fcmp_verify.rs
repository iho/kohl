//! Fuzz FCMP0001 verification: pure garbage and mutated valid proofs must
//! never panic (PR-11 / BLUEPRINT.md §9.1).
#![no_main]

use libfuzzer_sys::fuzz_target;
use ringct_crypto::{
    fcmp::{self, ProveWitness, RingMember},
    native as crypto,
};

fuzz_target!(|data: &[u8]| {
    // Path A: pure garbage — return false, never panic.
    let msg = data.get(..32).unwrap_or(&[0u8; 32]);
    let root = data.get(32..64).unwrap_or(&[0u8; 32]);
    let c = data.get(64..96).unwrap_or(&[0u8; 32]);
    let ki = data.get(96..128).unwrap_or(&[0u8; 32]);
    let proof = data.get(128..).unwrap_or(&[]);
    let _ = fcmp::verify(msg, root, c, ki, proof);

    // Transparent-path tag must never accept (D17).
    if data.len() >= 8 {
        let mut tr = Vec::with_capacity(32);
        tr.extend_from_slice(fcmp::TRANSPARENT_PATH_DEBUG_TAG);
        tr.extend_from_slice(&data[..data.len().min(24)]);
        let _ = fcmp::verify(msg, root, c, ki, &tr);
    }

    // Path B: build a tiny valid FCMP0001 proof, mutate with fuzzer bytes.
    if data.len() < 16 {
        return;
    }
    let n = 1 + (data[0] as usize % 4); // 1..4 admitted leaves
    let real = (data[1] as usize) % n;
    let amount = 1u64 + u64::from(data[2]);

    let mut digests = Vec::with_capacity(n);
    let mut admitted = Vec::with_capacity(n);
    let mut real_secret = [0u8; 32];
    let mut in_blinding = [0u8; 32];
    let empty = fcmp::empty_leaf_hash();

    for i in 0..n {
        if i == real {
            let (sk, pk) = crypto::random_secret_key();
            real_secret = sk;
            in_blinding = crypto::random_blinding();
            let Some(c_pt) = crypto::commit(amount, &in_blinding) else {
                return;
            };
            digests.push(fcmp::leaf_hash(&pk, &c_pt));
            admitted.push(RingMember {
                one_time_key: pk,
                commitment: c_pt,
                tree_index: i as u64,
            });
        } else {
            // EMPTY placeholder slot (still in tree; not in mature ring).
            digests.push(empty);
        }
    }

    // Ensure at least one admitted leaf: rebuild if real path failed to push.
    if admitted.is_empty() {
        return;
    }

    // Re-filter digests: only real indices should be non-empty for this tiny case.
    // For EMPTY slots we left empty; ring is only non-empty leaves.
    let root = fcmp::root_from_leaves(&digests);
    let mut msg32 = [0u8; 32];
    msg32.copy_from_slice(&data[..32.min(data.len())]);
    if data.len() < 32 {
        msg32 = [data[0]; 32];
    }

    let pseudo_b = crypto::random_blinding();
    let witness = ProveWitness {
        digests: digests.clone(),
        admitted: admitted.clone(),
        real_index: 0, // only one non-empty leaf in this construction
        secret_key: real_secret,
        input_blinding: in_blinding,
        pseudo_blinding: pseudo_b,
    };

    let Some(res) = fcmp::prove(&msg32, &witness) else {
        return;
    };
    let _ = fcmp::verify(
        &msg32,
        &root,
        &res.pseudo_commitment,
        &res.key_image,
        &res.proof,
    );

    // Mutate proof.
    let mut bad = res.proof.clone();
    if !bad.is_empty() {
        let i = (data[3] as usize) % bad.len();
        bad[i] ^= data.get(4).copied().unwrap_or(1);
    }
    let _ = fcmp::verify(&msg32, &root, &res.pseudo_commitment, &res.key_image, &bad);

    // Wrong root.
    let mut bad_root = root;
    bad_root[0] ^= 1;
    let _ = fcmp::verify(
        &msg32,
        &bad_root,
        &res.pseudo_commitment,
        &res.key_image,
        &res.proof,
    );
});
