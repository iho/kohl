//! Fuzz CLSAG verification: mutated valid signatures and pure garbage must
//! never panic (BLUEPRINT.md Phase 5).
#![no_main]

use libfuzzer_sys::fuzz_target;
use ringct_crypto::{clsag, native as crypto};

fuzz_target!(|data: &[u8]| {
    // Path A: pure garbage — decoder / verifier must return false, not panic.
    let _ = clsag::verify(
        data.get(..32).unwrap_or(&[0u8; 32]),
        data.get(32..).unwrap_or(&[]),
        data.get(0..32).unwrap_or(&[0u8; 32]),
        data.get(32..64).unwrap_or(&[0u8; 32]),
        data.get(64..).unwrap_or(&[]),
    );

    // Path B: start from a valid signature, flip bytes from the fuzzer input.
    if data.len() < 8 {
        return;
    }
    let msg = [data[0]; 32];
    let blinding = crypto::random_blinding();
    let amount = u64::from_le_bytes(data[0..8].try_into().unwrap_or([0u8; 8]));
    let n = 2 + (data[0] as usize % 7); // ring size 2..8
    let l = data[1] as usize % n;

    let mut blob = Vec::new();
    let mut real_secret = [0u8; 32];
    for i in 0..n {
        let (secret, public) = crypto::random_secret_key();
        blob.extend_from_slice(&public);
        if i == l {
            real_secret = secret;
            if let Some(c) = crypto::commit(amount, &blinding) {
                blob.extend_from_slice(&c);
            } else {
                return;
            }
        } else {
            let c = crypto::commit(i as u64 + 1, &crypto::random_blinding()).unwrap_or([0u8; 32]);
            blob.extend_from_slice(&c);
        }
    }

    let Some(res) =
        clsag::sign(&msg, &blob, l, &real_secret, &blinding, &crypto::random_blinding())
    else {
        return;
    };
    let _ = clsag::verify(&msg, &blob, &res.pseudo_commitment, &res.key_image, &res.signature);

    // Mutate signature with fuzzer bytes.
    let mut bad = res.signature.clone();
    if !bad.is_empty() {
        let i = (data[2] as usize) % bad.len();
        bad[i] ^= data.get(3).copied().unwrap_or(1);
    }
    let _ = clsag::verify(&msg, &blob, &res.pseudo_commitment, &res.key_image, &bad);
});
