//! CLSAG linkable ring signatures over Ristretto.
//!
//! Implements the scheme from Goodell–Noether–RandomRun, "Concise Linkable
//! Ring Signatures and Forgery Against Adversarial Keys" (eprint 2019/654) —
//! Monero's production signature since 2020 — adapted to the prime-order
//! Ristretto group (no cofactor, so none of ed25519's small-subgroup checks
//! are needed; every decoded point is canonical by construction).
//!
//! A signature over a ring of pairs `(P_i, C_i)` proves the signer knows,
//! for one undisclosed index `l`:
//!   * the key: `x` with `P_l = x·G`, publishing the key image `I = x·Hp(P_l)`
//!     (deterministic per key → double-spends link, spends don't trace);
//!   * the amount: `z` with `C_l − C' = z·G`, where `C'` is the input's
//!     pseudo-output commitment (same amount as `C_l`, fresh blinding `z`
//!     absorbs the difference — note blinding lives on the basepoint `G`,
//!     value on `H`, exactly Monero's convention; see `native::pc_gens`).
//!
//! ## Byte formats (consensus-critical)
//!
//! * ring blob: `n × 64` bytes of `P_i ‖ C_i` (compressed Ristretto);
//! * signature: `c0 (32) ‖ s_0 … s_{n−1} (32 each) ‖ D (32)`.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use sha2::{Digest, Sha512};

/// Maximum ring size for production CLSAG transfers (`RingSize` ≤ 16).
pub const MAX_RING: usize = ringct_primitives::MAX_RING_SIZE as usize;

/// Maximum ring size for FCMP interim full-mature-set CLSAG (PR-5).
pub const MAX_FCMP_RING: usize = ringct_primitives::MAX_FCMP_ANON_SET as usize;

const DOM_AGG_KEY: &[u8] = b"kohl/clsag/agg-key/v1";
const DOM_AGG_COM: &[u8] = b"kohl/clsag/agg-com/v1";
const DOM_ROUND: &[u8] = b"kohl/clsag/round/v1";
const DOM_HP: &[u8] = b"kohl/clsag/hp/v1";

/// Domain-separated hash-to-scalar over concatenated parts.
pub(crate) fn hs(domain: &[u8], parts: &[&[u8]]) -> Scalar {
    let mut h = Sha512::new();
    h.update(domain);
    for p in parts {
        h.update(p);
    }
    Scalar::from_hash(h)
}

/// Hash-to-point for key images (Ristretto Elligator — no ad-hoc tricks).
pub(crate) fn hp(point_bytes: &[u8]) -> RistrettoPoint {
    let mut h = Sha512::new();
    h.update(DOM_HP);
    h.update(point_bytes);
    RistrettoPoint::from_hash(h)
}

fn scalar(bytes: &[u8]) -> Option<Scalar> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes.try_into().ok()?))
}

fn decompress(bytes: &[u8]) -> Option<RistrettoPoint> {
    CompressedRistretto::from_slice(bytes).ok()?.decompress()
}

/// Parse a ring blob into (one-time keys, commitments).
fn parse_ring(blob: &[u8], max_n: usize) -> Option<(Vec<RistrettoPoint>, Vec<RistrettoPoint>)> {
    if blob.is_empty() || !blob.len().is_multiple_of(64) {
        return None;
    }
    let n = blob.len() / 64;
    if n == 0 || n > max_n {
        return None;
    }
    let mut keys = Vec::with_capacity(n);
    let mut commitments = Vec::with_capacity(n);
    for pair in blob.chunks_exact(64) {
        keys.push(decompress(&pair[..32])?);
        commitments.push(decompress(&pair[32..])?);
    }
    Some((keys, commitments))
}

/// μ_P and μ_C: aggregation coefficients binding ring, key images and C'.
fn aggregation_coefficients(
    ring_blob: &[u8],
    key_image: &[u8],
    aux_image: &[u8],
    pseudo: &[u8],
) -> (Scalar, Scalar) {
    (
        hs(DOM_AGG_KEY, &[ring_blob, key_image, aux_image, pseudo]),
        hs(DOM_AGG_COM, &[ring_blob, key_image, aux_image, pseudo]),
    )
}

/// The round challenge c_{i+1} = Hs(ring ‖ C' ‖ msg ‖ L_i ‖ R_i).
fn round_challenge(ring_blob: &[u8], pseudo: &[u8], msg: &[u8], l: &[u8], r: &[u8]) -> Scalar {
    hs(DOM_ROUND, &[ring_blob, pseudo, msg, l, r])
}

/// The key image `I = x·Hp(x·G)` for a one-time secret key.
pub fn key_image(secret_key: &[u8; 32]) -> Option<[u8; 32]> {
    let x = scalar(secret_key)?;
    let p = (G * x).compress();
    Some((hp(p.as_bytes()) * x).compress().to_bytes())
}

pub struct ClsagResult {
    /// `c0 ‖ s_0..s_{n−1} ‖ D`
    pub signature: Vec<u8>,
    pub key_image: [u8; 32],
    /// `C' = C_l − z·G` — commits to the real amount under a fresh blinding.
    pub pseudo_commitment: [u8; 32],
}

/// Sign: prove membership at `real_index` (whose one-time secret is
/// `secret_key` and whose commitment blinding is `input_blinding`), against
/// a pseudo-output commitment re-blinded with `pseudo_blinding`.
pub fn sign(
    msg: &[u8; 32],
    ring_blob: &[u8],
    real_index: usize,
    secret_key: &[u8; 32],
    input_blinding: &[u8; 32],
    pseudo_blinding: &[u8; 32],
) -> Option<ClsagResult> {
    sign_with_max(
        msg,
        ring_blob,
        real_index,
        secret_key,
        input_blinding,
        pseudo_blinding,
        MAX_RING,
    )
}

/// CLSAG sign with an explicit ring-size cap (FCMP interim uses [`MAX_FCMP_RING`]).
pub fn sign_with_max(
    msg: &[u8; 32],
    ring_blob: &[u8],
    real_index: usize,
    secret_key: &[u8; 32],
    input_blinding: &[u8; 32],
    pseudo_blinding: &[u8; 32],
    max_n: usize,
) -> Option<ClsagResult> {
    let (keys, commitments) = parse_ring(ring_blob, max_n)?;
    let n = keys.len();
    if real_index >= n {
        return None;
    }
    let x = scalar(secret_key)?;
    if keys[real_index] != G * x {
        return None;
    }

    // C_l = a·H + x_in·G and C' = a·H + x'·G  ⇒  C' = C_l − (x_in − x')·G.
    let z = scalar(input_blinding)? - scalar(pseudo_blinding)?;
    let pseudo_point = commitments[real_index] - G * z;
    let pseudo = pseudo_point.compress().to_bytes();

    let real_key_bytes = &ring_blob[real_index * 64..real_index * 64 + 32];
    let hp_real = hp(real_key_bytes);
    let i_point = hp_real * x;
    let d_point = hp_real * z;
    let key_image = i_point.compress().to_bytes();
    let aux_image = d_point.compress().to_bytes();

    let (mu_p, mu_c) = aggregation_coefficients(ring_blob, &key_image, &aux_image, &pseudo);
    let w = mu_p * x + mu_c * z;
    let w_tilde = i_point * mu_p + d_point * mu_c;

    let mut rng = rand::rngs::OsRng;
    let a = Scalar::random(&mut rng);
    let mut s: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();

    // Challenge for position (real_index + 1) % n, seeded by the real spend.
    let mut c = round_challenge(
        ring_blob,
        &pseudo,
        msg,
        (G * a).compress().as_bytes(),
        (hp_real * a).compress().as_bytes(),
    );
    let mut cur = (real_index + 1) % n;
    let mut c0 = (cur == 0).then_some(c);
    while cur != real_index {
        let key_bytes = &ring_blob[cur * 64..cur * 64 + 32];
        let w_i = keys[cur] * mu_p + (commitments[cur] - pseudo_point) * mu_c;
        let l_point = G * s[cur] + w_i * c;
        let r_point = hp(key_bytes) * s[cur] + w_tilde * c;
        c = round_challenge(
            ring_blob,
            &pseudo,
            msg,
            l_point.compress().as_bytes(),
            r_point.compress().as_bytes(),
        );
        cur = (cur + 1) % n;
        if cur == 0 {
            c0 = Some(c);
        }
    }
    // `c` is now the challenge at the real position: close the ring.
    s[real_index] = a - c * w;
    let c0 = c0.expect("the loop passes position 0 exactly once");

    let mut signature = Vec::with_capacity(32 * (n + 2));
    signature.extend_from_slice(&c0.to_bytes());
    for si in &s {
        signature.extend_from_slice(&si.to_bytes());
    }
    signature.extend_from_slice(&aux_image);
    Some(ClsagResult {
        signature,
        key_image,
        pseudo_commitment: pseudo,
    })
}

/// Verify a CLSAG. Total-decoding strict: every scalar must be canonical,
/// every point must decompress, `I` must not be the identity.
pub fn verify(msg: &[u8], ring_blob: &[u8], pseudo: &[u8], key_image: &[u8], sig: &[u8]) -> bool {
    verify_with_max(msg, ring_blob, pseudo, key_image, sig, MAX_RING)
}

/// CLSAG verify with an explicit ring-size cap (FCMP interim uses [`MAX_FCMP_RING`]).
pub fn verify_with_max(
    msg: &[u8],
    ring_blob: &[u8],
    pseudo: &[u8],
    key_image: &[u8],
    sig: &[u8],
    max_n: usize,
) -> bool {
    if msg.len() != 32 || pseudo.len() != 32 || key_image.len() != 32 {
        return false;
    }
    let Some((keys, commitments)) = parse_ring(ring_blob, max_n) else {
        return false;
    };
    let n = keys.len();
    if sig.len() != 32 * (n + 2) {
        return false;
    }
    let Some(c0) = scalar(&sig[..32]) else {
        return false;
    };
    let Some(s) = sig[32..32 * (n + 1)]
        .chunks_exact(32)
        .map(scalar)
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    let Some(d_point) = decompress(&sig[32 * (n + 1)..]) else {
        return false;
    };
    let (Some(pseudo_point), Some(i_point)) = (decompress(pseudo), decompress(key_image)) else {
        return false;
    };
    if i_point == RistrettoPoint::identity() {
        return false;
    }

    let aux_image = &sig[32 * (n + 1)..];
    let (mu_p, mu_c) = aggregation_coefficients(ring_blob, key_image, aux_image, pseudo);
    let w_tilde = i_point * mu_p + d_point * mu_c;

    let mut c = c0;
    for i in 0..n {
        let key_bytes = &ring_blob[i * 64..i * 64 + 32];
        let w_i = keys[i] * mu_p + (commitments[i] - pseudo_point) * mu_c;
        let l_point = G * s[i] + w_i * c;
        let r_point = hp(key_bytes) * s[i] + w_tilde * c;
        c = round_challenge(
            ring_blob,
            pseudo,
            msg,
            l_point.compress().as_bytes(),
            r_point.compress().as_bytes(),
        );
    }
    c == c0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::{commit, random_blinding, random_secret_key};

    /// Build a ring blob of `n` members; the real one at `l` commits to
    /// `amount` under `blinding`, decoys are random keys with random
    /// commitments to random amounts.
    fn test_ring(n: usize, l: usize, amount: u64, blinding: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
        let mut blob = Vec::new();
        let mut real_secret = [0u8; 32];
        for i in 0..n {
            let (secret, public) = random_secret_key();
            blob.extend_from_slice(&public);
            if i == l {
                real_secret = secret;
                blob.extend_from_slice(&commit(amount, blinding).unwrap());
            } else {
                blob.extend_from_slice(&commit(i as u64 * 999 + 1, &random_blinding()).unwrap());
            }
        }
        (blob, real_secret)
    }

    #[test]
    fn sign_verify_roundtrip_all_positions_and_sizes() {
        let msg = [7u8; 32];
        for n in [1usize, 2, 4, 11, 16] {
            for l in [0, n / 2, n - 1] {
                let blinding = random_blinding();
                let (ring, secret) = test_ring(n, l, 1_000, &blinding);
                let pseudo_blinding = random_blinding();
                let res = sign(&msg, &ring, l, &secret, &blinding, &pseudo_blinding).unwrap();
                assert!(verify(
                    &msg,
                    &ring,
                    &res.pseudo_commitment,
                    &res.key_image,
                    &res.signature
                ));
                // The pseudo commitment really is commit(amount, pseudo_blinding).
                assert_eq!(
                    res.pseudo_commitment,
                    commit(1_000, &pseudo_blinding).unwrap()
                );
            }
        }
    }

    #[test]
    fn key_image_is_deterministic_and_ring_independent() {
        let msg = [1u8; 32];
        let blinding = [0u8; 32]; // coinbase-style: zero blinding
        let (ring_a, secret) = test_ring(4, 2, 50, &blinding);
        // Same real key inside a different ring.
        let mut ring_b = test_ring(4, 0, 50, &blinding).0;
        ring_b[..64].copy_from_slice(&ring_a[2 * 64..3 * 64]);

        let sig_a = sign(&msg, &ring_a, 2, &secret, &blinding, &random_blinding()).unwrap();
        let sig_b = sign(&msg, &ring_b, 0, &secret, &blinding, &random_blinding()).unwrap();
        assert_eq!(sig_a.key_image, sig_b.key_image);
        assert_eq!(Some(sig_a.key_image), key_image(&secret));
    }

    #[test]
    fn forgeries_fail() {
        let msg = [9u8; 32];
        let blinding = random_blinding();
        let (ring, secret) = test_ring(4, 1, 77, &blinding);
        let pseudo_blinding = random_blinding();
        let res = sign(&msg, &ring, 1, &secret, &blinding, &pseudo_blinding).unwrap();

        // Wrong message.
        assert!(!verify(
            &[0u8; 32],
            &ring,
            &res.pseudo_commitment,
            &res.key_image,
            &res.signature
        ));
        // Tampered scalar.
        let mut bad = res.signature.clone();
        bad[40] ^= 1;
        assert!(!verify(
            &msg,
            &ring,
            &res.pseudo_commitment,
            &res.key_image,
            &bad
        ));
        // Substituted key image (decouples linkability).
        let other_ki = key_image(&random_secret_key().0).unwrap();
        assert!(!verify(
            &msg,
            &ring,
            &res.pseudo_commitment,
            &other_ki,
            &res.signature
        ));
        // Pseudo commitment to a different amount.
        let wrong_pseudo = commit(78, &pseudo_blinding).unwrap();
        assert!(!verify(
            &msg,
            &ring,
            &wrong_pseudo,
            &res.key_image,
            &res.signature
        ));
        // Identity key image.
        let identity = RistrettoPoint::identity().compress().to_bytes();
        assert!(!verify(
            &msg,
            &ring,
            &res.pseudo_commitment,
            &identity,
            &res.signature
        ));
    }

    #[test]
    fn cannot_sign_without_the_key_or_wrong_position() {
        let blinding = random_blinding();
        let (ring, _secret) = test_ring(4, 1, 5, &blinding);
        let (wrong_secret, _) = random_secret_key();
        assert!(sign(
            &[0u8; 32],
            &ring,
            1,
            &wrong_secret,
            &blinding,
            &random_blinding()
        )
        .is_none());
        // Right key, wrong claimed position.
        let (ring2, secret2) = test_ring(4, 3, 5, &blinding);
        assert!(sign(
            &[0u8; 32],
            &ring2,
            0,
            &secret2,
            &blinding,
            &random_blinding()
        )
        .is_none());
        let _ = ring;
    }

    #[test]
    fn pseudo_balance_composes_with_range_proofs() {
        // A pseudo commitment produced by sign() balances against outputs
        // re-blinded to match: Σ C' == Σ C_out + fee·H.
        let amount = 10_000u64;
        let fee = 100u64;
        let in_blinding = [0u8; 32]; // coinbase input
        let (ring, secret) = test_ring(2, 0, amount, &in_blinding);
        let pseudo_blinding = random_blinding();
        let res = sign(
            &[3u8; 32],
            &ring,
            0,
            &secret,
            &in_blinding,
            &pseudo_blinding,
        )
        .unwrap();

        let out_blinding = pseudo_blinding; // single output absorbs it all
        let out = commit(amount - fee, &out_blinding).unwrap();
        assert!(crate::native::verify_balance(
            &res.pseudo_commitment,
            &out,
            fee
        ));
    }
}
