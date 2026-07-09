//! SA+L sketch for the PR-0 spike (not a full FCMP composition).
//!
//! Covers the *open* algebraic checks that any FCMP+SA+L must satisfy once
//! membership opens `(P, C)`:
//! * key image `I = x·Hp(P)` — **byte-identical** to `clsag::key_image`
//! * amount re-blind `C − C' = z·G`
//! * **D17**: transparent Merkle paths are rejected as membership proofs

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};

use super::merkle::TransparentPath;
use crate::clsag;

/// Open (non-ZK) witness material for SA+L unit checks.
#[derive(Clone, Debug)]
pub struct OpenSaLinkStatement {
    pub p: [u8; 32],
    pub c: [u8; 32],
    pub c_prime: [u8; 32],
    pub key_image: [u8; 32],
    pub secret_key: [u8; 32],
    pub input_blinding: [u8; 32],
    pub pseudo_blinding: [u8; 32],
}

/// Derive the CryptoNote key image with the **same** function as CLSAG.
///
/// KAT requirement (design \(\mathcal{R}\) item 3): FCMP KI bytes equal
/// `clsag::key_image(sk)`.
pub fn sa_link_key_image(secret_key: &[u8; 32]) -> Option<[u8; 32]> {
    clsag::key_image(secret_key)
}

fn scalar(bytes: &[u8; 32]) -> Option<Scalar> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes))
}

fn decompress(bytes: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto::from_slice(bytes).ok()?.decompress()
}

/// Check spend-auth + re-blind on an *opened* leaf (spike only).
///
/// Full FCMP must prove the same relations without opening `(P,C,ℓ)`.
pub fn open_reblind_ok(st: &OpenSaLinkStatement) -> bool {
    let Some(x) = scalar(&st.secret_key) else {
        return false;
    };
    let Some(p) = decompress(&st.p) else {
        return false;
    };
    if p == RistrettoPoint::identity() || p != G * x {
        return false;
    }

    let Some(expected_ki) = sa_link_key_image(&st.secret_key) else {
        return false;
    };
    if expected_ki != st.key_image {
        return false;
    }
    // Canonicity: non-identity
    let Some(ki) = decompress(&st.key_image) else {
        return false;
    };
    if ki == RistrettoPoint::identity() {
        return false;
    }

    let Some(c) = decompress(&st.c) else {
        return false;
    };
    let Some(c_prime) = decompress(&st.c_prime) else {
        return false;
    };
    let Some(x_in) = scalar(&st.input_blinding) else {
        return false;
    };
    let Some(x_p) = scalar(&st.pseudo_blinding) else {
        return false;
    };
    let z = x_in - x_p;
    // C − C' = z·G
    c - c_prime == G * z
}

/// Design D17 negative rule: a transparent path encoding is **never** a valid `π`.
///
/// Spike stand-in for `verify_fcmp_v1` rejecting open paths. Production
/// PR-5a must keep an equivalent negative KAT.
pub fn reject_transparent_path_as_proof(_path: &TransparentPath) -> bool {
    // Always reject — membership must be index-hiding ZK.
    false
}

/// Build a valid open statement for tests using native commit helpers.
pub fn make_open_statement(
    amount: u64,
    secret_key: &[u8; 32],
    input_blinding: &[u8; 32],
    pseudo_blinding: &[u8; 32],
) -> Option<OpenSaLinkStatement> {
    use crate::native;
    let x = scalar(secret_key)?;
    let p = (G * x).compress().to_bytes();
    let c = native::commit(amount, input_blinding)?;
    let c_prime = native::commit(amount, pseudo_blinding)?;
    let key_image = sa_link_key_image(secret_key)?;
    Some(OpenSaLinkStatement {
        p,
        c,
        c_prime,
        key_image,
        secret_key: *secret_key,
        input_blinding: *input_blinding,
        pseudo_blinding: *pseudo_blinding,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fcmp_spike::merkle::SparseMerkleTree;
    use crate::native;

    #[test]
    fn key_image_matches_clsag() {
        let (sk, _pk) = native::random_secret_key();
        assert_eq!(sa_link_key_image(&sk), clsag::key_image(&sk));
    }

    #[test]
    fn open_reblind_roundtrip() {
        let (sk, _) = native::random_secret_key();
        let in_b = native::random_blinding();
        let ps_b = native::random_blinding();
        let st = make_open_statement(1_000, &sk, &in_b, &ps_b).expect("stmt");
        assert!(open_reblind_ok(&st));
    }

    #[test]
    fn open_reblind_rejects_wrong_amount_link() {
        let (sk, _) = native::random_secret_key();
        let in_b = native::random_blinding();
        let ps_b = native::random_blinding();
        let mut st = make_open_statement(1_000, &sk, &in_b, &ps_b).expect("stmt");
        // Break C' amount
        st.c_prime = native::commit(999, &ps_b).unwrap();
        assert!(!open_reblind_ok(&st));
    }

    #[test]
    fn transparent_path_always_rejected_as_proof() {
        let mut t = SparseMerkleTree::new();
        t.grow_empty();
        let (sk, pk) = native::random_secret_key();
        let c = native::commit(1, &native::random_blinding()).unwrap();
        assert!(t.admit(0, &pk, &c));
        let path = t.transparent_path(0).unwrap();
        assert!(!reject_transparent_path_as_proof(&path));
        // Path itself may still recompute root correctly (maintenance OK).
        assert!(SparseMerkleTree::verify_transparent_path(&path, &t.root()));
        let _ = sk;
    }
}
