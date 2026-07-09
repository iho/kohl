//! Naive "full-set ring" cost model — why O(n) CLSAG cannot replace FCMP.
//!
//! CLSAG sign/verify and signature size scale linearly with ring size.
//! Production kohl uses `n = 16`. Proving membership in *all* mature outputs
//! via a giant CLSAG would make signatures and verify time proportional to
//! the chain's output count — unbounded.

use crate::clsag;

/// CLSAG signature byte length: `c0 (32) || s_0..s_{n-1} (32*n) || D (32)`.
pub fn estimate_clsag_sig_bytes(n: usize) -> usize {
    32 * (n + 2)
}

/// Cost model row for a hypothetical full-set CLSAG of size `n`.
#[derive(Clone, Debug)]
pub struct NaiveFullsetCost {
    pub n: usize,
    pub sig_bytes: usize,
    /// Measured or extrapolated verify time (ms).
    pub verify_ms: f64,
    /// Measured or extrapolated sign time (ms).
    pub sign_ms: f64,
    pub within_d2_verify: bool,
    pub within_d2_size: bool,
    pub note: &'static str,
}

/// Extrapolate from a measured baseline at `base_n` (typically 16).
pub fn naive_fullset_cost(
    n: usize,
    base_n: usize,
    base_verify_ms: f64,
    base_sign_ms: f64,
) -> NaiveFullsetCost {
    let scale = n as f64 / base_n as f64;
    let verify_ms = base_verify_ms * scale;
    let sign_ms = base_sign_ms * scale;
    let sig_bytes = estimate_clsag_sig_bytes(n);
    NaiveFullsetCost {
        n,
        sig_bytes,
        verify_ms,
        sign_ms,
        within_d2_verify: verify_ms <= 25.0,
        within_d2_size: sig_bytes <= 16 * 1024,
        note: "linear extrapolation from CLSAG; not a log-size membership proof",
    }
}

/// Run real CLSAG sign+verify at production ring size for baseline timing.
///
/// Returns `(sign_ms, verify_ms)` averaged over `iters` (wall-clock).
pub fn measure_clsag_baseline(iters: u32) -> (f64, f64) {
    use crate::native as crypto;
    use std::time::Instant;

    let n = 16usize;
    let msg = [7u8; 32];
    let blinding = crypto::random_blinding();
    let (ring, secret) = make_ring(n, 0, 1_000, &blinding);
    let res = clsag::sign(
        &msg,
        &ring,
        0,
        &secret,
        &blinding,
        &crypto::random_blinding(),
    )
    .expect("sign");

    let t0 = Instant::now();
    for _ in 0..iters {
        let r = clsag::sign(
            &msg,
            &ring,
            0,
            &secret,
            &blinding,
            &crypto::random_blinding(),
        )
        .expect("sign");
        std::hint::black_box(r);
    }
    let sign_ms = t0.elapsed().as_secs_f64() * 1000.0 / f64::from(iters);

    let t1 = Instant::now();
    for _ in 0..iters {
        assert!(clsag::verify(
            &msg,
            &ring,
            &res.pseudo_commitment,
            &res.key_image,
            &res.signature,
        ));
    }
    let verify_ms = t1.elapsed().as_secs_f64() * 1000.0 / f64::from(iters);
    (sign_ms, verify_ms)
}

fn make_ring(n: usize, real: usize, amount: u64, blinding: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
    use crate::native as crypto;
    let mut blob = Vec::with_capacity(n * 64);
    let mut secret = [0u8; 32];
    for i in 0..n {
        let (sk, pk) = crypto::random_secret_key();
        blob.extend_from_slice(&pk);
        if i == real {
            secret = sk;
            blob.extend_from_slice(&crypto::commit(amount, blinding).unwrap());
        } else {
            blob.extend_from_slice(
                &crypto::commit(i as u64 * 99 + 1, &crypto::random_blinding()).unwrap(),
            );
        }
    }
    (blob, secret)
}

/// Table of full-set sizes relevant to the memo.
pub fn cost_table(base_verify_ms: f64, base_sign_ms: f64) -> alloc::vec::Vec<NaiveFullsetCost> {
    const BASE: usize = 16;
    [16usize, 64, 256, 1024, 16_384, 1_000_000]
        .into_iter()
        .map(|n| naive_fullset_cost(n, BASE, base_verify_ms, base_sign_ms))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sig_size_formula() {
        assert_eq!(estimate_clsag_sig_bytes(16), 32 * 18);
        assert_eq!(estimate_clsag_sig_bytes(1_000_000), 32 * 1_000_002);
    }

    #[test]
    fn million_ring_blows_size_gate() {
        let c = naive_fullset_cost(1_000_000, 16, 1.0, 2.0);
        assert!(!c.within_d2_size);
        assert!(!c.within_d2_verify);
    }

    #[test]
    fn production_ring_fits_size() {
        let c = naive_fullset_cost(16, 16, 1.0, 2.0);
        assert!(c.within_d2_size);
        assert_eq!(c.sig_bytes, clsag_sig_len_constant());
    }

    fn clsag_sig_len_constant() -> usize {
        // Matches ringct_primitives CLSAG_MAX_BYTES for n=16: 32*(16+2)
        32 * (16 + 2)
    }
}
