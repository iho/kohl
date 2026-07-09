//! Path B (Curve Trees) embedding sketch + literature assessment.
//!
//! This spike does **not** implement Helios/Selene/Wei25519 cycle arithmetic.
//! It records how Ristretto `(P, C)` would embed into a cycle-based Curve Tree
//! and compares published Monero FCMP++ numbers to design D2 gates.

use super::gates::{GateResult, GateSet, D2_GATES};

/// Sketch of a collision-hardened embedding of a Ristretto output into cycle
/// field elements / points. **Not** a production embedding — documentation
/// and deterministic hash placeholders only.
#[derive(Clone, Debug)]
pub struct EmbeddingSketch {
    /// Domain-separated digest of `(P, C)` for Path A leaf (blake2).
    pub path_a_leaf: [u8; 32],
    /// Proposed Path B preimage: same 80-byte `LEAF_DOM||P||C`, then
    /// hash-to-field / hash-to-curve on the *cycle* group (not implemented).
    pub path_b_preimage: alloc::vec::Vec<u8>,
    /// Security notes for PR-0 memo / design amend.
    pub notes: &'static [&'static str],
}

impl EmbeddingSketch {
    /// Build the embedding sketch for one occupied output.
    pub fn for_output(p: &[u8; 32], c: &[u8; 32]) -> Self {
        use super::leaf::{leaf_hash, preimage};
        Self {
            path_a_leaf: leaf_hash(p, c),
            path_b_preimage: preimage(p, c),
            notes: EMBEDDING_NOTES,
        }
    }
}

const EMBEDDING_NOTES: &[&str] = &[
    "Ristretto is a prime-order *group abstraction* over Curve25519, not a Pasta-style cycle member.",
    "Monero FCMP++ uses a tailored cycle (Wei25519 / Helios / Selene) with Curve Trees + divisors.",
    "Kohl user keys stay Ristretto (D2); cycle arithmetic — if any — is host-std only.",
    "Embedding (P,C) into cycle leaves must be: domain-separated, deterministic, injective or collision-hardened, reject non-canonical Ristretto, no DL trapdoors between G/H and cycle gens.",
    "EMPTY placeholder needs a fixed distinct cycle embedding so immature slots exist without being spendable.",
    "fcmp-ringct / monero-oxide / fcmp-plus-plus are evaluation targets only — license + full Ristretto rewrite; no byte-compatible import.",
    "No trusted setup for headline Path B (aligns with rings/BP ethos).",
];

/// Published / cited Path B performance anchors (not measured in this crate).
///
/// Sources: Kayaba public notes (≈35 ms verify / ~2–3 KiB proofs on early
/// Curve Trees work); Monero FCMP++ blog and fcmp-plus-plus development.
/// Treat as **order-of-magnitude** until kohl re-benches a pinned rewrite.
#[derive(Clone, Copy, Debug)]
pub struct LiteraturePathB {
    pub prove_ms_per_input: f64,
    pub verify_ms_per_input: f64,
    pub proof_bytes_per_input: usize,
    pub trusted_setup: bool,
    pub source: &'static str,
}

impl LiteraturePathB {
    /// Conservative mid-range citation for go/no-go comparison.
    pub const MONERO_FCMP_PLUSPLUS_EARLY: Self = Self {
        // Proving often multi-second on laptop-class hardware in early notes;
        // use a mid estimate under the 30 s D2 cap.
        prove_ms_per_input: 5_000.0,
        verify_ms_per_input: 35.0,
        proof_bytes_per_input: 3 * 1024,
        trusted_setup: false,
        source: "Kayaba Curve Trees / FCMP++ public notes (≈35ms verify, ~2–3KiB); prove order-of-magnitude",
    };
}

/// Assessment of Path B against D2 gates using literature numbers.
#[derive(Clone, Debug)]
pub struct PathBAssessment {
    pub literature: LiteraturePathB,
    pub gate_result: GateResult,
    pub embedding_blocker: &'static str,
    pub recommendation: &'static str,
}

impl PathBAssessment {
    pub fn evaluate() -> Self {
        let lit = LiteraturePathB::MONERO_FCMP_PLUSPLUS_EARLY;
        let measured = GateSet {
            prove_ms_per_input: lit.prove_ms_per_input,
            verify_ms_per_input: lit.verify_ms_per_input,
            proof_bytes_per_input: lit.proof_bytes_per_input,
            trusted_setup: lit.trusted_setup,
            embedding_memo_ok: false, // no production embedding yet
        };
        let gate_result = super::gates::evaluate_gates(&measured, &D2_GATES);
        Self {
            literature: lit,
            gate_result,
            embedding_blocker: "Ristretto↛cycle embedding not implemented; Helios/Selene not in tree",
            recommendation: "Do not freeze Path B membership for Dual until a host-native cycle library is spiked with kohl embeddings and re-benched under D2 (or D2 verify gate is explicitly revised).",
        }
    }
}

/// Proxy cost: `n` variable-base Ristretto scalar muls (order-of-magnitude for
/// EC-heavy membership work). Not a Curve Trees proof.
pub fn msm_proxy_ristretto(n: usize) -> [u8; 32] {
    use curve25519_dalek::{
        constants::RISTRETTO_BASEPOINT_POINT as G,
        ristretto::RistrettoPoint,
        scalar::Scalar,
        traits::{Identity, MultiscalarMul},
    };
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    if n == 0 {
        return RistrettoPoint::identity().compress().to_bytes();
    }

    let mut rng = StdRng::seed_from_u64(0xFC0F_5B10_u64);
    let mut scalars = alloc::vec::Vec::with_capacity(n);
    let mut points = alloc::vec::Vec::with_capacity(n);
    for i in 0..n {
        let mut sb = [0u8; 64];
        rng.fill_bytes(&mut sb);
        scalars.push(Scalar::from_bytes_mod_order_wide(&sb));
        points.push(G * Scalar::from((i as u64) + 1));
    }
    RistrettoPoint::multiscalar_mul(&scalars, &points)
        .compress()
        .to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedding_sketch_deterministic() {
        let p = [1u8; 32];
        let c = [2u8; 32];
        let a = EmbeddingSketch::for_output(&p, &c);
        let b = EmbeddingSketch::for_output(&p, &c);
        assert_eq!(a.path_a_leaf, b.path_a_leaf);
        assert_eq!(a.path_b_preimage, b.path_b_preimage);
        assert!(!a.notes.is_empty());
    }

    #[test]
    fn path_b_literature_fails_strict_verify_gate() {
        let a = PathBAssessment::evaluate();
        // 35 ms > 25 ms D2 verify cap → overall fail until optimized or gate revised
        assert!(
            !a.gate_result.passed,
            "expected literature Path B to fail strict D2 (verify and/or embedding)"
        );
        assert!(!a.gate_result.verify_ok || !a.gate_result.embedding_ok);
    }

    #[test]
    fn msm_proxy_runs() {
        let out = msm_proxy_ristretto(8);
        assert_ne!(out, [0u8; 32]);
    }
}
