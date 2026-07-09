//! Confidential-transaction cryptography for the kohl chain.
//!
//! This crate is the **host-function boundary** described in BLUEPRINT.md
//! §1.6: the runtime (WASM, `no_std`) sees only the `#[runtime_interface]`
//! functions at the bottom of this file and calls them like any other host
//! function; the implementations run natively with `bulletproofs` /
//! `curve25519-dalek`, which are only compiled under `std`.
//!
//! Everything here is **consensus-critical**, including the byte-level
//! serialization at this boundary. Functions are versioned (`*_v1`) so old
//! blocks stay re-executable if rules evolve.
//!
//! ## Commitment convention (Monero's)
//!
//! A commitment to amount `a` with blinding `x` is `C = a·H + x·G`, where
//! `G` is the Ristretto basepoint and `H` is a NUMS hash-to-point (nobody
//! knows `log_G(H)`, or amounts could be forged). The blinding lives on the
//! *basepoint* so that CLSAG's commitment relation `C_real − C_pseudo = z·G`
//! shares its generator with the one-time keys `P = x·G` — exactly Monero.
//! The transparent fee enters the balance equation as `fee·H`:
//!
//! ```text
//! Σ C_pseudo_inputs == Σ C_outputs + fee·H
//! ```
//!
//! which holds iff amounts balance **and** blindings balance
//! (`Σ x_in == Σ x_out`). Range proofs over every output commitment prevent
//! negative-amount / overflow minting.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "std")]
pub mod clsag;
/// FCMP+SA+L verify (PR-4 host stub; real composition PR-5c).
///
/// Available under `std` (host) like CLSAG. Runtime calls via
/// [`RingctCrypto::verify_fcmp_v1`].
#[cfg(feature = "std")]
pub mod fcmp;
#[cfg(feature = "std")]
pub mod stealth;

/// FCMP research spike (PR-0). Feature-gated; **not** consensus-wired.
///
/// ```text
/// cargo test -p ringct-crypto --features fcmp-spike
/// cargo bench -p ringct-crypto --features fcmp-spike --bench fcmp_spike
/// ```
#[cfg(all(feature = "std", feature = "fcmp-spike"))]
pub mod fcmp_spike;

/// The set of host functions to register in the node executor so the WASM
/// runtime can call the native RingCT verifiers (BLUEPRINT.md §1.6).
#[cfg(feature = "std")]
pub use crate::ringct_crypto::HostFunctions as RingCtHostFunctions;

/// Bit width of every range proof: amounts are proven to lie in [0, 2^64).
pub const RANGE_PROOF_BITS: usize = 64;

/// Maximum commitments covered by one aggregated proof (== MAX_OUTPUTS).
/// The verifier pads to the next power of two with identity commitments
/// (= commitment to value 0 with blinding 0), mirroring the prover.
pub const MAX_AGGREGATED: usize = ringct_primitives::MAX_OUTPUTS as usize;

/// Merlin transcript domain label. Consensus-critical; version with care.
pub const TRANSCRIPT_LABEL: &[u8] = b"kohl/rangeproof/v1";

#[cfg(feature = "std")]
pub mod native {
    use super::*;
    use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
    use curve25519_dalek::{
        constants::RISTRETTO_BASEPOINT_POINT,
        ristretto::{CompressedRistretto, RistrettoPoint},
        scalar::Scalar,
        traits::Identity,
    };
    use merlin::Transcript;
    use sha2::Sha512;
    use std::sync::OnceLock;

    /// Monero-convention generators (see crate docs): value on the NUMS
    /// point `H`, blinding on the Ristretto basepoint `G`.
    pub(crate) fn pc_gens() -> &'static PedersenGens {
        static GENS: OnceLock<PedersenGens> = OnceLock::new();
        GENS.get_or_init(|| PedersenGens {
            B: RistrettoPoint::hash_from_bytes::<Sha512>(b"kohl/pedersen/value-generator/v1"),
            B_blinding: RISTRETTO_BASEPOINT_POINT,
        })
    }

    fn bp_gens() -> &'static BulletproofGens {
        static GENS: OnceLock<BulletproofGens> = OnceLock::new();
        GENS.get_or_init(|| BulletproofGens::new(RANGE_PROOF_BITS, MAX_AGGREGATED))
    }

    /// Split a blob into compressed points; `None` unless len % 32 == 0.
    fn parse_points(blob: &[u8]) -> Option<Vec<CompressedRistretto>> {
        if !blob.len().is_multiple_of(32) {
            return None;
        }
        Some(
            blob.chunks_exact(32)
                .map(|c| CompressedRistretto::from_slice(c).expect("chunk is 32 bytes"))
                .collect(),
        )
    }

    fn decompress_all(points: &[CompressedRistretto]) -> Option<Vec<RistrettoPoint>> {
        points.iter().map(|p| p.decompress()).collect()
    }

    /// Pedersen commitment `a·B + x·B̃`. `None` if the blinding bytes are not
    /// a canonical scalar.
    pub fn commit(amount: u64, blinding: &[u8; 32]) -> Option<[u8; 32]> {
        let x = Option::<Scalar>::from(Scalar::from_canonical_bytes(*blinding))?;
        Some(
            pc_gens()
                .commit(Scalar::from(amount), x)
                .compress()
                .to_bytes(),
        )
    }

    /// Commitment to a public amount with zero blinding (coinbase outputs).
    pub fn value_commitment(amount: u64) -> [u8; 32] {
        pc_gens()
            .commit(Scalar::from(amount), Scalar::ZERO)
            .compress()
            .to_bytes()
    }

    /// True iff `bytes` is a canonical compressed Ristretto point that is
    /// **not** the identity. Used to reject garbage one-time keys at mint time
    /// so they cannot poison future rings as decoys.
    pub fn is_valid_point(bytes: &[u8; 32]) -> bool {
        let Ok(c) = CompressedRistretto::from_slice(bytes) else {
            return false;
        };
        match c.decompress() {
            Some(p) => p != RistrettoPoint::identity(),
            None => false,
        }
    }

    /// Consensus balance equation: Σ inputs == Σ outputs + fee·B.
    /// Rejects any non-canonical / non-decompressible point.
    pub fn verify_balance(inputs: &[u8], outputs: &[u8], fee: u64) -> bool {
        let Some(ins) = parse_points(inputs).and_then(|p| decompress_all(&p)) else {
            return false;
        };
        let Some(outs) = parse_points(outputs).and_then(|p| decompress_all(&p)) else {
            return false;
        };
        if ins.is_empty() || outs.is_empty() {
            return false;
        }
        let in_sum = ins
            .iter()
            .fold(RistrettoPoint::identity(), |acc, p| acc + p);
        let out_sum = outs
            .iter()
            .fold(RistrettoPoint::identity(), |acc, p| acc + p);
        in_sum == out_sum + pc_gens().B * Scalar::from(fee)
    }

    /// Verify one aggregated range proof over `commitments` (concatenated
    /// 32-byte compressed points). Pads with identity commitments to the
    /// next power of two, mirroring [`prove_range`].
    pub fn verify_range_proof(proof: &[u8], commitments: &[u8]) -> bool {
        let Some(mut points) = parse_points(commitments) else {
            return false;
        };
        if points.is_empty() || points.len() > MAX_AGGREGATED {
            return false;
        }
        while !points.len().is_power_of_two() {
            points.push(RistrettoPoint::identity().compress());
        }
        let Ok(proof) = RangeProof::from_bytes(proof) else {
            return false;
        };
        let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
        proof
            .verify_multiple(
                bp_gens(),
                pc_gens(),
                &mut transcript,
                &points,
                RANGE_PROOF_BITS,
            )
            .is_ok()
    }

    // ---- Prover side (wallets and tests; never called by the runtime) ----

    /// A uniformly random canonical blinding scalar.
    pub fn random_blinding() -> [u8; 32] {
        Scalar::random(&mut rand::rngs::OsRng).to_bytes()
    }

    /// A random one-time keypair `(x, P = x·G)` (tests and wallets).
    pub fn random_secret_key() -> ([u8; 32], [u8; 32]) {
        let x = Scalar::random(&mut rand::rngs::OsRng);
        (
            x.to_bytes(),
            (RISTRETTO_BASEPOINT_POINT * x).compress().to_bytes(),
        )
    }

    /// The blinding that balances a transaction:
    /// `Σ input_blindings − Σ other_output_blindings` (fee has no blinding).
    pub fn balancing_blinding(
        input_blindings: &[[u8; 32]],
        output_blindings: &[[u8; 32]],
    ) -> Option<[u8; 32]> {
        let sum = |bs: &[[u8; 32]]| -> Option<Scalar> {
            bs.iter()
                .map(|b| Option::<Scalar>::from(Scalar::from_canonical_bytes(*b)))
                .try_fold(Scalar::ZERO, |acc, s| Some(acc + s?))
        };
        Some((sum(input_blindings)? - sum(output_blindings)?).to_bytes())
    }

    /// Produce one aggregated proof for `values` under `blindings`, padding
    /// to the next power of two with (0, 0). Returns the proof bytes and the
    /// commitments for the *real* values (in order).
    pub fn prove_range(values: &[u64], blindings: &[[u8; 32]]) -> Option<(Vec<u8>, Vec<[u8; 32]>)> {
        if values.is_empty() || values.len() != blindings.len() || values.len() > MAX_AGGREGATED {
            return None;
        }
        let real = values.len();
        let mut values = values.to_vec();
        let mut scalars = blindings
            .iter()
            .map(|b| Option::<Scalar>::from(Scalar::from_canonical_bytes(*b)))
            .collect::<Option<Vec<_>>>()?;
        while !values.len().is_power_of_two() {
            values.push(0);
            scalars.push(Scalar::ZERO);
        }
        let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
        let (proof, commitments) = RangeProof::prove_multiple(
            bp_gens(),
            pc_gens(),
            &mut transcript,
            &values,
            &scalars,
            RANGE_PROOF_BITS,
        )
        .ok()?;
        Some((
            proof.to_bytes(),
            commitments[..real].iter().map(|c| c.to_bytes()).collect(),
        ))
    }
}

use sp_runtime_interface::pass_by::{
    AllocateAndReturnByCodec, AllocateAndReturnPointer, PassFatPointerAndRead,
};

/// The host functions exposed to the runtime. Native implementations above;
/// the WASM side only sees extern stubs. Register `ringct_crypto::HostFunctions`
/// in the node's executor (Phase 4).
#[sp_runtime_interface::runtime_interface]
pub trait RingctCrypto {
    /// Σ inputs == Σ outputs + fee·B over concatenated compressed points.
    fn verify_balance_v1(
        input_commitments: PassFatPointerAndRead<&[u8]>,
        output_commitments: PassFatPointerAndRead<&[u8]>,
        fee: u64,
    ) -> bool {
        native::verify_balance(input_commitments, output_commitments, fee)
    }

    /// Aggregated 64-bit Bulletproof over the given output commitments.
    fn verify_range_proof_v1(
        proof: PassFatPointerAndRead<&[u8]>,
        output_commitments: PassFatPointerAndRead<&[u8]>,
    ) -> bool {
        native::verify_range_proof(proof, output_commitments)
    }

    /// Commitment to a public amount with zero blinding (coinbase).
    fn value_commitment_v1(amount: u64) -> AllocateAndReturnPointer<[u8; 32], 32> {
        native::value_commitment(amount)
    }

    /// CLSAG over a ring blob of `n × 64` bytes (`P_i ‖ C_i` pairs); see
    /// `clsag` module docs for the exact byte formats.
    fn verify_clsag_v1(
        msg: PassFatPointerAndRead<&[u8]>,
        ring: PassFatPointerAndRead<&[u8]>,
        pseudo_commitment: PassFatPointerAndRead<&[u8]>,
        key_image: PassFatPointerAndRead<&[u8]>,
        signature: PassFatPointerAndRead<&[u8]>,
    ) -> bool {
        clsag::verify(msg, ring, pseudo_commitment, key_image, signature)
    }

    /// FCMP+SA+L membership/spend proof for one input (design § verification).
    ///
    /// **PR-5 interim (`FCMP0001`):** full mature-set membership under the
    /// Path A Merkle root + CLSAG SA/link/re-blind. Transparent Merkle paths
    /// are never valid (D17). Anonymity set size ≤ `MAX_FCMP_ANON_SET` (64).
    /// Do not change this `v1` surface; add `v2` on break.
    ///
    /// * `msg` — 32-byte tx binding hash (`kohl/transfer/v4` when wired)
    /// * `membership_root` — 32-byte tree root
    /// * `pseudo_commitment` — 32-byte `C'`
    /// * `key_image` — 32-byte `I` (must equal `clsag::key_image`)
    /// * `proof` — ≤ `MAX_FCMP_PROOF_BYTES`
    fn verify_fcmp_v1(
        msg: PassFatPointerAndRead<&[u8]>,
        membership_root: PassFatPointerAndRead<&[u8]>,
        pseudo_commitment: PassFatPointerAndRead<&[u8]>,
        key_image: PassFatPointerAndRead<&[u8]>,
        proof: PassFatPointerAndRead<&[u8]>,
    ) -> bool {
        fcmp::verify(msg, membership_root, pseudo_commitment, key_image, proof)
    }

    /// Canonical non-identity Ristretto point? Used for one-time key hygiene.
    fn is_valid_point_v1(point: PassFatPointerAndRead<&[u8]>) -> bool {
        if point.len() != 32 {
            return false;
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(point);
        native::is_valid_point(&bytes)
    }

    /// Host-only random keypair as `secret ‖ public` (64 bytes). Used by
    /// WASM benchmarks (OsRng is not available in the runtime).
    fn random_secret_key_v1() -> AllocateAndReturnPointer<[u8; 64], 64> {
        let (sk, pk) = native::random_secret_key();
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&sk);
        out[32..].copy_from_slice(&pk);
        out
    }

    /// Host-only random blinding scalar (32 bytes).
    fn random_blinding_v1() -> AllocateAndReturnPointer<[u8; 32], 32> {
        native::random_blinding()
    }

    /// Host-only Pedersen commit → 32-byte compressed point.
    fn commit_v1(
        amount: u64,
        blinding: PassFatPointerAndRead<&[u8]>,
    ) -> AllocateAndReturnPointer<[u8; 32], 32> {
        let mut b = [0u8; 32];
        if blinding.len() == 32 {
            b.copy_from_slice(blinding);
        }
        native::commit(amount, &b).unwrap_or([0u8; 32])
    }

    /// Host-only key image of a one-time secret.
    fn key_image_v1(
        secret: PassFatPointerAndRead<&[u8]>,
    ) -> AllocateAndReturnPointer<[u8; 32], 32> {
        let mut sk = [0u8; 32];
        if secret.len() == 32 {
            sk.copy_from_slice(secret);
        }
        clsag::key_image(&sk).unwrap_or([0u8; 32])
    }

    /// Host-only: build a complete 1-in/1-out transfer for benchmarks.
    ///
    /// Inputs (SCALE where noted):
    /// * `ring_indices` — SCALE `Vec<u64>` of ring members (length = ring size)
    /// * `ring_blob` — `n × 64` bytes of `P‖C` pairs matching `ring_indices`
    /// * `real_index` — position of the real spend in the ring
    /// * `secret` — 32-byte one-time secret of the real spend
    /// * `amount` / `fee` — public amounts (`amount > fee`)
    /// * `in_blinding` — 32-byte input blinding (zeros for coinbase)
    ///
    /// Returns SCALE-encoded `TransferTx` bytes, or empty on failure.
    /// Runs on the host so WASM benchmarks can prepare valid CLSAG+BP material
    /// without pulling `rand`/OsRng into the runtime.
    fn bench_make_transfer_v1(
        ring_indices: PassFatPointerAndRead<&[u8]>,
        ring_blob: PassFatPointerAndRead<&[u8]>,
        real_index: u32,
        secret: PassFatPointerAndRead<&[u8]>,
        amount: u64,
        fee: u64,
        in_blinding: PassFatPointerAndRead<&[u8]>,
    ) -> AllocateAndReturnByCodec<alloc::vec::Vec<u8>> {
        use alloc::vec::Vec;
        if amount <= fee || secret.len() != 32 || in_blinding.len() != 32 {
            return Vec::new();
        }
        let Ok(indices) = <Vec<u64> as codec::Decode>::decode(&mut &ring_indices[..]) else {
            return Vec::new();
        };
        let n = indices.len();
        if n == 0 || ring_blob.len() != n * 64 || (real_index as usize) >= n {
            return Vec::new();
        }
        let mut sk = [0u8; 32];
        sk.copy_from_slice(secret);
        let mut in_b = [0u8; 32];
        in_b.copy_from_slice(in_blinding);

        let out_amount = amount - fee;
        let pseudo_blinding = native::random_blinding();
        let Some((proof, commits)) = native::prove_range(&[out_amount], &[pseudo_blinding]) else {
            return Vec::new();
        };
        let Some(pseudo_c) = native::commit(amount, &pseudo_blinding) else {
            return Vec::new();
        };
        let Some(ki) = clsag::key_image(&sk) else {
            return Vec::new();
        };
        let (_, otk) = native::random_secret_key();
        let (_, tx_pk) = native::random_secret_key();

        // SCALE layout mirrors pallet_ringct::TransferTx (BoundedVec ≡ Vec).
        #[derive(codec::Encode)]
        struct RingInputEnc {
            ring: Vec<u64>,
            key_image: [u8; 32],
            pseudo_commitment: [u8; 32],
            clsag: Vec<u8>,
        }
        #[derive(codec::Encode)]
        struct OutputEnc {
            one_time_key: [u8; 32],
            commitment: [u8; 32],
            view_tag: u8,
            payload: Vec<u8>,
        }
        #[derive(codec::Encode)]
        struct TransferEnc {
            inputs: Vec<RingInputEnc>,
            outputs: Vec<OutputEnc>,
            tx_pubkey: [u8; 32],
            range_proof: Vec<u8>,
            fee: u64,
        }

        let mut tx = TransferEnc {
            inputs: vec![RingInputEnc {
                ring: indices,
                key_image: ki,
                pseudo_commitment: pseudo_c,
                clsag: Vec::new(),
            }],
            outputs: vec![OutputEnc {
                one_time_key: otk,
                commitment: commits[0],
                view_tag: 0,
                payload: Vec::new(),
            }],
            tx_pubkey: tx_pk,
            range_proof: proof,
            fee,
        };

        // Must match pallet_ringct::signing_hash / SIGNING_DOMAIN.
        const SIGNING_DOMAIN: [u8; 16] = *b"kohl/transfer/v3";
        let rings: Vec<Vec<u64>> = tx.inputs.iter().map(|i| i.ring.clone()).collect();
        let kis: Vec<[u8; 32]> = tx.inputs.iter().map(|i| i.key_image).collect();
        let pseudos: Vec<[u8; 32]> = tx.inputs.iter().map(|i| i.pseudo_commitment).collect();
        let msg = sp_io::hashing::blake2_256(&codec::Encode::encode(&(
            SIGNING_DOMAIN,
            rings,
            kis,
            pseudos,
            &tx.outputs,
            tx.tx_pubkey,
            tx.fee,
        )));
        let Some(sig) = clsag::sign(
            &msg,
            ring_blob,
            real_index as usize,
            &sk,
            &in_b,
            &pseudo_blinding,
        ) else {
            return Vec::new();
        };
        tx.inputs[0].clsag = sig.signature;
        codec::Encode::encode(&tx)
    }
}

#[cfg(test)]
mod tests {
    use super::native::*;

    #[test]
    fn commit_roundtrip_and_value_commitment_agree() {
        let zero = [0u8; 32];
        assert_eq!(commit(42, &zero).unwrap(), value_commitment(42));
    }

    #[test]
    fn balance_holds_iff_amounts_and_blindings_balance() {
        // in: 100 (blinding 0)  →  out: 60 + 30, fee 10
        let b1 = random_blinding();
        let b2 = balancing_blinding(&[], &[b1]).unwrap();
        let input = value_commitment(100);
        let o1 = commit(60, &b1).unwrap();
        let o2 = commit(30, &b2).unwrap();
        let outs = [o1, o2].concat();
        assert!(verify_balance(&input, &outs, 10));
        assert!(!verify_balance(&input, &outs, 11)); // wrong fee
        let o2_bad = commit(31, &b2).unwrap(); // wrong amount
        assert!(!verify_balance(&input, &[o1, o2_bad].concat(), 10));
        let o2_bad_blind = commit(30, &random_blinding()).unwrap(); // unbalanced blinding
        assert!(!verify_balance(&input, &[o1, o2_bad_blind].concat(), 10));
    }

    #[test]
    fn range_proof_roundtrip_with_padding() {
        // 3 outputs → prover/verifier pad to 4 identically.
        let blindings = [random_blinding(), random_blinding(), random_blinding()];
        let (proof, commitments) = prove_range(&[1, u64::MAX, 0], &blindings).unwrap();
        assert!(verify_range_proof(&proof, &commitments.concat()));

        // Mutated proof fails.
        let mut bad = proof.clone();
        bad[10] ^= 1;
        assert!(!verify_range_proof(&bad, &commitments.concat()));

        // Proof over different commitments fails.
        let (_, other) = prove_range(&[5], &[random_blinding()]).unwrap();
        assert!(!verify_range_proof(&proof, &other.concat()));

        // Reordered commitments fail (transcript binds order).
        let reordered = [commitments[1], commitments[0], commitments[2]].concat();
        assert!(!verify_range_proof(&proof, &reordered));
    }

    #[test]
    fn garbage_inputs_are_rejected_not_panicking() {
        assert!(!verify_range_proof(b"junk", &[0u8; 32]));
        assert!(!verify_range_proof(&[], &[]));
        assert!(!verify_balance(&[0u8; 31], &[0u8; 32], 0)); // bad length
        assert!(!verify_balance(&[0xffu8; 32], &value_commitment(1), 0)); // non-canonical point
    }

    #[test]
    fn is_valid_point_accepts_keys_rejects_garbage() {
        let (_sk, pk) = random_secret_key();
        assert!(is_valid_point(&pk));
        assert!(!is_valid_point(&[0u8; 32])); // identity
        assert!(!is_valid_point(&[0xff; 32])); // non-canonical
    }
}
