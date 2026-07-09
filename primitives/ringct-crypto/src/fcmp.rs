//! FCMP+SA+L verification and proving (host path).
//!
//! # PR-5 interim construction (v1 proof tag `FCMP0001`)
//!
//! Full **mature-set** membership under the Path A Merkle root, with CLSAG
//! providing spend-authorization, linkability (key image), and amount re-blind
//! in one shot:
//!
//! 1. Proof carries leaf digests `0..tree_slots` (EMPTY or `L(P,C)`).
//! 2. Verifier recomputes Merkle root → must equal public `membership_root`.
//! 3. Proof carries ring `(P‖C)×n` of **every non-EMPTY leaf** (full mature set).
//! 4. Each ring member’s `leaf_hash(P,C)` must match the corresponding digest.
//! 5. CLSAG over that ring binds `msg`, `C'`, and key image `I` (same as
//!    `clsag::key_image`).
//!
//! ## Privacy
//!
//! Index-hiding among the **full mature set** at that root (not a decoy-16
//! ring). Transparent single-leaf Merkle paths are **rejected** (D17).
//!
//! ## Scale limit (honest)
//!
//! Proof size is **O(tree_slots + |admitted|)**. Cap:
//! [`ringct_primitives::MAX_FCMP_ANON_SET`] (64). Larger trees require Curve
//! Trees / a later log-size membership argument — do not silently raise the
//! cap without a size audit against [`MAX_FCMP_PROOF_BYTES`].
//!
//! ## Host ABI
//!
//! ```text
//! verify_fcmp_v1(msg, membership_root, C', I, proof) -> bool
//! ```

use alloc::vec::Vec;

use ringct_primitives::{
    FCMP_EMPTY_LEAF_DOM, FCMP_LEAF_DOM, FCMP_MERKLE_DOM, FCMP_MERKLE_EMPTY_DOM, MAX_FCMP_ANON_SET,
    MAX_FCMP_PROOF_BYTES,
};
use sp_io::hashing::blake2_256;

use crate::clsag::{self, MAX_FCMP_RING};

/// Fiat–Shamir domain (reserved for future non-CLSAG transcripts).
pub const FS_LABEL: &[u8] = b"kohl/fcmp/fs/v1";

/// Proof encoding version tag (8 bytes).
pub const PROOF_TAG: &[u8; 8] = b"FCMP0001";

/// Marker for debug transparent Merkle paths — **never** a valid `π` (D17).
pub const TRANSPARENT_PATH_DEBUG_TAG: &[u8; 8] = b"TRPATH01";

// ---- Path A leaf / Merkle (host copy of pallet domains) ------------------

/// Occupied leaf: `blake2_256(FCMP_LEAF_DOM || P || C)`.
pub fn leaf_hash(p: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let mut v = Vec::with_capacity(FCMP_LEAF_DOM.len() + 64);
    v.extend_from_slice(FCMP_LEAF_DOM);
    v.extend_from_slice(p);
    v.extend_from_slice(c);
    blake2_256(&v)
}

/// Immature / not-yet-admitted placeholder leaf.
pub fn empty_leaf_hash() -> [u8; 32] {
    blake2_256(FCMP_EMPTY_LEAF_DOM)
}

fn merkle_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut v = Vec::with_capacity(FCMP_MERKLE_DOM.len() + 64);
    v.extend_from_slice(FCMP_MERKLE_DOM);
    v.extend_from_slice(left);
    v.extend_from_slice(right);
    blake2_256(&v)
}

fn merkle_empty_child() -> [u8; 32] {
    blake2_256(FCMP_MERKLE_EMPTY_DOM)
}

/// Binary Merkle root over leaf digests (Path A; matches pallet).
pub fn root_from_leaves(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return merkle_empty_child();
    }
    let pad = merkle_empty_child();
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let n = level.len().next_power_of_two();
    while level.len() < n {
        level.push(pad);
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(merkle_node_hash(&pair[0], &pair[1]));
        }
        level = next;
    }
    level[0]
}

// ---- Public-input hygiene ------------------------------------------------

/// Length / bound checks on host ABI public inputs.
pub fn public_inputs_well_formed(
    msg: &[u8],
    membership_root: &[u8],
    pseudo_commitment: &[u8],
    key_image: &[u8],
    proof: &[u8],
) -> bool {
    msg.len() == 32
        && membership_root.len() == 32
        && pseudo_commitment.len() == 32
        && key_image.len() == 32
        && proof.len() <= MAX_FCMP_PROOF_BYTES as usize
}

/// True if `proof` uses the debug transparent-path tag (D17 reject).
pub fn looks_like_transparent_path_encoding(proof: &[u8]) -> bool {
    proof.len() >= TRANSPARENT_PATH_DEBUG_TAG.len()
        && &proof[..TRANSPARENT_PATH_DEBUG_TAG.len()] == TRANSPARENT_PATH_DEBUG_TAG
}

// ---- Proof codec (FCMP0001) ----------------------------------------------

/// One admitted output in the mature-set ring.
#[derive(Clone, Debug)]
pub struct RingMember {
    pub one_time_key: [u8; 32],
    pub commitment: [u8; 32],
    /// Global tree slot index for this leaf (digest position).
    pub tree_index: u64,
}

/// Decoded interim proof.
#[derive(Clone, Debug)]
pub struct FcmpProof {
    pub digests: Vec<[u8; 32]>,
    pub ring: Vec<RingMember>,
    pub clsag: Vec<u8>,
}

impl FcmpProof {
    /// Encode to host proof bytes.
    pub fn encode(&self) -> Option<Vec<u8>> {
        let n_slots = self.digests.len();
        let n_ring = self.ring.len();
        if n_slots == 0
            || n_slots > MAX_FCMP_ANON_SET as usize
            || n_ring == 0
            || n_ring > MAX_FCMP_RING
            || n_ring > n_slots
        {
            return None;
        }
        let sig_len = 32 * (n_ring + 2);
        if self.clsag.len() != sig_len {
            return None;
        }
        // tag(8) + slots(8) + digests + ring_n(4) + ring*(64+8) + clsag
        let mut out = Vec::with_capacity(8 + 8 + n_slots * 32 + 4 + n_ring * 72 + sig_len);
        out.extend_from_slice(PROOF_TAG);
        out.extend_from_slice(&(n_slots as u64).to_le_bytes());
        for d in &self.digests {
            out.extend_from_slice(d);
        }
        out.extend_from_slice(&(n_ring as u32).to_le_bytes());
        for m in &self.ring {
            out.extend_from_slice(&m.one_time_key);
            out.extend_from_slice(&m.commitment);
            out.extend_from_slice(&m.tree_index.to_le_bytes());
        }
        out.extend_from_slice(&self.clsag);
        if out.len() > MAX_FCMP_PROOF_BYTES as usize {
            return None;
        }
        Some(out)
    }

    /// Decode from host proof bytes.
    pub fn decode(proof: &[u8]) -> Option<Self> {
        if proof.len() < 8 + 8 + 4 + 72 + 32 * 3 {
            return None;
        }
        if &proof[..8] != PROOF_TAG {
            return None;
        }
        let mut o = 8usize;
        let n_slots = u64::from_le_bytes(proof.get(o..o + 8)?.try_into().ok()?) as usize;
        o += 8;
        if n_slots == 0 || n_slots > MAX_FCMP_ANON_SET as usize {
            return None;
        }
        let digests_end = o.checked_add(n_slots.checked_mul(32)?)?;
        if proof.len() < digests_end + 4 {
            return None;
        }
        let mut digests = Vec::with_capacity(n_slots);
        for chunk in proof[o..digests_end].chunks_exact(32) {
            let mut d = [0u8; 32];
            d.copy_from_slice(chunk);
            digests.push(d);
        }
        o = digests_end;
        let n_ring = u32::from_le_bytes(proof.get(o..o + 4)?.try_into().ok()?) as usize;
        o += 4;
        if n_ring == 0 || n_ring > MAX_FCMP_RING || n_ring > n_slots {
            return None;
        }
        let ring_bytes = n_ring.checked_mul(72)?;
        let ring_end = o.checked_add(ring_bytes)?;
        if proof.len() < ring_end {
            return None;
        }
        let mut ring = Vec::with_capacity(n_ring);
        for chunk in proof[o..ring_end].chunks_exact(72) {
            let mut p = [0u8; 32];
            let mut c = [0u8; 32];
            p.copy_from_slice(&chunk[..32]);
            c.copy_from_slice(&chunk[32..64]);
            let tree_index = u64::from_le_bytes(chunk[64..72].try_into().ok()?);
            ring.push(RingMember {
                one_time_key: p,
                commitment: c,
                tree_index,
            });
        }
        o = ring_end;
        let sig_len = 32 * (n_ring + 2);
        if proof.len() != o + sig_len {
            return None;
        }
        let clsag = proof[o..].to_vec();
        Some(Self {
            digests,
            ring,
            clsag,
        })
    }

    fn ring_blob(&self) -> Vec<u8> {
        let mut blob = Vec::with_capacity(self.ring.len() * 64);
        for m in &self.ring {
            blob.extend_from_slice(&m.one_time_key);
            blob.extend_from_slice(&m.commitment);
        }
        blob
    }
}

// ---- Prove / verify ------------------------------------------------------

/// Witness for proving a spend of one admitted leaf in a fixed tree.
pub struct ProveWitness {
    /// Full leaf digests `0..tree_slots` (EMPTY or L), matching chain tree.
    pub digests: Vec<[u8; 32]>,
    /// All admitted members as `(tree_index, P, C)`, sorted by `tree_index`.
    pub admitted: Vec<RingMember>,
    /// Position of the real spend inside `admitted`.
    pub real_index: usize,
    pub secret_key: [u8; 32],
    pub input_blinding: [u8; 32],
    pub pseudo_blinding: [u8; 32],
}

/// Result of [`prove`].
pub struct ProveResult {
    pub proof: Vec<u8>,
    pub key_image: [u8; 32],
    pub pseudo_commitment: [u8; 32],
}

/// Build an FCMP0001 proof for `msg` under the Merkle root of `witness.digests`.
pub fn prove(msg: &[u8; 32], witness: &ProveWitness) -> Option<ProveResult> {
    let n_slots = witness.digests.len();
    let n_ring = witness.admitted.len();
    if n_slots == 0
        || n_slots > MAX_FCMP_ANON_SET as usize
        || n_ring == 0
        || n_ring > MAX_FCMP_RING
        || witness.real_index >= n_ring
    {
        return None;
    }

    // Every non-EMPTY digest must appear exactly once in the admitted ring.
    let empty = empty_leaf_hash();
    let mut non_empty = 0usize;
    for (i, d) in witness.digests.iter().enumerate() {
        if *d != empty {
            non_empty += 1;
            let m = witness
                .admitted
                .iter()
                .find(|m| m.tree_index as usize == i)?;
            if leaf_hash(&m.one_time_key, &m.commitment) != *d {
                return None;
            }
        }
    }
    if non_empty != n_ring {
        return None;
    }
    // Admitted list strictly increasing by tree index.
    for w in witness.admitted.windows(2) {
        if w[0].tree_index >= w[1].tree_index {
            return None;
        }
    }

    let mut ring_blob = Vec::with_capacity(n_ring * 64);
    for m in &witness.admitted {
        ring_blob.extend_from_slice(&m.one_time_key);
        ring_blob.extend_from_slice(&m.commitment);
    }

    let clsag = clsag::sign_with_max(
        msg,
        &ring_blob,
        witness.real_index,
        &witness.secret_key,
        &witness.input_blinding,
        &witness.pseudo_blinding,
        MAX_FCMP_RING,
    )?;

    let proof = FcmpProof {
        digests: witness.digests.clone(),
        ring: witness.admitted.clone(),
        clsag: clsag.signature,
    };
    let bytes = proof.encode()?;
    Some(ProveResult {
        proof: bytes,
        key_image: clsag.key_image,
        pseudo_commitment: clsag.pseudo_commitment,
    })
}

/// Verify one FCMP+SA+L proof (host `verify_fcmp_v1` body).
pub fn verify(
    msg: &[u8],
    membership_root: &[u8],
    pseudo_commitment: &[u8],
    key_image: &[u8],
    proof: &[u8],
) -> bool {
    if !public_inputs_well_formed(msg, membership_root, pseudo_commitment, key_image, proof) {
        return false;
    }
    // D17: transparent paths are never valid.
    if looks_like_transparent_path_encoding(proof) {
        return false;
    }
    let Some(parsed) = FcmpProof::decode(proof) else {
        return false;
    };

    // 5a — membership: digests commit to the public root.
    let root = root_from_leaves(&parsed.digests);
    if root.as_slice() != membership_root {
        return false;
    }

    let empty = empty_leaf_hash();
    let n_slots = parsed.digests.len();
    let mut non_empty = 0usize;
    for d in &parsed.digests {
        if *d != empty {
            non_empty += 1;
        }
    }
    if non_empty != parsed.ring.len() || parsed.ring.is_empty() {
        return false;
    }

    // Ring members are exactly the non-EMPTY leaves (full mature set).
    let mut seen = alloc::collections::BTreeSet::new();
    for m in &parsed.ring {
        let idx = m.tree_index as usize;
        if idx >= n_slots || !seen.insert(m.tree_index) {
            return false;
        }
        let lh = leaf_hash(&m.one_time_key, &m.commitment);
        if parsed.digests[idx] != lh || lh == empty {
            return false;
        }
    }
    // Strictly increasing tree indices (canonical ring order).
    for w in parsed.ring.windows(2) {
        if w[0].tree_index >= w[1].tree_index {
            return false;
        }
    }
    // No non-EMPTY digest left out of the ring.
    for (i, d) in parsed.digests.iter().enumerate() {
        if *d != empty && !seen.contains(&(i as u64)) {
            return false;
        }
    }

    // 5b/5c — SA + linkability + re-blind via CLSAG.
    let ring_blob = parsed.ring_blob();
    let mut msg32 = [0u8; 32];
    msg32.copy_from_slice(msg);
    if !clsag::verify_with_max(
        &msg32,
        &ring_blob,
        pseudo_commitment,
        key_image,
        &parsed.clsag,
        MAX_FCMP_RING,
    ) {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clsag;
    use crate::native::{commit, random_blinding, random_secret_key};

    fn build_tree_and_spend(
        n_slots: usize,
        admitted_mask: &[bool],
        real_slot: usize,
        amount: u64,
    ) -> ([u8; 32], ProveWitness, [u8; 32]) {
        assert_eq!(admitted_mask.len(), n_slots);
        assert!(admitted_mask[real_slot]);
        let empty = empty_leaf_hash();
        let mut digests = vec![empty; n_slots];
        let mut admitted = Vec::new();
        let mut real_secret = [0u8; 32];
        let mut real_blinding = [0u8; 32];
        let mut real_pos = 0usize;

        for i in 0..n_slots {
            if !admitted_mask[i] {
                continue;
            }
            let (sk, pk) = random_secret_key();
            let blinding = if i == real_slot {
                real_secret = sk;
                real_blinding = random_blinding();
                real_pos = admitted.len();
                real_blinding
            } else {
                let _ = sk;
                random_blinding()
            };
            let c = commit(amount + i as u64, &blinding).unwrap();
            digests[i] = leaf_hash(&pk, &c);
            admitted.push(RingMember {
                one_time_key: pk,
                commitment: c,
                tree_index: i as u64,
            });
        }

        let root = root_from_leaves(&digests);
        let witness = ProveWitness {
            digests,
            admitted,
            real_index: real_pos,
            secret_key: real_secret,
            input_blinding: real_blinding,
            pseudo_blinding: random_blinding(),
        };
        (root, witness, real_secret)
    }

    #[test]
    fn prove_verify_roundtrip_sparse_tree() {
        let msg = [9u8; 32];
        // slots: EMPTY, L, L, EMPTY, L  — mature set size 3
        let mask = [false, true, true, false, true];
        let (root, witness, sk) = build_tree_and_spend(5, &mask, 2, 1000);
        let res = prove(&msg, &witness).expect("prove");
        assert!(verify(
            &msg,
            &root,
            &res.pseudo_commitment,
            &res.key_image,
            &res.proof
        ));
        // KI KAT vs clsag
        assert_eq!(res.key_image, clsag::key_image(&sk).unwrap());
    }

    #[test]
    fn full_admitted_set_sizes() {
        let msg = [3u8; 32];
        for n in [1usize, 4, 16, 32] {
            let mask = vec![true; n];
            let (root, witness, _) = build_tree_and_spend(n, &mask, n / 2, 42);
            let res = prove(&msg, &witness).expect("prove");
            assert!(
                res.proof.len() <= MAX_FCMP_PROOF_BYTES as usize,
                "n={n} proof {} bytes",
                res.proof.len()
            );
            assert!(verify(
                &msg,
                &root,
                &res.pseudo_commitment,
                &res.key_image,
                &res.proof
            ));
        }
    }

    #[test]
    fn rejects_wrong_root() {
        let msg = [1u8; 32];
        let mask = [true, true, true];
        let (root, witness, _) = build_tree_and_spend(3, &mask, 0, 7);
        let res = prove(&msg, &witness).unwrap();
        let mut bad_root = root;
        bad_root[0] ^= 1;
        assert!(!verify(
            &msg,
            &bad_root,
            &res.pseudo_commitment,
            &res.key_image,
            &res.proof
        ));
    }

    #[test]
    fn rejects_tampered_clsag() {
        let msg = [2u8; 32];
        let mask = [true, true];
        let (root, witness, _) = build_tree_and_spend(2, &mask, 1, 9);
        let mut res = prove(&msg, &witness).unwrap();
        let last = res.proof.len() - 1;
        res.proof[last] ^= 0xff;
        assert!(!verify(
            &msg,
            &root,
            &res.pseudo_commitment,
            &res.key_image,
            &res.proof
        ));
    }

    #[test]
    fn d17_transparent_path_tag_rejected() {
        let (msg, root, c, i) = ([0u8; 32], [1u8; 32], [2u8; 32], [3u8; 32]);
        let mut proof = TRANSPARENT_PATH_DEBUG_TAG.to_vec();
        proof.extend_from_slice(&[0u8; 40]);
        assert!(looks_like_transparent_path_encoding(&proof));
        assert!(!verify(&msg, &root, &c, &i, &proof));
    }

    #[test]
    fn rejects_incomplete_mature_set() {
        // Prove with full set then drop a ring member from encoding — decode path.
        let msg = [4u8; 32];
        let mask = [true, true, true];
        let (root, witness, _) = build_tree_and_spend(3, &mask, 0, 1);
        let res = prove(&msg, &witness).unwrap();
        let mut parsed = FcmpProof::decode(&res.proof).unwrap();
        parsed.ring.pop(); // incomplete set
                           // re-sign would be needed; just re-encode incomplete → verify fails set check
                           // clsag length won't match — decode encode with truncated ring needs new clsag
        let mut bad = parsed;
        bad.clsag = vec![0u8; 32 * (bad.ring.len() + 2)];
        let bytes = bad.encode().unwrap();
        assert!(!verify(
            &msg,
            &root,
            &res.pseudo_commitment,
            &res.key_image,
            &bytes
        ));
    }

    #[test]
    fn rejects_wrong_public_lengths() {
        let (msg, root, c, i) = ([0u8; 32], [1u8; 32], [2u8; 32], [3u8; 32]);
        let proof = [0u8; 32];
        assert!(!verify(&msg[..31], &root, &c, &i, &proof));
    }

    #[test]
    fn rejects_oversized_proof() {
        let (msg, root, c, i) = ([0u8; 32], [1u8; 32], [2u8; 32], [3u8; 32]);
        let proof = vec![0u8; MAX_FCMP_PROOF_BYTES as usize + 1];
        assert!(!verify(&msg, &root, &c, &i, &proof));
    }

    #[test]
    fn root_matches_pallet_style_empty() {
        assert_eq!(root_from_leaves(&[]), merkle_empty_child());
        assert_ne!(empty_leaf_hash(), merkle_empty_child());
    }
}
