# FCMP composition review memo (D14 / PR-10)

| Field | Value |
|---|---|
| **Title** | Internal composition review — FCMP0001 + Path A tree + BP/balance |
| **Date** | 2026-07-10 |
| **Scope** | Interim production path in `ringct-crypto::fcmp` + `pallet-ringct` transfer |
| **Audience** | Operators, reviewers, auditors (PR-11 handoff) |
| **Status** | **Internal review complete** for encoding freeze. **Not** a substitute for external audit. |

References: [`fcmp-design.md`](fcmp-design.md) D1–D18, [`fcmp-pr0-memo.md`](fcmp-pr0-memo.md), [`fcmp-mainnet-freeze.md`](fcmp-mainnet-freeze.md).

---

## 1. Statement of the spend relation

A valid FCMP transfer input proves, under public `(msg, membership_root, C', I)` and proof `π`:

1. **Membership (full mature set at root):**  
   Digests `d[0..TreeSlots)` rebuild `membership_root` under Path A domains.  
   Non-EMPTY leaves form ring `R = {(P_j, C_j)}` with `|R| ≤ MAX_FCMP_ANON_SET` (64).  
   Each ring member’s `leaf_hash(P,C)` matches the digest at its tree index.

2. **Spend auth + linkability + re-blind (CLSAG SA+L):**  
   CLSAG over `R` on `msg` with pseudo-commitment `C'` and key image `I`.  
   Key image formula is identical to `clsag::key_image(sk)` (CryptoNote / design D4).

3. **Transparent paths forbidden (D17):**  
   Proofs tagged `TRPATH01` or open Merkle paths alone are never accepting.

Transaction-level (all inputs share one root):

4. **Balance:** `Σ C'_i == Σ C_out + fee·H` via `verify_balance_v1`.
5. **Range:** aggregated Bulletproof on outputs via `verify_range_proof_v1`.
6. **Double-spend:** `I` inserted into permanent `KeyImages` map; duplicates rejected.
7. **Maturity:** only non-EMPTY admitted leaves appear in the mature set; immature slots are EMPTY and cannot be opened as ring members.

---

## 2. Binding and domains

| Binding | Domain / mechanism |
|---------|-------------------|
| Tx message | `blake2_256(kohl/transfer/v4 ‖ root ‖ KIs ‖ C's ‖ outs ‖ R ‖ fee)` |
| Leaf | `blake2_256(kohl/fcmp/leaf/v1 ‖ P ‖ C)` |
| EMPTY leaf | `blake2_256(kohl/fcmp/leaf/empty/v1)` |
| Merkle node | `blake2_256(kohl/fcmp/merkle/v1 ‖ L ‖ R)` |
| Empty child | `blake2_256(kohl/fcmp/merkle/v1/empty)` |
| Proof tag | `FCMP0001` |
| BP transcript | `kohl/rangeproof/v1` (existing) |
| CLSAG internals | Existing CLSAG domains inside native verify |

**Review note:** Membership digests are inside `π` and bound to the root by reconstruction; CLSAG binds `msg` and ring. Output commitments are bound by balance + BP, not by FCMP membership (same class as Monero: membership/auth separate from amount range).

---

## 3. Threat analysis (summary)

| Threat | Verdict under FCMP0001 |
|--------|-------------------------|
| Spend non-member / immature output | Rejected — not in non-EMPTY ring / wrong root |
| Double spend | Key image map (same as CLSAG era design) |
| Forge amount / inflation | BP + balance (unchanged) |
| Reveal spent index among mature set | Hiding among full mature set at root (stronger than ring-16); **not** hiding among future outputs not yet admitted |
| Transparent path leak | Rejected (D17 KATs) |
| KI ≠ sk for claimed P | CLSAG soundness |
| Root stale / reorg race | `MembershipRootAt` window (`FCMP_ROOT_MAX_AGE_BLOCKS`) |
| Host/runtime skew | Matrix + node-first upgrade (PR-9) |
| Proof > block / DoS | Caps + weights (PR-6) |
| Composition gap (membership ⊕ SA+L) | **Interim composition** reuses CLSAG over full set under Merkle root — see §4 |

---

## 4. Composition residual risks (honest)

### 4.1 Scale — O(n) proof

FCMP0001 packs digests + full mature ring + CLSAG. Anonymity set and proof size grow with admitted leaves, hard-capped at **64**.  
**Not** Monero FCMP++ / Curve Trees scale. Shipping mainnet-candidate with this limit is intentional pre-launch honesty; Path B is future work.

### 4.2 Not Curve Trees SA+L

Headline design (D1) remains Curve-Trees-style membership. FCMP0001 is a **documented interim** that meets full-mature-set membership under Path A for small trees. External reviewers must not equate this with audited FCMP++.

### 4.3 No external audit yet

This memo is **internal**. Soundness of CLSAG + BP stack inherits prior review posture of those components; the **glue** (digest packing, ring extraction, root check, tag hygiene) needs independent audit (PR-11).

### 4.4 Proof malleability class

CLSAG bytes are outside `msg` (historical Monero-class property). Identity / tx hash consumers should use msg-bound fields (KIs, root, outs), not raw proof bytes alone.

### 4.5 Embedding / Path B

PR-0 Path B NO-GO stands. Do not claim cycle membership until embedding memo + D2 benches pass.

---

## 5. Positive properties retained

- Ristretto user keys, stealth receivers, Pedersen amounts, Bulletproofs
- CryptoNote key images shared forever (no nullifier migration)
- Unsigned self-authenticating transfers
- Fair-launch PoW; no Dual privacy hangover
- Host-function verification with versioned ABI

---

## 6. Reviewer checklist (PR-11 handoff)

Closed in [`fcmp-audit-hardening.md`](fcmp-audit-hardening.md). External auditors should still re-run:

- [x] Re-read `fcmp.rs` prove/verify and CLSAG `verify_with_max` (internal)
- [x] Confirm D17 negative KATs for transparent paths
- [x] KI KAT: `fcmp` key image == `clsag::key_image`
- [x] Root rebuild matches pallet `membership` domains exactly
- [x] Weight vs worst-case verify time under n=64, 4 inputs (engineered + unit tests)
- [x] Mempool authorize does not accept CLSAG ring extrinsics
- [x] Wallet never samples decoys on production path
- [ ] **External** independent audit sign-off (open)

---

## 7. Conclusion (D14 composition gate)

| Gate | Result |
|------|--------|
| Internal composition memo | **PASS** (this document) |
| Fit for encoding freeze / throwaway soak | **PASS** with n≤64 caveat |
| Fit for “audit-complete unlimited-set mainnet” marketing | **FAIL** until **external** audit + Path B (or explicit product accept of n≤64). Internal PR-11 hardening is done. |
| Dual | **N/A — out of scope** |

**Recommendation:** Freeze encoding (PR-10). Keep FCMP0001 as the only spend path. Schedule external audit and Path B research without re-opening Dual.
