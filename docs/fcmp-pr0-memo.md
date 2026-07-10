# PR-0 — FCMP research spike go/no-go memo

| Field | Value |
|---|---|
| **Title** | FCMP curve/tree spike and go/no-go |
| **Date** | 2026-07-10 |
| **Status** | Complete (spike code + gates; Path B membership **not** implemented) |
| **Design** | [`docs/fcmp-design.md`](fcmp-design.md) PR-0 |
| **Code** | `ringct-crypto` feature `fcmp-spike` (`src/fcmp_spike/`) |
| **Consensus impact** | **None** — no pallet/host/runtime wiring |

---

## 1. Executive recommendation

| Path | Role | PR-0 verdict |
|---|---|---|
| **Path A — blake2 sparse Merkle (maintenance)** | Tree grow / admit / root | **PASS** — implementable, runtime-cheap, matches design domains |
| **Path A — ZK-IPA membership over blake2 path (A5)** | Membership `π` | **NOT SPIKED** — composition risk remains the dominant A5 cost (D17 forbids transparent paths) |
| **Path B — Curve Trees + cycle (headline)** | Membership + future SA+L | **NO-GO for freeze** under strict D2 with *current* literature numbers + missing embedding |
| **Naive full-set CLSAG** | “Just use huge rings” | **REJECT** — linear size/time; fails long before full-chain scale |

**Recommended next step (PR-0b — done in design rev 6):**

1. **Freeze Path A leaf/Merkle domains** for tree *maintenance* storage (PR-1 can land without a membership prover).
2. **Pre-launch FCMP-only:** no Dual; mainnet genesis is FcmpOnly; throwaway re-genesis instead of CLSAG history migration ([`fcmp-design.md`](fcmp-design.md) rev 6).
3. **Do not freeze Path B leaf encoding** until a host-native cycle/FCMP composition is re-spiked against D2 (or D2 verify gate is revised).
4. Track Monero `fcmp-plus-plus` / `fcmp-ringct` as **algorithm references only** (license + Ristretto rewrite; no byte import).

Honest bottom line: PR-0 **unblocks tree scaffolding**; it does **not** unlock mainnet FcmpOnly (crypto + D14 still required). Dual is **out of scope**.

---

## 2. What was built

```text
primitives/ringct-crypto/src/fcmp_spike/
  leaf.rs          Path A domains + L/EMPTY/node hashes (blake2_256)
  merkle.rs        Sparse tree: lag-aware grow, admit, root, transparent path
  sa_link.rs       KI KAT vs clsag::key_image; open re-blind; D17 reject path
  embedding.rs     Path B embedding notes; literature gates; MSM proxy
  gates.rs         D2 evaluate_gates()
  naive_fullset.rs CLSAG linear cost model + baseline measure
benches/fcmp_spike.rs
```

### Commands

```bash
# Unit tests (including KATs)
cargo test -p ringct-crypto --features fcmp-spike

# Micro-benchmarks (feed §4)
cargo bench -p ringct-crypto --features fcmp-spike --bench fcmp_spike
```

---

## 3. D2 gates (design)

| Gate | Threshold |
|---|---|
| Prove (laptop) | ≤ 30 s / input |
| Verify (native) | ≤ 25 ms / input |
| Proof size | ≤ 16 KiB / input |
| Trusted setup | **none** |
| Embedding memo | required for Path B |

Code: `fcmp_spike::gates::D2_GATES` + `evaluate_gates`.

---

## 4. Measurements

### 4.1 Path A — tree maintenance (this crate)

Criterion `--quick` on a laptop-class host (2026-07-10). Re-run with
`cargo bench -p ringct-crypto --features fcmp-spike --bench fcmp_spike` for local numbers.

| Operation | N | Wall time (approx) | Per-leaf |
|---|---:|---:|---:|
| `grow_empty` × N + root | 64 | ~25 µs | ~0.4 µs |
| `grow_empty` × N + root | 4 096 | ~1.6 ms | ~0.4 µs |
| grow + admit all + root | 64 | ~7.3 ms | ~110 µs (incl. keygen/commit in bench) |
| grow + admit all + root | 4 096 | ~455 ms | ~110 µs |
| `root()` only | 1 024 | ~202 µs | — |
| `root()` only | 16 384 | ~3.2 ms | O(N) full recompute |
| transparent path + recompute | 4 096 | ~0.8 ms | depth ≈ 12 |

Notes:

* Admit bench includes `random_secret_key` + `commit` per leaf — **not** pure hash cost; still ≪ 1 ms/leaf for runtime budgets once keys are already on chain.
* Spike `root()` is O(N) full rebuild; PR-1 should keep a frontier/peaks structure for O(log N) updates.
* Transparent path **size** ≈ `8+32+4+32·depth` bytes (~300–400 B) — cheap but **invalid as `π`**.

**Gate relevance:** Maintenance cost is **not** the D2 membership proof gate. It is low enough for pure-runtime blake2 updates (D12 Path A).

**D17:** `reject_transparent_path_as_proof` always returns `false`. Transparent paths remain available only for tree correctness tests. They must never be accepted as `π`.

### 4.2 SA+L sketch (open checks)

| Check | Result |
|---|---|
| `sa_link_key_image(sk) == clsag::key_image(sk)` | **PASS** (KAT) |
| Open re-blind `C − C' = z·G` | **PASS** when amounts match |
| Transparent path as `π` | **Always rejected** |

Full ZK composition of membership ⊕ SA+L is **out of scope** for PR-0 (PR-5a–5c).

### 4.3 Naive full-set CLSAG (why not huge rings)

CLSAG signature size = `32 × (n + 2)` bytes. Verify ≈ linear in `n`.

Measured CLSAG sign+verify pair at `n = 16` (bench `fcmp_clsag_baseline_sign_verify_pair`):
**~15.3 ms** total. Splitting roughly evenly ⇒ **Tᵥ ≈ 5–8 ms** verify / **Tₛ ≈ 7–10 ms** sign
(order-of-magnitude; use `measure_clsag_baseline` for a cleaner split).

| n | Sig size | Verify (extrapolated @ Tᵥ≈6 ms) | D2 size | D2 verify (≤25 ms) |
|---:|---:|---:|---|---|
| 16 | 576 B | ~6 ms | OK | OK |
| 256 | 8.25 KiB | ~96 ms | OK | **FAIL** |
| 1024 | 32.1 KiB | ~384 ms | **FAIL** | **FAIL** |
| 10⁶ | ~30.5 MiB | ~minutes | **FAIL** | **FAIL** |

**Conclusion:** Full-chain anonymity via CLSAG is structurally impossible at cash-chain scale. Log-size membership (Curve Trees or ZK-Merkle) is mandatory.

### 4.4 Path B — literature vs D2

Anchors (order-of-magnitude; **not** re-implemented here):

| Metric | Literature (early FCMP++ / Curve Trees notes) | D2 | Pass? |
|---|---:|---:|---|
| Prove | ~seconds (order 1–30 s band) | ≤ 30 s | **Likely** |
| Verify | **~35 ms** / proof (public Kayaba notes) | ≤ 25 ms | **FAIL** (strict) |
| Proof size | ~2–3 KiB | ≤ 16 KiB | **PASS** |
| Trusted setup | No | No | **PASS** |
| Ristretto embedding | Not in Monero stack | Memo required | **FAIL** (not done) |

`PathBAssessment::evaluate()` encodes this: **overall `passed = false`**.

MSM proxy benches (`fcmp_msm_proxy_ristretto`) only bound EC work on Ristretto; they are **not** Curve Trees proofs.

| MSM size (Ristretto VBasemul) | Time (quick bench) |
|---:|---:|
| 16 | ~0.9 ms |
| 64 | ~3.6 ms |
| 256 | ~14 ms |
| 1024 | ~55 ms |

Interpretation: a membership proof whose dominant cost is O(10²–10³) MSMs can sit near or above the 25 ms verify gate — consistent with literature ~35 ms for early Curve Trees work.

### 4.5 Path A membership (ZK-IPA over blake2)

**Not implemented.** Reasons recorded for PR-0b:

* Transparent path is cheap but **forbidden** as `π` (D17).
* blake2 inside an IPA/Bulletproof circuit is heavy (bit-decomposed hash) — likely to miss D2 prove/verify without algebraic hashes or a different tree.
* A5 remains the **documented fallback** if Path B never clears gates; it needs its own spike (PR-0 extension or PR-5a research), not a silent “Merkle path” ship.

---

## 5. Embedding security memo (sketch)

For Path B, occupied leaves must map Ristretto `(P, C)` into the cycle leaf type:

1. **Preimage** — same as Path A: `LEAF_DOM || P || C` (`kohl/fcmp/leaf/v1`).
2. **Hash-to-field / hash-to-curve** on the *cycle* group with domain separation; reject non-canonical compressed Ristretto before embed.
3. **EMPTY** — fixed distinct cycle element from `EMPTY_LEAF_DOM` (not the zero point if that is spendable).
4. **No trapdoors** — cycle generators NUMS; no known DL vs Ristretto `G`/`H`.
5. **Injectivity / collisions** — prefer injective encoding into field elements or collision-hardened hash with security proof note.

**Status:** Notes only (`EmbeddingSketch`). **Not** sufficient to set `embedding_memo_ok = true` for Dual.

### External references (evaluation only)

| Artifact | Use | Import into consensus? |
|---|---|---|
| [fcmp-ringct](https://github.com/kayabaNerve/fcmp-ringct) | Algorithm / composition reference | **No** |
| [fcmp-plus-plus](https://github.com/kayabaNerve/fcmp-plus-plus) | Crypto crates reference | **No** (license + curve mismatch) |
| monero-oxide / monero-serai | Wallet/tx patterns | **No** byte compatibility |
| Curve Trees eprint 2022/756 | Theory | Cite |
| Eagen divisors eprint 2022/596 | Theory | Cite |
| Monero FCMP blog 2024-04-27 | Roadmap context | Cite |

Kohl is **Ristretto + own domains** — any reuse is a **rewrite**, not a vendor.

**License:** Before any code copy, legal review of MIT/Apache vs GPL-adjacent Monero crates. Prefer clean-room from papers + audited interfaces.

---

## 6. Go / no-go matrix

| Decision | Result | Action |
|---|---|---|
| Path A tree domains (`leaf` / `EMPTY` / `merkle`) | **GO** | Freeze in PR-0b; use in PR-1 storage |
| Path A transparent path as `π` | **NO-GO** | Negative KAT forever |
| Path A full ZK membership | **DEFER** | PR-5a research; not PR-1 blocker |
| Path B membership freeze | **NO-GO** | Need cycle spike + embedding + re-bench |
| Dual mode | **OUT OF SCOPE** | Pre-launch FCMP-only policy (design rev 6) |
| Mainnet FcmpOnly | **GO (encoding freeze PR-10)** | FCMP0001 n≤64; external audit → PR-11; Path B still open |
| Naive full-set CLSAG | **NO-GO** | Cost model |
| PR-0b Path A maintenance freeze + no Dual | **GO** | Design rev 6 |

---

## 7. Proposed PR-0b freezes (for design amend)

Freeze **now** (maintenance only):

```text
LEAF_DOM            = b"kohl/fcmp/leaf/v1"
EMPTY_LEAF_DOM      = b"kohl/fcmp/leaf/empty/v1"
MERKLE_DOM          = b"kohl/fcmp/merkle/v1"
MERKLE_EMPTY_DOM    = b"kohl/fcmp/merkle/v1/empty"
leaf_hash           = blake2_256(LEAF_DOM || P || C)
EMPTY               = blake2_256(EMPTY_LEAF_DOM)
node                = blake2_256(MERKLE_DOM || left || right)
EMPTY_MEMBERSHIP_ROOT = blake2_256(MERKLE_EMPTY_DOM)   # TreeSlots = 0
arity               = 2
root storage        = [u8; 32]
append locus        = pure runtime (Path A maintenance)
```

**Explicitly do not freeze:**

* Path B cycle choice, arity, root blob width  
* `MAX_FCMP_PROOF_BYTES` final (keep provisional 12 KiB from design D15)  
* `verify_fcmp_v1` ABI semantics beyond “reject transparent path”  
* Dual activation heights  

Optional design amend note: consider revising D2 verify gate from 25 ms → **40 ms** if Path B is retained as headline after measured kohl reimplementation — **only** with written rationale (Monero-class ~35 ms).

---

## 8. Risks carried forward

| Risk | Severity | Mitigation |
|---|---|---|
| Path B never meets D2 verify on kohl hardware | High | A5 ZK-Merkle research; or gate revision |
| A5 blake2-in-circuit too slow | High | Algebraic hash tree; or Path B |
| Embedding trapdoor / non-canonical leaks | Critical | Full memo + audit before Dual |
| Premature Dual with stub verify | Critical | D14 gates; host stub returns false |
| O(N) root recompute at large N | Medium | Frontier / peaks in PR-1 |

---

## 9. Checklist (PR-0 acceptance)

- [x] Feature-gated spike module (no consensus wiring)
- [x] Path A leaf + sparse Merkle + tests (incl. lag grow, sparse admit)
- [x] D17 transparent path rejection helper + test
- [x] KI KAT vs `clsag::key_image`
- [x] Path B embedding notes + literature gate evaluation
- [x] Naive full-set cost model
- [x] Criterion bench target `fcmp_spike`
- [x] This go/no-go memo
- [ ] Path B cycle prove/verify implementation — **out of scope**
- [ ] Path A ZK-IPA membership — **out of scope**

---

## 10. References

* `docs/fcmp-design.md` — D2, D11–D17, PR plan  
* `BLUEPRINT.md` §9.2–9.3  
* Monero: [Full-Chain Membership Proofs Development](https://www.getmonero.org/2024/04/27/fcmps.html)  
* Curve Trees: eprint 2022/756  
* Eagen divisors: eprint 2022/596  
