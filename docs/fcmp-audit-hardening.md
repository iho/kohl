# FCMP post-freeze hardening (PR-11)

| Field | Value |
|---|---|
| **Title** | Audit-oriented hardening, fuzz, docs (rings → FCMP) |
| **Date** | 2026-07-10 |
| **Depends** | PR-10 encoding freeze + [`fcmp-composition-memo.md`](fcmp-composition-memo.md) |
| **Status** | **Internal hardening complete.** Independent external audit still recommended before social mainnet. |

This is the PR-11 deliverable: close the composition-memo handoff checklist with code and tests, add FCMP fuzz surface, and rewrite operator-facing docs so production privacy is **FCMP-only** (not ring-16 + decoys).

---

## 1. Composition-memo checklist (closed)

| Item | Evidence |
|------|----------|
| Re-read `fcmp.rs` prove/verify + CLSAG `verify_with_max` | Internal review recorded in composition memo; hardening tests below |
| D17 transparent path KATs | `fcmp::tests::d17_transparent_path_tag_rejected`; fuzz path with `TRPATH01` |
| KI KAT: fcmp KI == `clsag::key_image` | `fcmp::tests::prove_verify_roundtrip_sparse_tree` |
| Root rebuild domains match pallet | `mainnet_invariants::membership_leaf_digest_matches_host_fcmp`; `path_a_domains_match_primitives_freeze` |
| Weight vs n=64 / 4 inputs | PR-6 weights + `machine_merge` / `transfer_fcmp` unit tests; freeze block budget test |
| No CLSAG ring extrinsic | `FcmpInput` only; invariants + authorize path uses `verify_fcmp_v1` |
| Wallet no production decoys | PR-8; `legacy-decoy` feature off by default |

### Hardening changes in this PR

1. **Host point hygiene** — `verify_fcmp_v1` rejects non-canonical / identity `I` and `C'` before CLSAG (defense in depth; pallet already checked).
2. **Domain freeze tests** — host + pallet leaf digests must match primitives domains.
3. **Fuzz target** — `fuzz/fuzz_targets/fcmp_verify.rs` (garbage + mutated valid proofs + D17 tag).
4. **Docs** — `BLUEPRINT.md`, `GLOSSARY.md`, `README.md` production path is FCMP.

---

## 2. Fuzz surface

```bash
# Requires nightly + cargo-fuzz
cargo install cargo-fuzz
cargo +nightly fuzz run fcmp_verify
cargo +nightly fuzz run clsag_verify      # still useful: FCMP0001 SA+L uses CLSAG
cargo +nightly fuzz run transfer_decode   # SCALE TransferTx (FCMP layout)
```

| Target | Goal |
|--------|------|
| `fcmp_verify` | No panic; garbage/mutated proofs → false |
| `clsag_verify` | SA+L building block remains panic-free |
| `transfer_decode` | Arbitrary extrinsic bytes decode without panic |

CI does not run libFuzzer by default (nightly + long runtime). Keep targets compiling with the workspace.

---

## 3. Residual risks (honest — external audit scope)

| Risk | Severity | Notes |
|------|----------|-------|
| FCMP0001 composition soundness (glue) | Critical | Internal review only; external pass recommended |
| CLSAG / BP library soundness | Critical | Inherited stack; re-audit if versions change |
| n ≤ 64 scale limit | Product | Path B / Curve Trees not shipped |
| Host ABI serialization consensus | High | Fuzz + freeze docs; version `*_v1` discipline |
| Network / timing metadata | Medium | Dandelion++ + Tor runbooks; not crypto |

**Do not claim “audit complete”** until at least one independent review of:

- `primitives/ringct-crypto/src/fcmp.rs`
- Host interface in `ringct-crypto` `RingctCrypto`
- `pallet-ringct` `verify_transfer` / authorize
- Domain constants in `ringct-primitives`

---

## 4. Doc migration (rings → FCMP)

| Doc | Change |
|-----|--------|
| `BLUEPRINT.md` | Pillars, types, wallet, risks: FCMP-only production |
| `GLOSSARY.md` | Life of a transfer, FAQ, acronyms: FCMP primary |
| `README.md` | Status table FCMP + fuzz |
| Design `fcmp-design.md` | PR-11 ✅ |

Historical CLSAG ring-16 text is retained only where it describes **Phase 3 history** or **FCMP0001 internal SA+L**.

---

## 5. Operator one-liner

Production kohl spends prove **full mature-set membership** under the Path A Merkle root (`FCMP0001`, interim n≤64), not a wallet-chosen ring of 16. Key images, stealth, and Bulletproofs are unchanged.
