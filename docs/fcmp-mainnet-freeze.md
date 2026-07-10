# Mainnet encoding freeze (PR-10)

| Field | Value |
|---|---|
| **Title** | Mainnet FcmpOnly encoding freeze + D14 artifact index |
| **Date** | 2026-07-10 |
| **Status** | **Encoding frozen** for mainnet-candidate FCMP0001; external audit deferred to PR-11 |
| **Policy** | Pre-launch FCMP-only; **no Dual**; re-genesis over migration |
| **Companion** | [`fcmp-design.md`](fcmp-design.md) D14 / D18; [`fcmp-runbook.md`](fcmp-runbook.md) |

This document is the **named freeze record** for PR-10. Changing any item in §2 without a coordinated hard fork (new `spec_version` / `transaction_version` and host matrix row) is a consensus split.

---

## 1. D14 artifact index

| # | Artifact | Location | Status |
|---|----------|----------|--------|
| 1 | Composition review memo | [`fcmp-composition-memo.md`](fcmp-composition-memo.md) | **Done (internal)** — interim FCMP0001; **not** external audit |
| 2 | FCMP weights merged | `pallets/ringct/src/weights.rs` (+ `weights_machine.rs`) | **Done (PR-6)** — CI runs weight unit tests |
| 3 | FCMP-only soak report | [`fcmp-soak-report.md`](fcmp-soak-report.md) | **Done (automated + procedure)** — multi-week public soak optional ops step |
| 4 | Invariant suite | `pallets/ringct` mainnet invariants + primitives freeze snapshot | **Done** — green in CI |
| 5 | Encoding freeze (this doc) | §2 | **Done** |
| 6 | Host capability matrix | `node/src/fcmp_capability.rs`, runbook §2 | **Done (PR-9)** |

### Honest residual gates (not blocking this freeze, block “unlimited-set mainnet marketing”)

| Residual | Severity | Tracked in |
|----------|----------|------------|
| External crypto audit of FCMP0001 composition | Critical for social launch confidence | Hardening done (PR-11); **external** review still open |
| Anonymity set n ≤ 64 (O(n) proof) | Product / scale | Path B / Curve Trees research |
| Live multi-node adversarial soak duration | Ops confidence | soak report § live procedure |

---

## 2. Frozen encoding inventory

### 2.1 Runtime identity

| Item | Frozen value |
|------|----------------|
| `spec_name` | `"kohl"` |
| `spec_version` | `1` |
| `transaction_version` | `1` |
| `authoring_version` | `1` |
| Min node package (host matrix) | `0.1.0` |

Bump `spec_version` for state-transition rule changes; bump `transaction_version` for extrinsic encoding changes that wallets must notice.

### 2.2 Spend path

| Item | Frozen value |
|------|----------------|
| Mode | **FcmpOnly only** (`fcmp_mode() == 2`) |
| Dual / CLSAG transfer extrinsic | **Absent** — no height matrix |
| Extrinsic | `pallet_ringct::Call::transfer(TransferTx)` unsigned via `AuthorizeCall` |
| Signing domain | `b"kohl/transfer/v4"` (16 bytes) |
| Inputs | `FcmpInput { key_image, pseudo_commitment, fcmp_proof }` |
| Root | Single tx-level `membership_root: [u8; 32]` (D13) |
| Outputs | Unchanged stealth + Pedersen + payload layout |
| Fee | Public `u64` in balance equation |

### 2.3 Host ABI (consensus verify)

| Host fn | Role |
|---------|------|
| `verify_fcmp_v1` | Per-input membership + SA+L |
| `verify_balance_v1` | Σ C' == Σ C_out + fee·H |
| `verify_range_proof_v1` | Aggregated Bulletproof |
| `value_commitment_v1` | Coinbase amount → commitment |
| `is_valid_point_v1` | Point hygiene |

Do **not** change `*_v1` semantics; add `*_v2` on break. Matrix: runbook / `fcmp_capability.rs`.

### 2.4 Proof format (interim but frozen wire)

| Item | Frozen value |
|------|----------------|
| Proof tag | `b"FCMP0001"` |
| Transparent path tag (must reject) | `b"TRPATH01"` |
| `MAX_FCMP_PROOF_BYTES` | `12_288` |
| `MAX_FCMP_INPUTS` | `4` |
| `MAX_FCMP_ANON_SET` | `64` |

Raising `MAX_FCMP_ANON_SET` or changing `FCMP0001` layout is a **hard fork** (and usually a new proof tag).

### 2.5 Path A membership tree (maintenance — frozen since PR-0b)

| Item | Frozen value |
|------|----------------|
| `FCMP_LEAF_DOM` | `b"kohl/fcmp/leaf/v1"` |
| `FCMP_EMPTY_LEAF_DOM` | `b"kohl/fcmp/leaf/empty/v1"` |
| `FCMP_MERKLE_DOM` | `b"kohl/fcmp/merkle/v1"` |
| `FCMP_MERKLE_EMPTY_DOM` | `b"kohl/fcmp/merkle/v1/empty"` |
| Arity | 2 |
| Append locus | Pure runtime `blake2_256` |
| `FCMP_ADMIT_MAX_LEAVES_PER_BLOCK` | `64` |
| `FCMP_GROW_CATCHUP_MAX_PER_BLOCK` | `64` |
| `FCMP_ROOT_MAX_AGE_BLOCKS` | `64` |

### 2.6 Maturity & economics (runtime config)

| Item | Frozen value (mainnet runtime) |
|------|--------------------------------|
| `SpendableAge` | `10` blocks |
| `CoinbaseMaturity` | `60` blocks |
| `MinFeePerByte` | `1000` atomic units |
| Max block length | `300 * 1024` bytes |
| Genesis supply | `0` (fair launch) |
| Mainnet initial difficulty | `50_000_000` |
| Emission | `ringct_primitives::block_reward` curve + tail |

### 2.7 Explicitly **not** frozen for Path B / future

- Curve Trees / cycle choice / embedding
- Log-size membership prover beyond FCMP0001
- Seraphis / Jamtis addresses
- Batch verify host ABI
- Spent-leaf pruning (default: never)
- Post-launch legal emergency policy beyond “not Dual”

---

## 3. Mainnet genesis template

Built-in preset `mainnet` / CLI `--chain kohl`:

- Fair launch: zero balances, zero pre-mine
- FCMP-only spends from block 0
- Tree empty at genesis; grows on first coinbase/outputs
- **No** CLSAG history to migrate
- Difficulty: `50_000_000`

Export for miners: `scripts/make-chainspec.sh` (see `chainspecs/README.md`).

Social “genesis moment” is operational coordination only; the binary does not enforce a start time.

---

## 4. Re-genesis policy

| Network class | Policy |
|---------------|--------|
| Dev (`--dev`) | Wipe freely |
| `kohl-ash` / throwaway public test | Prefer **re-genesis** over Dual or CLSAG migration |
| Any chain that ever ran CLSAG rings | **Discard**; do not feed into mainnet history |
| Mainnet after social launch | Re-genesis is a product/legal decision; **not** a Dual HF. Host verify still requires node upgrade |

There is **no** supported path that accepts both CLSAG rings and FCMP spends on the same economic history.

---

## 5. CI assertions (invariant suite)

CI must keep green:

```text
cargo test -p ringct-primitives freeze
cargo test -p pallet-ringct mainnet_invariants
cargo test -p pallet-ringct --lib   # includes FCMP path + weights unit tests
cargo test -p kohl-node fcmp_capability
```

See `.github/workflows/ci.yml`.

---

## 6. Operator quick check before treating a chain as mainnet

1. Startup log: FcmpOnly, `verify_fcmp_v1` listed (PR-9)
2. RPC `fcmp_mode` → `2`
3. Node package ≥ matrix min for `spec_version`
4. Same chainspec / genesis hash on all seeds
5. Read composition memo residual risks (n≤64, audit pending)
6. Weights present (do not ship a custom runtime without `transfer_fcmp` weights)

---

## 7. Changelog of freeze

| Date | Event |
|------|--------|
| 2026-07-10 | PR-10: initial freeze for FCMP0001 mainnet-candidate |
