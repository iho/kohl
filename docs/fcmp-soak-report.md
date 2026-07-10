# FCMP-only soak report (D14 / PR-10)

| Field | Value |
|---|---|
| **Title** | FCMP-only automated soak + multi-node procedure |
| **Date** | 2026-07-10 |
| **Network class** | Throwaway / mainnet-candidate (no Dual) |
| **Status** | **Automated suite green**; live multi-node soak procedure documented |

Companion: [`fcmp-mainnet-freeze.md`](fcmp-mainnet-freeze.md), [`fcmp-runbook.md`](fcmp-runbook.md).

---

## 1. Scope

D14 requires a **throwaway FCMP-only testnet soak** with adversarial proof spam and reorg drills before treating a network as persistent mainnet.

This report covers:

1. **Automated soak** — unit/integration coverage that exercises the production spend path, tree, double-spend, stale root, bad proofs, weights, host capability.
2. **Live soak procedure** — how operators run multi-node FCMP-only smoke on `kohl-ash` or exported chainspecs.

It does **not** claim a completed multi-week public adversarial campaign; that remains an optional ops step before social mainnet launch.

---

## 2. Automated suite (CI / local)

### 2.1 Commands (must stay green)

```bash
# Primitives freeze snapshot
cargo test -p ringct-primitives freeze

# Pallet: FCMP path + mainnet invariants + weights unit tests
cargo test -p pallet-ringct --lib

# Crypto FCMP KATs (included in ringct-crypto tests)
cargo test -p ringct-crypto --lib

# Wallet FCMP builder
cargo test -p kohl-wallet

# Node host matrix
cargo test -p kohl-node --bin kohl fcmp_capability

# Optional: node + runtime link
cargo build -p kohl-node -p kohl-runtime
```

CI: `.github/workflows/ci.yml` (Build & test job).

### 2.2 Coverage map

| Scenario | Where | Result target |
|----------|-------|---------------|
| Happy-path FCMP spend | `pallet-ringct` tests | Accept |
| Multi-input FCMP | same | Accept |
| Double-spend (KI) | same | Reject |
| Stale membership root | same | Reject |
| Bad / empty FCMP proof | same | Reject |
| Fee floor | same | Reject |
| Balance / range failure | same | Reject |
| `fcmp_mode == 2` | mainnet invariants | Assert |
| No CLSAG transfer fields | encoding freeze / types | `FcmpInput` only |
| Transparent path D17 | `ringct-crypto` fcmp tests | Reject |
| Weight monotonicity / budgets | `weights.rs` unit tests | Pass |
| Host matrix lists `verify_fcmp_v1` | `fcmp_capability` tests | Pass |
| Tree grow + admit maturity | membership / coinbase tests | Pass |

### 2.3 Record (this freeze)

| Date | Runner | Suite | Outcome |
|------|--------|-------|---------|
| 2026-07-10 | PR-10 authoring | `cargo test -p ringct-primitives freeze` + `pallet-ringct --lib` mainnet invariants | Required green before merge |
| ongoing | GitHub Actions CI | workspace tests + node build | Required on `main` |

*(Fill exact local pass timestamps in the PR description when merging.)*

---

## 3. Live multi-node soak procedure (`kohl-ash`)

Use for pre-launch confidence; wipe afterward.

### 3.1 Topology

- ≥ 2 full nodes, same binary / matrix row
- 1–2 miners (`--validator --mining-seed`)
- 1 wallet against RPC (localhost or filtered)
- Optional: third node join mid-soak for sync

### 3.2 Steps

1. Build release node (`cargo build -p kohl-node --release`).
2. Start seed + miner on `--chain kohl-ash` (or exported JSON with bootnodes).
3. Confirm journal: FcmpOnly + required host fns; RPC `fcmp_mode` = 2.
4. Mine past coinbase maturity (60 blocks) + spendable age (10) as needed.
5. Wallet: scan, build FCMP transfer, submit; confirm inclusion.
6. **Adversarial spam (manual):**
   - Replay spent key image → reject
   - Mutate proof bytes → reject
   - Stale root from old height → reject
   - Underpay fee → reject
7. **Reorg drill:** mine competing short forks if tooling allows; wallet resync membership cache; resubmit with fresh root.
8. Watch tree RPC: `tree_slots`, admit cursor, roots advance; no unbounded backlog under steady mint.
9. Tear down: **delete chain DB** (throwaway). Do not migrate to mainnet history.

### 3.3 Live soak log (template)

| Date | Duration | Peers | Blocks | Spends OK | Rejects exercised | Notes |
|------|----------|-------|--------|-----------|-------------------|-------|
| _TBD_ | | | | | | |

---

## 4. Known soak limits

- FCMP0001 **n ≤ 64** — do not soak-claim large-set performance.
- BLAKE2b PoW without `randomx` is fine for functional soak, not for mainnet security budget.
- Dandelion++ / Tor are orthogonal; optional during privacy network soak.

---

## 5. Gate decision

| D14 soak criterion | Status |
|--------------------|--------|
| Automated FCMP-only path coverage | **PASS** (suite above) |
| Weights present before soak | **PASS** (PR-6) |
| Procedure for multi-node adversarial drills | **PASS** (§3) |
| Multi-week public soak completed | **Not claimed** — optional before social launch |
| Dual involved | **No** |

**Recommendation:** Encoding freeze may proceed. Complete §3 live log before marketing a public persistent testnet as “soaked.”
