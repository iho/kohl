# FCMP operator runbook (host skew, genesis, no Dual)

Operational companion to [`fcmp-design.md`](fcmp-design.md) **PR-9**. For Tor / public seed setup see [`tor-runbook.md`](tor-runbook.md) and [`production-bootnode.md`](production-bootnode.md).

**Launch posture:** pre-launch, **FCMP-only**. There is **no Dual** era, no CLSAG/FCMP height matrix, and no “keep rings for rollback on mainnet.” Throwaway chains are wiped or re-genesised; they are not migrated.

---

## 1. What operators must know

| Fact | Detail |
|------|--------|
| Spend path | `fcmp_mode = 2` (FcmpOnly). Production transfers call `verify_fcmp_v1`, not `verify_clsag_v1`. |
| Signing domain | `kohl/transfer/v4` |
| Membership | Path A blake2 sparse Merkle; maturity via non-EMPTY admission |
| Interim crypto | **FCMP0001** — full mature-set membership + CLSAG SA+L, anonymity set **n ≤ 64**. Large-set Curve Trees still open (Path B). |
| Genesis | Fair launch (zero supply). Tree starts empty; grows as outputs are created. |
| Host boundary | Expensive crypto is **native host functions** (BLUEPRINT §1.6). Node binary must export every host the runtime imports. |

---

## 2. Host / runtime version matrix

**Rule:** ship the **node binary** that registers new host functions **before** (or together with) any runtime WASM that calls them. A runtime upgrade alone cannot add host code.

Source of truth in-tree:

- Code: `node/src/fcmp_capability.rs` (`HOST_CAPABILITY_MATRIX`, `REQUIRED_CONSENSUS_HOST_FNS`)
- Runtime version: `runtime/src/lib.rs` → `VERSION.spec_version`
- Node package version: workspace `Cargo.toml` → `[workspace.package].version`

### Current matrix

| Runtime `spec_version` | Min node (`kohl` / `kohl-node`) | Spend mode | Notes |
|------------------------|----------------------------------|------------|--------|
| **1** | **0.1.0** | FcmpOnly | FCMP0001; Path A tree; no Dual |

When you add a host ABI or change consensus verify behaviour:

1. Append a matrix row (do not rewrite frozen public-network rows).
2. Bump `spec_version` if the runtime behaviour/encoding changes.
3. Bump the node package version if operators must upgrade the binary.
4. Update this table and `fcmp_capability.rs` in the same PR.
5. Announce: “node ≥ X required for runtime `spec_version` Y.”

### Required consensus host functions (`spec_version` 1)

Logical names = `RingctCrypto` trait methods (registered via `RingCtHostFunctions` in `node/src/service.rs`):

| Host fn | Used for |
|---------|----------|
| `verify_fcmp_v1` | Per-input FCMP+SA+L (PR-5c / PR-7) |
| `verify_balance_v1` | Σ C' == Σ C_out + fee·H |
| `verify_range_proof_v1` | Aggregated Bulletproof |
| `value_commitment_v1` | Coinbase transparent amount → commitment |
| `is_valid_point_v1` | Point hygiene (OTKs, KI, C', tx pubkey) |

**Not** on the production transfer path after PR-7 (still may be registered):

| Host fn | Role |
|---------|------|
| `verify_clsag_v1` | Legacy CLSAG; FCMP0001 uses CLSAG **inside** native `verify_fcmp_v1` |
| `prove_range_v1`, `fcmp_prove_v1`, RNG / `commit_v1` / `key_image_v1` | Benchmarks / tooling only |

### Startup log

On every full-node start, `new_partial` logs capability lines under target `kohl`, for example:

```text
RingCT/FCMP host capability: node_version=0.1.0 matrix_spec_version=1 min_node=0.1.0 (...)
FCMP spend path: FcmpOnly (mode=2); Dual HF matrix: none (out of scope)
Required consensus host fns (RingctCrypto): verify_balance_v1, ...
```

If peers run an older binary missing `verify_fcmp_v1`, they **cannot** correctly execute the current runtime. Prefer refusing to author / clear operator messaging over silent wrong verification.

### Skew symptoms

| Symptom | Likely cause | Action |
|---------|--------------|--------|
| WASM host import missing / executor panic on verify | Node older than runtime | Upgrade **node** first |
| All FCMP txs invalid after upgrade | Host ABI mismatch or wrong binary feature set | Align node to matrix; do not “patch” verify in WASM |
| Wallet builds txs nodes reject | Wallet/node/runtime out of sync on root age / proof format | Match wallet to same release train |
| “CLSAG ring” txs in mempool | Stale client or fork of pre-PR-7 code | Reject; there is no Dual accept path |

---

## 3. No Dual height matrix

**Intentionally empty.** Design rev 6 removes Dual coexistence.

Do **not** maintain:

- `clsag_until_height` / `fcmp_from_height`
- Per-era host matrices for CLSAG vs FCMP on the same economic history
- Mainnet “rollback to rings” HF schedules

Pre-launch emergency options:

1. **Re-genesis** (new chain id / wipe DB) with a fixed binary, or  
2. **Git revert + coordinated restart** on throwaway networks  

Post-launch host verify still cannot be silent-patched without a **node** upgrade (D10).

---

## 4. FCMP-only genesis checklist

Use for any chain you care about (public testnet soak or mainnet freeze). Built-in presets already use the FCMP-only runtime:

| CLI | Preset id | Difficulty (initial) | Role |
|-----|-----------|----------------------|------|
| `--dev` | `development` | `MinDifficulty` | Single machine |
| `--chain kohl-ash` | `kohl-ash` | `100_000` | Multi-node / soak |
| `--chain kohl` / `mainnet` | `mainnet` | `50_000_000` | Public mainnet template |

### 4.1 Before first peer

- [ ] Same **node binary** family on all validators (matrix row for current `spec_version`)
- [ ] Confirm startup log: FcmpOnly, `verify_fcmp_v1` in required host list
- [ ] Same chain id + genesis (export with `scripts/make-chainspec.sh` if using bootnodes)
- [ ] No plan to accept CLSAG `v3` extrinsics on this history
- [ ] Wallet is FCMP builder (no production `--ring` / decoy path; `legacy-decoy` feature is dev-only)
- [ ] Understand interim **n ≤ 64** mature-set cap (FCMP0001); do not market as unlimited set until Path B

### 4.2 Mainnet / persistent testnet (D14 — PR-10)

Named artifacts (see [`fcmp-mainnet-freeze.md`](fcmp-mainnet-freeze.md)):

- [x] Composition review memo (internal) — [`fcmp-composition-memo.md`](fcmp-composition-memo.md)
- [x] FCMP weights merged + weight unit tests in CI
- [x] FCMP-only soak report — [`fcmp-soak-report.md`](fcmp-soak-report.md)
- [x] Invariant suite — `mainnet_invariants` + freeze snapshot
- [x] Encoding freeze recorded — freeze doc §2

Still optional / PR-11 before social “audit-complete” launch:

- [ ] External crypto audit
- [ ] Multi-week public live soak log filled in soak report §3.3
- [ ] Product accept of n≤64 **or** Path B upgrade

### 4.3 Exporting a miner-facing chainspec

```bash
cargo build -p kohl-node --release
# optional: --features randomx for production PoW

./scripts/make-chainspec.sh \
  --chain kohl \
  --bootnode /ip4/YOUR.IP/tcp/30333/p2p/12D3KooW... \
  --output chainspecs/kohl.json
```

Document for miners: **node ≥ matrix min**, same `chainspecs/*.json`, FCMP-only (no ring size flag).

---

## 5. Day-2 operations

### Tree / membership health

Useful RPC / API (names may be prefixed `ringct_*` on JSON-RPC):

| Signal | Why |
|--------|-----|
| `membership_root` / root-at-height | Wallet anchors; stale root → `fcmp_root_stale` |
| `tree_slots`, `admit_scan_cursor`, backfill status | Lag after mid-dev enable; mainnet should not lag at genesis |
| `fcmp_mode` | Must be `2` |
| `Emitted` / supply checks | With BP, economic invariant |

Prefer **genesis-with-tree-at-zero** (empty tree, grow on create). Mid-dev lag catch-up (PR-2) is for throwaway chains only — not a Dual gate.

### Weight / DoS

- FCMP verify weight scales with inputs and tree size (see pallet weights; PR-6).
- Cap: `MAX_FCMP_INPUTS`, `MAX_FCMP_PROOF_BYTES`, `MAX_FCMP_ANON_SET` (64 interim).
- Watch block weight utilization and reject under-weighted clients after weight bumps.

### Reorgs

Membership roots are state; reorg rolls back tree storage with the chain. Wallets must resync membership cache / frontier (PR-8). Do not special-case Dual.

---

## 6. Emergency playbooks

| Situation | Pre-launch | Post mainnet freeze (product policy TBD) |
|-----------|------------|------------------------------------------|
| Unsound FCMP / critical host bug | Stop network; fix; **re-genesis** | Coordinated halt + node upgrade; re-genesis is product/legal decision — **not Dual** |
| Need new host fn | New node release → then runtime | Same; publish matrix row |
| Accidental CLSAG client traffic | Drop / invalid | Same |
| Public testnet had rings historically | Wipe; new genesis FCMP-only | N/A if never launched with rings |

---

## 7. CI / engineering assertions (checklist)

- [ ] Mainnet runtime has no CLSAG **transfer** extrinsic path
- [ ] `fcmp_mode()` always returns `2`
- [ ] Node tests: `fcmp_capability` matrix non-empty; consensus list includes `verify_fcmp_v1` and excludes `verify_clsag_v1`
- [ ] Host capability log remains on `new_partial` (operators rely on journal lines)
- [x] Design status: PR-0…**PR-11 ✅** (hardening + docs); external audit still recommended

---

## 8. Related docs

| Doc | Role |
|-----|------|
| [`fcmp-design.md`](fcmp-design.md) | Architecture, PR plan, D1–D18 |
| [`fcmp-pr0-memo.md`](fcmp-pr0-memo.md) | Path A/B go/no-go |
| [`../chainspecs/README.md`](../chainspecs/README.md) | Exporting specs with bootnodes |
| [`production-bootnode.md`](production-bootnode.md) | Public seed |
| [`tor-runbook.md`](tor-runbook.md) | Tor ops |
| `node/src/fcmp_capability.rs` | Matrix + startup log |
| `node/src/chain_spec.rs` | Built-in presets |
| `node/src/service.rs` | `HostFunctions` registration |
