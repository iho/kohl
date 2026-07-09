# kohl

**Private cash L1** — a pure value-transfer blockchain built with the
[Polkadot SDK](https://github.com/paritytech/polkadot-sdk) (Substrate/FRAME),
modeled on Monero’s privacy design.

Privacy is **mandatory** at the protocol level. There is no transparent
balance path, no smart contracts, and no EVM. Value moves only as
confidential RingCT outputs.

| Pillar | Hides | Mechanism |
|--------|--------|-----------|
| Sender anonymity | *which* past output was spent | **CLSAG** ring signatures + decoys |
| Receiver privacy | *who* was paid | CryptoNote **stealth** / one-time addresses |
| Amount confidentiality | *how much* moved | **Pedersen** commitments + **Bulletproofs** |

Double-spends are stopped with **key images** (linkable nullifiers). Consensus
is **RandomX PoW** for a fair launch (zero genesis supply; all coins from mining).

> **Not Monero-compatible.** Kohl uses **Ristretto** everywhere (prime-order
> group) and its own domain tags — addresses, seeds, and transactions are not
> interchangeable with Monero.

---

## Status

Implemented through **Phase 4** against `polkadot-stable2606`: privacy crypto,
`pallet-ringct` monetary rules, LWMA difficulty, PoW node, and a wallet crate.
A single-node dev chain can mine and mint coinbase outputs.

| Area | State |
|------|--------|
| RingCT transfer (CLSAG + balance + range proofs) | Done |
| Stealth addresses + view tags | Done |
| Host-function crypto (native verify) | Done |
| Runnable PoW node (`--dev`) | Done |
| Epoch-rotating PoW seed (lagged block hash) | Done (importer + miner) |
| Persistent miner address (`--mining-seed`) | Done |
| Wallet age-biased decoy sampler | Done |
| `#[pallet::authorize]` (no ValidateUnsigned) | Done |
| Production RandomX hasher (vs BLAKE2b dev) | Feature-gated (`cargo build -p kohl-node --features randomx`) |
| WeightInfo (engineered, host-crypto scaled) | Done — replace with machine benches later |
| One-time key point hygiene | Done |
| Multi-input wallet spends | Done |
| Local testnet `kohl-ash` | Done |
| Fuzz targets (CLSAG / transfer decode) | Done (`fuzz/`) |
| Coinbase view tags (wallet scan parity) | Done |
| `ringct_*` JSON-RPC for wallets | Done |
| Network privacy (Tor / Dandelion++) | Planned |

See [BLUEPRINT.md](BLUEPRINT.md) for architecture, verification rules (§3.4),
tokenomics, and the full remaining-work list.

---

## Repository layout

```text
primitives/
  ringct-primitives/   Consensus constants, emission curve
  ringct-crypto/       CLSAG, stealth, Pedersen, Bulletproofs, host fns
  kohl-runtime-api/    DifficultyApi + RingCtApi
pallets/
  ringct/              Monetary system (outputs, key images, transfers, coinbase)
  difficulty/          LWMA PoW difficulty
consensus/kohl-pow/    Mining core + sc-consensus-pow algorithm
runtime/               FRAME runtime wiring
node/                  Runnable binary: kohl
wallet/                Scan + build RingCT transfers
examples/learn_ringct.py   Interactive Monero/kohl privacy tour (Python)
```

---

## Quick start

### Prerequisites

- Rust via the repo pin ([`rust-toolchain.toml`](rust-toolchain.toml))
- Standard C toolchain (RandomX / native deps when enabled)
- Python 3 (optional, for the learning script only)

### Build the node

```bash
cargo build -p kohl-node --release
```

WASM runtime builds pass `--allow-undefined` to the linker so `sp_io` and
`ringct_crypto` host functions remain imports — configured in
[`.cargo/config.toml`](.cargo/config.toml).

### Run a single-node dev chain

```bash
# Throwaway miner keys (printed once at startup):
./target/release/kohl --dev --validator --tmp

# Persistent payout address (same seed as kohl-wallet):
./target/release/kohl --dev --validator --tmp \
  --mining-seed 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

The node mines blocks and attaches a **coinbase inherent** each block: one
stealth one-time output to the miner address. The **reward amount is computed
by the runtime** (`block_reward + fees`), not chosen by the miner. PoW uses an
**epoch seed** derived from a lagged block hash (see `kohl_pow::seed_for_parent`).

### Tests

```bash
cargo test -p ringct-crypto -p pallet-ringct -p ringct-primitives -p pallet-difficulty
# or the whole workspace:
cargo test
```

### Wallet RPC

The node exposes convenience methods (in addition to `state_call`):

| Method | Purpose |
|--------|---------|
| `ringct_outputCount` | total outputs |
| `ringct_minFeePerByte` | fee floor |
| `ringct_isKeyImageSpent` | hex key image → bool |
| `ringct_outputsInRange` | block range → SCALE hex of outputs |

`kohl-wallet` prefers these and falls back to `state_call` for older nodes.

### Local testnet (`kohl-ash`)

```bash
./target/release/kohl --chain kohl-ash --validator --tmp \
  --mining-seed <64-hex>
```

Same fair-launch genesis as mainnet, moderate initial difficulty for multi-node
smoke tests.

### Learn the privacy model

```bash
python3 examples/learn_ringct.py          # full tour + diagrams
python3 examples/learn_ringct.py --clsag  # ring verification loop
python3 examples/learn_ringct.py --check  # self-tests
```

Companion write-up: **[GLOSSARY.md](GLOSSARY.md)** (acronyms, math, Python toys).

### Fuzzing (Phase 5)

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run clsag_verify --fuzz-dir fuzz
cargo +nightly fuzz run transfer_decode --fuzz-dir fuzz
```

---

## How a transfer works (sketch)

```text
Wallet                                      Runtime (pallet-ringct)
──────                                      ───────────────────────
Pick real output + 15 decoys (ring size 16)
Build pseudo-commitments C'
CLSAG per input + aggregated Bulletproof
Stealth OTKs + masked amounts for receivers
Submit unsigned extrinsic  ──────────────►  shape / maturity / fee floor
                                            verify_clsag_v1 (host)
                                            Σ C' == Σ C_out + fee·H
                                            verify_range_proof_v1 (host)
                                            insert key images, append outputs
```

There is **no account balance**, **no nonce**, and **no signed origin** for
user payments. The CLSAG *is* the authorization. Heavy crypto runs **native**
via versioned host functions so block verification stays practical under WASM.

Details: [BLUEPRINT.md §3.4](BLUEPRINT.md) and `pallets/ringct/src/lib.rs`
(`verify_transfer`).

---

## Design choices (short)

- **Cash only** — no contracts, assets, or general programmability.
- **Fair launch** — genesis supply 0; PoW instead of PoS authority sets.
- **Ristretto** — avoids Monero’s historical cofactor / small-subgroup footguns.
- **Fees to miners** (via next coinbase), with a public fee and a min fee-per-byte floor.
- **Monero-like emission** — smooth curve + perpetual tail for a security budget.

---

## Documentation

| Doc | Contents |
|-----|----------|
| [BLUEPRINT.md](BLUEPRINT.md) | Architecture, pallet design, phases, risks, tokenomics |
| [GLOSSARY.md](GLOSSARY.md) | Terms & acronyms with explanations and examples |
| [examples/learn_ringct.py](examples/learn_ringct.py) | Runnable privacy walkthrough |
| [plan.md](plan.md) | Original design brief (historical requirements) |

---

## License

[GNU General Public License v3.0](LICENSE).
