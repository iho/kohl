# Private Cash L1 — Architecture & Implementation Blueprint

A pure cash-only Layer-1 blockchain built with the Polkadot SDK (Substrate/FRAME) in Rust,
emulating Monero's privacy structure: **ring signatures** (sender anonymity), **stealth
addresses** (receiver privacy), and **RingCT-style confidential amounts** (Pedersen
commitments + Bulletproofs range proofs). Privacy is mandatory at the protocol level —
there is no transparent transfer path.

> Working name used throughout: **`pallet-ringct`** for the core pallet, "**kohl**" for the chain.

---

## Implementation Status

This repository implements the blueprint through Phase 4 (all crates compile against
`polkadot-stable2606`; 44 tests green). Layout:

| Crate | Role | Status |
|---|---|---|
| `primitives/ringct-primitives` | consensus constants, emission curve | ✅ tested |
| `primitives/ringct-crypto` | Pedersen commitments, Bulletproofs, **CLSAG**, **stealth addresses**, host functions | ✅ tested |
| `primitives/kohl-runtime-api` | `DifficultyApi` + `RingCtApi` declarations | ✅ builds |
| `pallets/ringct` | the monetary system (outputs, key images, RingCT transfers, coinbase) | ✅ tested |
| `pallets/difficulty` | LWMA PoW difficulty | ✅ tested |
| `consensus/kohl-pow` | mining core + `sc-consensus-pow` `PowAlgorithm` (RandomX) | ✅ core tested; `node`/`randomx` feature-gated |
| `runtime` | `#[frame_support::runtime]` wiring, genesis, runtime APIs | ✅ builds native + WASM |
| `node` | `sc-service` PoW node: import queue, mining worker, CPU miner, coinbase minting, host-function-extended executor | ✅ builds; runnable dev chain |

The privacy cryptography, the full transfer/consensus logic, and a runnable PoW node are
implemented. Build the node with `cargo build -p kohl-node --release` and run a single-node
dev chain that mines blocks and mints rewards with
`./target/release/kohl --dev --validator --tmp`. Each block carries a coinbase inherent that
mints one confidential output (a stealth one-time key) to the miner's address; the reward
amount is computed by the runtime (`block_reward + carried fees`), not the miner.

The WASM runtime build needs `--allow-undefined` passed to the wasm linker (so the `sp_io`
and `ringct_crypto` host functions stay as imports); this is wired in `.cargo/config.toml`
via `WASM_BUILD_RUSTFLAGS`.

**Remaining work**: merge machine weights from `./scripts/benchmark-ringct.sh`
into production `WeightInfo` after a full STEPS/REPEAT run; external crypto
audit (Phase 5). Dandelion++ stem/fluff diffusion is implemented in
`node/src/dandelion/`.

**Benchmarks**: `frame_benchmarking::Benchmark` is exported by the runtime.
Because RingCT uses custom host functions, measure with
`kohl benchmark pallet` (not stock `frame-omni-bencher`). See
`scripts/benchmark-ringct.sh`.

**Recently landed**: production-WASM benchmark wiring (runtime API + node CLI +
script); criterion crypto benches; Tor guidance; cargo-deny; multi-input
wallet; ringct RPC; fuzz; authorize; epoch PoW seed.

---

## 0. Understanding of the Requirements (Confirmation)

- **Scope**: private fungible value transfer only. No contracts pallet, no EVM, no
  general programmability. The runtime is deliberately small.
- **Model**: UTXO-like *output/commitment* model layered inside a FRAME pallet — not
  Substrate's account model. Outputs are one-time keys + Pedersen commitments; spends
  reveal **key images** (linkable-ring nullifiers) to prevent double-spends without
  revealing which output was spent.
- **Three pillars**, mapped to concrete, implementable Rust cryptography:
  1. Sender anonymity → **CLSAG** linkable ring signatures over Ristretto
     (Monero's current scheme, post-MLSAG; see [Goodell–Noether–RandomRun, "Concise
     Linkable Ring Signatures and Forgery Against Adversarial Keys", 2019](https://eprint.iacr.org/2019/654)).
  2. Receiver privacy → **CryptoNote dual-key stealth addresses** with Monero-style
     **view tags** for fast scanning ([CryptoNote v2.0 whitepaper, van Saberhagen 2013](https://web.archive.org/web/20201028121818/https://cryptonote.org/whitepaper.pdf)).
  3. Amount confidentiality → **Pedersen commitments + Bulletproofs(+) range proofs**
     ([Noether, "Ring Confidential Transactions", 2016](https://eprint.iacr.org/2015/1098);
     [Bünz et al., "Bulletproofs", 2017](https://eprint.iacr.org/2017/1066)).
- **Standalone L1** (solochain, not a parachain), users run full nodes; light-client
  support planned via runtime APIs + view tags.
- **Consensus**: PoW (RandomX) block production — justified in §1.4.
- **Fair launch**: zero genesis supply; all emission via mining rewards with a Monero-like
  smooth curve and tail emission.
- **Performance**: heavy verification (CLSAG, Bulletproofs) runs **native via runtime host
  functions**, not interpreted WASM — this is the single most important Substrate-specific
  design decision, detailed in §1.6.

If classic MLSAG were required verbatim it would be strictly worse than CLSAG (larger,
slower, same assumptions), so CLSAG is used — it *is* Monero's production scheme since 2020.

---

## 1. High-Level Architecture Overview

### 1.1 Node & runtime composition

```
┌──────────────────────────── node (native) ─────────────────────────────┐
│  sc-consensus-pow (RandomX via randomx-rs)   sc-network / RPC / txpool │
│  Host functions: ringct_verify_clsag, ringct_verify_bp_batch  ◄────┐   │
├────────────────────────────────────────────────────────────────────┼───┤
│                        runtime (WASM + native)                     │   │
│  frame-system │ pallet-timestamp │ pallet-ringct ──── calls ───────┘   │
│               │ pallet-transaction-payment (minimal/none — see §3.6)   │
└────────────────────────────────────────────────────────────────────────┘
```

- The runtime is minimal: `frame-system`, `pallet-timestamp`, and **`pallet-ringct`**.
  There is **no `pallet-balances` exposed to users** — the native unit exists only inside
  the confidential output set. Fees are paid Monero-style: the fee is the one public
  amount in each transaction and is consumed by the commitment balance equation (§3.6).
- Transactions are **unsigned extrinsics** (`ValidateUnsigned`): like a Monero tx, a
  transfer is self-authenticating — the CLSAG signatures *are* the authorization. There
  is no account, no nonce, no signer. Replay is impossible because key images are
  single-use.

### 1.2 Data model: private UTXO / commitment set

Each **output** (TXO) stored on chain:

| Field | Size | Purpose |
|---|---|---|
| one-time public key `P` | 32 B | stealth destination (Ristretto point) |
| Pedersen commitment `C = xG + aH` | 32 B | hides amount `a` |
| view tag | 1 B | fast wallet scanning (Monero 2022 optimization) |
| encrypted amount | 8 B | `a XOR H(shared_secret)` so receiver can decode |
| tx pubkey `R = rG` | 32 B | per-tx, shared by its outputs |
| global output index | 8 B | key for ring-member referencing |

Outputs are **append-only** and indexed by a monotonically increasing **global output
index** (like Monero), so a ring can reference its members as compact `u64` offsets
instead of 32-byte keys. Outputs are never deleted (any output may be a decoy forever).

Each **spend** publishes a **key image** `I = x·Hp(P)` per real input. The chain keeps a
permanent key-image set; inclusion ⇒ reject (double spend). Key images reveal nothing
about *which* ring member was spent (linkability without traceability — CryptoNote §4).

### 1.3 The three pillars on Substrate

1. **Sender anonymity — CLSAG rings.** Every input is a ring of `RING_SIZE = 16`
   outputs (15 decoys + 1 real, indices chosen wallet-side with a gamma distribution
   over output age, per the [Möser et al. 2018 empirical analysis](https://arxiv.org/abs/1704.04299)
   that informed Monero's decoy sampler). The CLSAG proves: "I know the private key of
   one ring member, its key image is `I`, and the member's commitment minus this input's
   *pseudo-output commitment* is a commitment to zero."
2. **Receiver privacy — stealth addresses.** Addresses are dual-key `(A = aG, B = bG)`
   (view/spend). Sender picks random `r`, publishes `R = rG`, derives one-time key
   `P = Hs(rA ‖ i)·G + B`. Only the holder of `a` can detect the output (view key
   scanning), only the holder of `b` can spend. View tags (`first byte of Hs(rA ‖ i)`)
   let wallets skip ~99.6 % of the expensive scan work.
3. **Amount confidentiality — RingCT.** Amounts live only inside Pedersen commitments.
   Per tx: pseudo-output commitments `C'ᵢ` per input, output commitments `Cⱼ`, and the
   balance check `Σ C'ᵢ − Σ Cⱼ − fee·H = 0` (fee is the sole public amount). A single
   aggregated Bulletproof proves every output amount ∈ [0, 2⁶⁴) — no overflow minting.

### 1.4 Consensus: RandomX PoW + (optional, later) GRANDPA

**Choice: `sc-consensus-pow` with RandomX** ([tevador/RandomX](https://github.com/tevador/RandomX),
Rust bindings: [`randomx-rs`](https://github.com/tari-project/randomx-rs) maintained by Tari).

Justification for a cash chain:

- **Fair launch is a hard requirement.** PoS needs an initial stake distribution — i.e.,
  a premine or sale — which the spec forbids. PoW lets supply start at zero.
- **Permissionless validator set.** Aura/BABE need a known authority set; a cash chain
  should not have a permissioned or plutocratic block-producer registry.
- **ASIC/GPU resistance** (RandomX is CPU-optimized) keeps mining geographically and
  economically dispersed — the practical defense against 51 % capture for a small chain.
- **Precedent**: [Kulupu](https://github.com/kulupu/kulupu) ran a production PoW
  Substrate chain with `sc-consensus-pow` for years; its code is the reference for
  difficulty adjustment and reward-lock patterns.

Trade-offs, stated honestly: `sc-consensus-pow` is less actively maintained than
BABE/GRANDPA and gives probabilistic finality only. Mitigations: pin to the SDK stable
release and budget maintenance; consider adding **GRANDPA finality voted by recent-work
miners** (or a checkpoint scheme) in a later phase. RandomX itself is C++ — the node
links it via FFI (`randomx-rs`); it never runs in the runtime, only in the miner/import
pipeline, so WASM compatibility is unaffected. Difficulty: LWMA or Kulupu-style
adjustment targeting **60 s blocks**.

### 1.5 Mandatory privacy

There is exactly one way to move value: `pallet_ringct::transfer`. No transparent
balances, no opt-out, no "exempt" addresses. Coinbase outputs are the single exception
(amounts public, as in Monero) and become private the moment they are spent into a ring.
This maximizes fungibility and avoids Zcash's shielded/transparent bifurcation problem,
where optional privacy shrinks the anonymity set.

### 1.6 Where verification runs (the WASM problem)

CLSAG (≈ 2·ring_size scalar mults per input) and Bulletproof verification (a few ms
native) are 10–50× slower in interpreted WASM — unacceptable at block-verification time.
Solution: **runtime host functions** (`#[runtime_interface]`, the same mechanism as
`sp_io::crypto`):

- `ringct::verify_clsag(msg, ring, pseudo_commitment, key_image, sig) -> bool`
- `ringct::verify_bulletproof_batch(proofs, commitments) -> bool`

These execute natively (with `curve25519-dalek`'s SIMD backends) while the runtime stays
WASM-first. Cost: adding/changing a host function requires a **node** upgrade, not just a
forkless runtime upgrade — acceptable for a chain whose consensus rules should be
extremely stable, and the functions are versioned (`verify_clsag_v1`) to keep old blocks
re-executable. Additionally, all Bulletproofs in a block are **batch-verified** once
(amortizes to ~⅓ the cost per proof).

---

## 2. Recommended Tech Stack & Dependencies

### 2.1 Polkadot SDK

- **Release**: pin to **`polkadot-stable2606`** (v1.24.0, released 2026-07-06, EOL
  2027-07) — the current stable per the
  [release registry](https://github.com/paritytech/release-registry). Track patch tags
  (`polkadot-stable2606-N`).
- **Template**: start from the official
  [`polkadot-sdk-solochain-template`](https://github.com/paritytech/polkadot-sdk-solochain-template)
  (standalone chain, Aura+GRANDPA out of the box), then swap consensus to
  `sc-consensus-pow` using [Kulupu](https://github.com/kulupu/kulupu) as the reference
  implementation for the PoW plumbing. (The `minimal-template` is an alternative if you
  prefer building the service up from nothing.)

### 2.2 Cryptography crates

| Crate | Version | Role | Notes |
|---|---|---|---|
| [`curve25519-dalek`](https://crates.io/crates/curve25519-dalek) | `4.x` | Ristretto group ops, Pedersen commitments | `no_std` capable; SIMD backends node-side |
| [`bulletproofs`](https://github.com/zkcrypto/bulletproofs) (zkcrypto fork) | `4.x`/`5.x` | aggregated 64-bit range proofs, batch verify | dalek-cryptography original is the reference; zkcrypto fork tracks dalek 4.x |
| [`monero-serai` / `monero-clsag`](https://github.com/serai-dex/serai) | git | **CLSAG** sign/verify in pure Rust | the only serious non-C++ CLSAG; vendor + audit, or port |
| [`merlin`](https://crates.io/crates/merlin) | `3.x` | Fiat–Shamir transcripts (required by bulletproofs) | |
| [`blake2` / `sha3`](https://crates.io/crates/blake2) | latest | `Hs`/`Hp` hash-to-scalar / hash-to-point | use Ristretto `from_uniform_bytes` for `Hp` (sidesteps Monero's ad-hoc point hashing) |
| [`zeroize`](https://crates.io/crates/zeroize) | `1.x` | key material hygiene (wallet) | |
| [`randomx-rs`](https://github.com/tari-project/randomx-rs) | git/latest | RandomX PoW (node only) | FFI to C++ RandomX |
| [`subtle`](https://crates.io/crates/subtle) | `2.x` | constant-time comparisons | |

**Deliberate choice: Ristretto everywhere** (not raw ed25519 like Monero). It gives a
prime-order group — eliminating Monero's historical cofactor-8 bugs (including the 2017
key-image double-spend vulnerability) — and it is what `bulletproofs` natively uses.
Consequence: **no address/output compatibility with Monero**, which is fine (new chain).

**Alternative stack (documented, not chosen)**: arkworks/Halo2 zk-SNARK shielded pool
(Zcash-Sapling-like, à la Manta/ZeroPool). Pros: whole-chain anonymity set, smaller
proofs. Cons: circuit engineering + proving keys + (for Groth16) trusted setup, wallet
proving time of seconds, and a far larger audit surface. §9.3 describes when to revisit.

### 2.3 Prior art to study/adapt

- **Kulupu** — Substrate PoW consensus wiring, difficulty, era-locked rewards.
- **ZeroPool / Manta** — pallet-shaped zk privacy on Substrate (storage layout for
  nullifier/commitment sets, off-chain proving flow).
- **Monero codebase** — decoy selection (`wallet2.cpp` gamma sampler), view tags,
  `10-block spendable` rule, dynamic block weight / fee market.

---

## 3. Custom Pallet Design: `pallet-ringct`

Purpose: the entire monetary system — output set, key images, transfer verification,
emission, fees.

### 3.1 Core types

```rust
pub type RistrettoPoint = [u8; 32];   // compressed
pub type KeyImage      = [u8; 32];
pub type Commitment    = [u8; 32];

/// One confidential output (TXO).
#[derive(Encode, Decode, MaxEncodedLen, TypeInfo, Clone, PartialEq)]
pub struct Output {
    pub one_time_key: RistrettoPoint,
    pub commitment:   Commitment,
    pub view_tag:     u8,
    pub amount_enc:   [u8; 8],       // XOR-encrypted amount for the receiver
    pub tx_pubkey:    RistrettoPoint,
}

/// One ring input inside a transfer.
#[derive(Encode, Decode, TypeInfo, Clone, PartialEq)]
pub struct RingInput {
    /// Global output indices of the ring members (RING_SIZE of them, sorted).
    pub ring: BoundedVec<u64, ConstU32<RING_SIZE>>,
    pub key_image: KeyImage,
    /// Pseudo-output commitment C' for this input.
    pub pseudo_commitment: Commitment,
    /// CLSAG signature bytes: c1 ‖ s[0..RING_SIZE] ‖ D  = 32*(ring+2) bytes.
    pub clsag: BoundedVec<u8, ConstU32<{ 32 * (RING_SIZE + 2) }>>,
}

#[derive(Encode, Decode, TypeInfo, Clone, PartialEq)]
pub struct TransferTx {
    pub inputs:  BoundedVec<RingInput, ConstU32<MAX_INPUTS>>,   // e.g. 8
    pub outputs: BoundedVec<Output,    ConstU32<MAX_OUTPUTS>>,  // e.g. 8
    /// Aggregated Bulletproof covering all output commitments.
    pub range_proof: BoundedVec<u8, ConstU32<MAX_BP_BYTES>>,    // ~1.5 KiB for 8 outputs
    pub fee: u64,            // the only public amount
    pub encrypted_memo: Option<BoundedVec<u8, ConstU32<64>>>,   // payment-id style, optional
}
```

### 3.2 Storage

```rust
/// Append-only output set, keyed by global output index.
#[pallet::storage]
pub type Outputs<T> = StorageMap<_, Twox64Concat, u64, Output>;

/// Next global output index (== total outputs ever created).
#[pallet::storage]
pub type NextOutputIndex<T> = StorageValue<_, u64, ValueQuery>;

/// Spent key images. Presence = spent. Never pruned.
#[pallet::storage]
pub type KeyImages<T> = StorageMap<_, Blake2_128Concat, KeyImage, (), OptionQuery>;

/// Block height at which each output was created (enforces the
/// COINBASE_LOCK / SPENDABLE_AGE maturity rules and helps decoy sampling).
#[pallet::storage]
pub type OutputHeight<T> = StorageMap<_, Twox64Concat, u64, BlockNumberFor<T>>;

/// Total coins emitted so far (public — supply is auditable, amounts are not).
#[pallet::storage]
pub type Emitted<T> = StorageValue<_, u64, ValueQuery>;

/// Fees accumulated in the current block, paid to the next coinbase.
#[pallet::storage]
pub type BlockFees<T> = StorageValue<_, u64, ValueQuery>;
```

Consensus-critical constants: `RING_SIZE = 16`, `SPENDABLE_AGE = 10` blocks (outputs
can't be ring members or be spent before 10 confirmations — kills reorg-based ring
poisoning), `COINBASE_LOCK = 60` blocks.

### 3.3 Extrinsics

Only two, and users only ever build one:

1. **`transfer(tx: TransferTx)`** — unsigned; the entire private transfer.
2. **`coinbase(outputs, extra)`** — inherent-only (rejected from the tx pool); created by
   the block author to claim `block_reward(Emitted) + BlockFees`. Coinbase amounts are
   public: commitment must equal `amount·H` exactly (blinding = 0), checked on chain.

No `create_stealth_address` extrinsic is needed — stealth addresses are pure wallet-side
key derivation; the chain never sees an "address".

### 3.4 Verification pipeline for `transfer` (consensus rules)

```text
1. Shape checks: 1..=MAX inputs/outputs, ring sizes == RING_SIZE, sizes bounded.
2. For each input:
   a. all ring indices exist, are distinct, sorted, and mature (SPENDABLE_AGE);
   b. key image not in `KeyImages` AND no duplicate key image inside this tx;
   c. key image is a canonical point NOT in the small-order subgroup
      (Ristretto decoding enforces canonicity — the 2017-class bug is structurally gone);
   d. fetch ring members' (one_time_key, commitment) pairs;
   e. host_fn: verify CLSAG over msg = H(tx without signatures),
      ring pairs, pseudo_commitment, key_image.
3. Balance: Σ pseudo_commitments == Σ output_commitments + fee·H   (point addition).
4. host_fn: batch-verify the aggregated Bulletproof for all output commitments.
5. Effects (only after ALL checks pass):
   - insert every key image into `KeyImages`;
   - append outputs at NextOutputIndex.., record OutputHeight;
   - BlockFees += fee;
   - deposit Event::Transferred { key_images, output_indices, fee }.
```

The event deliberately contains *only* public data (key images and indices are already
on chain). Steps 2e and 4 are the host-function calls; everything else is cheap storage
and point arithmetic.

### 3.5 Double-spend prevention

Key image = deterministic function of the real spent key (`I = x·Hp(P)`), so the same
output always yields the same key image regardless of ring composition. The permanent
`KeyImages` set + mempool-level dedup (via `ValidateUnsigned::provides`) makes
double-spends impossible both in-block and across blocks.

### 3.6 Fees & unsigned-transaction economics

Fee is the single public amount, enforced by the balance equation (a lying fee breaks
step 3). `ValidateUnsigned` sets:

- `provides = key_images` — the txpool automatically treats two txs spending the same
  output as conflicting and keeps the higher-priority one;
- `priority = fee_per_byte` — the fee market;
- `longevity` bounded, `propagate = true`.

A **minimum fee-per-byte** (consensus constant, adjustable via runtime upgrade) is the
spam floor, since there is no signed-account weight/fee machinery. Fees are **paid to the
block author** through the next coinbase (`BlockFees`), not burned — miners must be paid
for including large proofs. `pallet-transaction-payment` is not used; the whole fee
system is these ~30 lines in the pallet.

### 3.7 Errors & events (excerpt)

```rust
#[pallet::error]
pub enum Error<T> {
    RingMemberUnknown, RingMemberImmature, RingIndicesInvalid,
    KeyImageAlreadySpent, DuplicateKeyImageInTx, KeyImageInvalid,
    ClsagInvalid, BalanceCheckFailed, RangeProofInvalid,
    FeeTooLow, CoinbaseAmountInvalid, TooManyInputsOrOutputs,
}

#[pallet::event]
pub enum Event<T: Config> {
    Transferred { key_images: Vec<KeyImage>, first_output_index: u64, count: u32, fee: u64 },
    CoinbaseMinted { first_output_index: u64, count: u32, reward: u64 },
}
```

---

## 4. Runtime Configuration

### 4.1 Pallet lineup

| Pallet | Status | Why |
|---|---|---|
| `frame-system` | standard | core |
| `pallet-timestamp` | standard | RandomX needs timestamps for difficulty adjustment |
| `pallet-ringct` | **custom** | everything monetary |
| `pallet-difficulty` | custom (port from Kulupu) | on-chain PoW difficulty state |
| `pallet-balances` | **omitted** | no transparent money |
| `pallet-transaction-payment` | **omitted** | fees are internal to RingCT (§3.6) |
| contracts / EVM / assets / governance pallets | **omitted** | cash only; upgrades via hard fork or sudo-then-burn (see §4.3) |

### 4.2 Wiring (see §7.4 for the code)

`pallet-ringct` implements `ValidateUnsigned`; `coinbase` is delivered via an inherent
(`ProvideInherent`) built by the PoW block author with its own stealth output.

### 4.3 Genesis & governance posture

- **Genesis supply: 0.** No endowed accounts (there are no accounts). The chain spec
  carries only consensus constants + initial difficulty.
- Include `pallet-sudo` **temporarily** for launch-phase emergency fixes, with a
  publicly committed burn height (Kulupu did the same); after burning sudo, upgrades are
  miner-signaled hard forks. A cash chain should ossify.

### 4.4 Runtime APIs (for wallets & light clients)

```rust
sp_api::decl_runtime_apis! {
    pub trait RingCtApi {
        /// Outputs created in a block range — the wallet-scanning feed.
        fn outputs_in_range(from: u32, to: u32) -> Vec<(u64, Output)>;
        /// Distribution of output count per block (decoy sampling input).
        fn output_distribution(from: u32, to: u32) -> Vec<u64>;
        fn is_key_image_spent(ki: KeyImage) -> bool;
        fn min_fee_per_byte() -> u64;
    }
}
```

---

## 5. Node & Client Side

### 5.1 Node binary

Fork the solochain template's `node/` crate and replace the Aura/GRANDPA service with
`sc-consensus-pow`: implement `PowAlgorithm` (RandomX seal verify + difficulty from
`pallet-difficulty`), wire `MiningWorker` for the built-in CPU miner
(`--mine --coinbase-viewkey ...` flags), and register the two crypto host functions in
the executor. RandomX cache/dataset management (per-epoch seed = hash of an old block,
as in Monero) lives entirely node-side. Everything else — txpool, libp2p networking,
RPC — is stock Substrate.

### 5.2 Wallet (separate binary/crate: `kohl-wallet`)

All heavy lifting is wallet-side; the chain only verifies.

- **Keys**: mnemonic → spend key `b`; view key `a = Hs(b)` (Monero-style derivation, so
  a mnemonic recovers everything). Address = bech32 of `(A, B)`.
- **Scanning**: stream `outputs_in_range` via the runtime API; for each output compute
  the shared secret, check the 1-byte **view tag** first (rejects ~255/256 outputs with
  one hash), then full derivation check; decrypt amount; verify it against the
  commitment before trusting it.
- **Spending**: pick real output, sample 15 decoys with a **gamma distribution over
  output age** projected through `output_distribution` (mirror Monero's sampler — this
  is empirically the hardest thing to get right; a bad sampler is the #1 practical
  deanonymization vector). Build pseudo-commitments, CLSAGs, aggregated Bulletproof
  (~50–150 ms total on a laptop — fine), submit via `author_submitExtrinsic`.
- **View-only wallets** work by construction (give `a`, keep `b` offline) — this is the
  auditability story for exchanges/merchants.

### 5.3 Light clients

- Substrate light clients (smoldot) sync headers; the runtime API + view tags make
  remote scanning cheap, but a *trusted-server* scanning model leaks the view key to the
  server. Ship three tiers: full node (private), smoldot + own scanning of block bodies
  (private, more bandwidth), and delegated view-key scanning (convenient, documented
  trust trade-off).
- Warp sync works (PoW headers chain-verify); state sync is small because the hot state
  is just the key-image and output maps.

---

## 6. Implementation Plan (Phased)

**Phase 0 — Skeleton (1–2 wk).** Fork solochain template @ `polkadot-stable2606`; strip
to system+timestamp; CI, toolchain pinning, `cargo deny`.

**Phase 1 — Transparent UTXO core (2–3 wk).** `pallet-ringct` with *plaintext* amounts
and single-key signatures (ring size 1, no commitments): output set, global indices,
key-image-style nullifiers, unsigned-tx validation, coinbase inherent, fees. This
de-risks all the FRAME/txpool/inherent plumbing before any hard crypto. Full unit tests.

**Phase 2 — Confidential amounts (2–3 wk).** Pedersen commitments + aggregated
Bulletproofs + balance equation + encrypted amounts. Introduce the
`verify_bulletproof_batch` host function and its versioning story. Property tests:
∀ valid tx passes; mutate any byte ⇒ fails.

**Phase 3 — Rings + stealth (4–6 wk).** CLSAG (vendor/port `monero-clsag` from
monero-serai onto Ristretto), key images, `verify_clsag` host function, stealth address
derivation + view tags in the wallet, gamma decoy sampler, `SPENDABLE_AGE` rules.
Cross-test CLSAG vectors against Monero's (adjusted for Ristretto).

**Phase 4 — Consensus + integration (3–4 wk).** RandomX PoW, difficulty pallet, emission
curve, testnet ("**kohl-ash**"), chaos testing (reorgs, spam at min fee, huge rings of
immature outputs), block-weight limits sized from real host-function benchmarks
(`frame-benchmarking` on the pallet, criterion on the host fns).

**Phase 5 — Hardening (ongoing).** External cryptography audit (non-negotiable — §9.1),
fuzzing (`cargo-fuzz` on tx decoding + verification), privacy analysis (simulate
chain-analysis attacks against the decoy sampler), docs, fair-launch announcement with
≥ 2 weeks public notice + published genesis.

**Known challenges & mitigations**

| Challenge | Mitigation |
|---|---|
| WASM crypto performance | host functions (§1.6); batch verification; block weight budgeted from benchmarks |
| Storage growth (outputs/key images never pruned) | ~150 B/output; at 10 tx/block/min ≈ 2–3 GiB/yr — acceptable; paged storage maps; document pruning non-options honestly |
| CLSAG implementation risk | reuse monero-serai code, differential-test against Monero, audit |
| Decoy-selection deanonymization | copy Monero's battle-tested sampler; ban immature/duplicate members at consensus level |
| `sc-consensus-pow` maintenance | pin stable SDK; keep the PoW surface small; budget upkeep |
| Fee spam (no accounts) | min fee-per-byte + `provides`-based txpool dedup + bounded tx size |

---

## 7. Code Skeletons

### 7.1 Workspace `Cargo.toml` (excerpt)

```toml
[workspace]
members = ["node", "runtime", "pallets/ringct", "primitives/ringct-crypto", "wallet"]
resolver = "2"

[workspace.dependencies]
# Polkadot SDK — pin every crate to the same stable tag
frame-support   = { git = "https://github.com/paritytech/polkadot-sdk", tag = "polkadot-stable2606", default-features = false }
frame-system    = { git = "https://github.com/paritytech/polkadot-sdk", tag = "polkadot-stable2606", default-features = false }
sp-runtime      = { git = "https://github.com/paritytech/polkadot-sdk", tag = "polkadot-stable2606", default-features = false }
sp-runtime-interface = { git = "https://github.com/paritytech/polkadot-sdk", tag = "polkadot-stable2606", default-features = false }
sc-consensus-pow = { git = "https://github.com/paritytech/polkadot-sdk", tag = "polkadot-stable2606" }

# Crypto (primitives crate: no_std for types, std for proving/host side)
curve25519-dalek = { version = "4", default-features = false }
bulletproofs     = { version = "4", default-features = false }
merlin           = { version = "3", default-features = false }
blake2           = { version = "0.10", default-features = false }
zeroize          = { version = "1", default-features = false }
subtle           = { version = "2", default-features = false }

# Node-only
randomx-rs = { git = "https://github.com/tari-project/randomx-rs" }
```

### 7.2 Host functions (`primitives/ringct-crypto`)

```rust
#[sp_runtime_interface::runtime_interface]
pub trait RingCtVerify {
    /// CLSAG over Ristretto. `ring` = (one_time_key, commitment) pairs.
    fn verify_clsag_v1(
        msg: &[u8; 32],
        ring: &[([u8; 32], [u8; 32])],
        pseudo_commitment: &[u8; 32],
        key_image: &[u8; 32],
        sig: &[u8],
    ) -> bool { native::clsag::verify(msg, ring, pseudo_commitment, key_image, sig) }

    /// One aggregated Bulletproof per tx; batched across the block by the caller.
    fn verify_bulletproof_v1(proof: &[u8], commitments: &[[u8; 32]]) -> bool {
        native::bp::verify(proof, commitments)
    }
}
```

### 7.3 Pallet skeleton (`pallets/ringct/src/lib.rs`)

```rust
#![cfg_attr(not(feature = "std"), no_std)]

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        #[pallet::constant] type RingSize: Get<u32>;          // 16
        #[pallet::constant] type SpendableAge: Get<BlockNumberFor<Self>>; // 10
        #[pallet::constant] type MinFeePerByte: Get<u64>;
        type WeightInfo: WeightInfo;
    }

    // storage items as in §3.2 …

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// The only user-facing operation on this chain.
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::transfer(tx.inputs.len() as u32, tx.outputs.len() as u32))]
        pub fn transfer(origin: OriginFor<T>, tx: TransferTx) -> DispatchResult {
            ensure_none(origin)?;                // unsigned only
            Self::verify_shape(&tx)?;            // §3.4 step 1
            let rings = Self::load_and_check_rings(&tx)?;         // steps 2a–2d
            let msg = Self::signing_hash(&tx);
            for (input, ring) in tx.inputs.iter().zip(&rings) {
                ensure!(
                    ringct_verify::verify_clsag_v1(
                        &msg, ring, &input.pseudo_commitment,
                        &input.key_image, &input.clsag),
                    Error::<T>::ClsagInvalid
                );
            }
            Self::check_balance(&tx)?;           // step 3: Σ C' = Σ C + fee·H
            ensure!(
                ringct_verify::verify_bulletproof_v1(
                    &tx.range_proof,
                    &tx.outputs.iter().map(|o| o.commitment).collect::<Vec<_>>()),
                Error::<T>::RangeProofInvalid
            );
            Self::apply(tx)                      // step 5: key images, outputs, fees, event
        }

        /// Inherent only — block author claims reward + fees as new outputs.
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::coinbase())]
        pub fn coinbase(origin: OriginFor<T>, outputs: BoundedVec<Output, T::MaxOutputs>) -> DispatchResult {
            ensure_none(origin)?;
            Self::check_coinbase(&outputs)?;     // Σ public amounts == reward + fees; C == a·H
            Self::apply_coinbase(outputs)
        }
    }

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;
        fn validate_unsigned(src: TransactionSource, call: &Self::Call) -> TransactionValidity {
            let Call::transfer { tx } = call else { return InvalidTransaction::Call.into() };
            Self::prevalidate_cheap(tx)?;        // shape, fee floor, unspent key images
            ValidTransaction::with_tag_prefix("RingCt")
                .and_provides(tx.inputs.iter().map(|i| i.key_image).collect::<Vec<_>>())
                .priority(tx.fee / tx.encoded_size() as u64)
                .longevity(64)
                .propagate(true)
                .build()
        }
    }
}
```

### 7.4 Runtime wiring (`runtime/src/lib.rs` excerpt)

```rust
impl pallet_ringct::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RingSize = ConstU32<16>;
    type SpendableAge = ConstU32<10>;
    type MinFeePerByte = ConstU64<1_000>;
    type WeightInfo = pallet_ringct::weights::SubstrateWeight<Runtime>;
}

construct_runtime!(
    pub enum Runtime {
        System:    frame_system,
        Timestamp: pallet_timestamp,
        Difficulty: pallet_difficulty,
        RingCt:    pallet_ringct,
        Sudo:      pallet_sudo,   // burned at block N_launch + K (published in advance)
    }
);
```

### 7.5 Chain spec / genesis notes

Genesis holds no balances — only initial PoW difficulty, `MinFeePerByte`, and the sudo
key with its committed burn height. Publish the full chain spec JSON + genesis hash
before launch; anyone can mine block 1.

---

## 8. Tokenomics & Economics (Light)

- **Unit**: 1 KOHL = 10⁸ atomic units (`u64` amounts ⇒ max supply must fit; see below).
- **Emission** (Monero-style smooth curve): `reward(h) = max(TAIL, (S_max − emitted) >> 19)`
  per 60 s block, `S_max ≈ 92 × 10⁶ KOHL`, tail `TAIL = 0.3 KOHL/block` forever.
  Rationale: front-loaded but decade-long distribution; **tail emission guarantees a
  perpetual security budget** — a privacy chain cannot rely on a fee market alone
  because you cannot see fee-paying demand concentrate (and Bitcoin-style fee-only
  security is unproven). Total supply grows ~0.9 %→asymptotically-0 %/yr — cash-like.
- **Fees to miners, not burned** (§3.6): burning fees under tail emission would be pure
  deflation theater and weakens inclusion incentives.
- **Supply auditability**: `Emitted` is public and exact — the chain proves no hidden
  inflation *given sound range proofs*; that conditionality is exactly why the
  Bulletproofs implementation gets audited first (a broken range proof = invisible
  infinite mint, the worst failure mode of any CT chain — cf. the Zcash counterfeiting
  vulnerability, fixed 2019).
- **Coinbase maturity** 60 blocks; coinbase outputs are public-amount (Monero-style) and
  enter the private set on first spend.
- No premine, no dev tax at protocol level. If you want sustainable funding, do it
  socially (donations) — protocol-level dev fees are both a fairness and a regulatory
  liability for a privacy chain.

---

## 9. Risks, Limitations & Recommendations

### 9.1 Cryptographic security

- **Mandatory external audit** of: CLSAG port (signature soundness + linkability),
  host-function boundary (serialization = consensus!), balance equation, Bulletproof
  integration (generator choice `H = hash_to_point("kohl.H")`, NUMS — never a scalar
  multiple of `G` with known discrete log, or amounts can be forged). Budget ≥ 2
  independent reviews before mainnet.
- Ristretto removes the cofactor bug class, but **key-image domain separation** and
  transcript binding (every tx field inside the CLSAG message hash) still need care —
  malleability of any unsigned field is a consensus-split vector.
- Fuzz the decoder: unsigned extrinsics mean *anyone* can feed the verifier bytes.

### 9.2 Privacy limitations (be honest in the docs)

- Ring signatures give a **plausible-deniability set of 16**, not cryptographic
  unlinkability like a Sapling-style pool. Known attack classes carry over from Monero:
  black-marble flooding (attacker mints outputs to dilute decoys), timing/decoy-sampling
  statistics, EAE (exchange-attacker-exchange) correlation. Mitigations: exact Monero
  sampler, mandatory uniform tx shape (pad to 2 outputs like Monero), `SPENDABLE_AGE`.
- Network-layer leakage: Dandelion++ stem/fluff diffusion is enabled on the
  node (`node/src/dandelion/`); still run Tor/i2p for defence in depth — see
  [docs/tor-runbook.md](docs/tor-runbook.md).

### 9.3 Alternatives & future work

- If ring-size limits become the binding privacy constraint, the upgrade path is a
  **full-chain-membership-proof pool** (à la Monero's planned FCMP++ / Curve Trees or a
  Halo2 shielded pool) — the output/nullifier storage model in this design is already
  the right substrate for that migration, which is a major reason to prefer it over an
  account-model hack now.
- Seraphis/Jamtis (Monero's next-gen tx protocol) is worth tracking for address-scheme
  improvements before freezing the address format.

### 9.4 Regulatory

Privacy coins face exchange delistings and jurisdiction-specific restrictions (e.g.,
EU MiCA trajectory, prior delistings of XMR). This blueprint is technology; launch,
distribution, and operation need competent legal review in the relevant jurisdictions.
Design choices that help legitimate use: **view keys** (user-controlled selective
disclosure/audit), public total supply, no built-in mixer semantics for third-party
funds — every user only ever spends their own outputs.

### 9.5 Scalability

60 s blocks, ~2–4 KiB per 2-in/2-out tx (dominated by 16-member rings + BP). With
batch verification a mid-range node verifies hundreds of tx/s natively — throughput will
bottleneck on bandwidth/storage before CPU. Dynamic block-weight (Monero-style
median-based growth with a reward penalty) is the Phase 5 answer to fee spikes; keep the
base limit conservative (300 KiB) at launch.

---

## References

- CryptoNote v2.0 — van Saberhagen, 2013 · [whitepaper](https://web.archive.org/web/20201028121818/https://cryptonote.org/whitepaper.pdf)
- Ring Confidential Transactions — S. Noether, 2016 · [eprint 2015/1098](https://eprint.iacr.org/2015/1098)
- Bulletproofs — Bünz et al., 2017 · [eprint 2017/1066](https://eprint.iacr.org/2017/1066)
- CLSAG — Goodell, Noether, RandomRun, 2019 · [eprint 2019/654](https://eprint.iacr.org/2019/654)
- Monero empirical traceability — Möser et al., 2018 · [arXiv 1704.04299](https://arxiv.org/abs/1704.04299)
- Polkadot SDK · [repo](https://github.com/paritytech/polkadot-sdk) · [release registry](https://github.com/paritytech/release-registry) · [solochain template](https://github.com/paritytech/polkadot-sdk-solochain-template) · [docs](https://docs.polkadot.com/)
- Kulupu (Substrate PoW reference) · [repo](https://github.com/kulupu/kulupu)
- RandomX · [tevador/RandomX](https://github.com/tevador/RandomX) · [randomx-rs](https://github.com/tari-project/randomx-rs)
- curve25519-dalek / bulletproofs / merlin · [dalek](https://github.com/dalek-cryptography) · [zkcrypto fork](https://github.com/zkcrypto/bulletproofs)
- monero-serai (Rust CLSAG) · [serai-dex/serai](https://github.com/serai-dex/serai)
- ZeroPool · [zeropool.network](https://zeropool.network) · Manta · [manta.network](https://manta.network)
