# Glossary: Monero privacy & the kohl chain

This document is a **learning guide**, not a consensus specification.
Consensus rules live in `BLUEPRINT.md` and the Rust code.
Here the goal is: *why* each piece exists, *how* the pieces fit, and *what*
the math is doing — with small Python examples you can run with only the
standard library.

**Conventions used in the Python toys**

- Real Monero/kohl use the **Ristretto** group over Curve25519 (prime order,
  32-byte points/scalars). That is hard to reimplement correctly in pure
  Python, so examples use a **toy cyclic group**: integers mod a small prime
  `p`, with generator `G`. The *shapes* of the protocols match; the numbers
  do not secure anything.
- Multiplication of a point by a scalar is written `x * G` in prose and
  `(x * G) % p` in toy code.
- “Hash to scalar” is `hash(...) % (p-1)` in the toys; production uses
  domain-separated SHA-512 → canonical scalar.

```bash
# Full guided tour (diagrams + end-to-end Alice→Bob payment):
python3 examples/learn_ringct.py

# CLSAG verification loop only / silent self-tests:
python3 examples/learn_ringct.py --clsag
python3 examples/learn_ringct.py --check
```

Inline snippets below are also self-contained if you prefer a REPL.

---

## 0. The big picture (read this first)

### What problem is Monero solving?

On Bitcoin, a transaction says:

> Address A paid Address B **exactly 1.5 BTC**.

Anyone can follow coins forever (traceability), see balances, and link
senders to receivers. Monero (and **kohl**) make a transfer look like:

> *Someone* in a set of plausible past outputs spent *something*; *someone*
> received *some amount*; the chain can still check no double-spend and no
> inflation.

That is achieved with **three pillars**:

| Pillar | Hides… | Mechanism |
|--------|--------|-----------|
| **Sender anonymity** | *Which* past output was spent | **FCMP** full mature-set membership (+ CLSAG SA+L inside interim proofs) |
| **Receiver privacy** | *Who* was paid | **Stealth / one-time addresses** |
| **Amount confidentiality** | *How much* moved | **Pedersen commitments** + **range proofs** (Bulletproofs) |

**Double-spend prevention** uses **key images** (linkable nullifiers): the
chain learns “this secret key was used once” without learning *which* mature
output it was among the anonymity set.

### How kohl relates to Monero

| | Monero | kohl |
|---|---|---|
| Privacy model | CryptoNote + RingCT + CLSAG (FCMP++ planned) | Same pillars; **FCMP-only spends** pre-launch |
| Curve / group | ed25519 (cofactor 8) | **Ristretto** (prime order; fewer historical footguns) |
| Engine | Custom C++ node | **Polkadot SDK / Substrate** (Rust) |
| Consensus | RandomX PoW | RandomX PoW (dev path may use a hasher fallback) |
| Money model | Outputs + key images | Same, inside `pallet-ringct` + membership tree |
| Address compatible with Monero? | — | **No** (different group + domains) |

Think of kohl as: *Monero-shaped cash, reimplemented as a Substrate solochain*,
with **full-chain membership** as the production spend path (interim n≤64).

### Life of one private transfer (kohl)

```text
Wallet (sender)                         Chain (pallet-ringct)
─────────────────                       ─────────────────────
1. Pick real output(s) you own
2. Fetch membership root + digests
3. Build pseudo-commitments C'
4. Build FCMP0001 proof (membership
   under root + SA+L / key image)
5. Build Bulletproof on outputs
6. Encrypt amount for receiver
7. Submit unsigned extrinsic  ──────►  verify shape + root window
                                       verify_fcmp_v1 per input
                                       verify Σ C' = Σ C_out + fee·H
                                       verify range proof
                                       insert key images
                                       append outputs + grow tree
```

There is **no account**, **no nonce**, **no signature from an “address”**.
The **FCMP proof** *is* the authorization. (No wallet decoy ring.)

---

## 1. Mental models & elementary crypto

### Group / elliptic curve / Ristretto

**Term:** algebraic structure where you can add “points” and multiply a
point by a scalar (integer). Hard problem: given `P = x·G`, find `x`
(discrete log).

| Term | Meaning |
|------|---------|
| **Generator `G`** | Fixed public base point; “1” of the group |
| **Scalar** | Secret integer in `0..order-1` (private key material) |
| **Point** | Public value `x·G` (public key, commitment piece, …) |
| **ed25519** | Curve Monero uses; has **cofactor 8** (some points have small order) |
| **Ristretto** | Encoding of a **prime-order** group on the same curve family; every decoded point is “safe”. **kohl uses this everywhere** |

**Why Ristretto in kohl?** Monero has historically needed careful
small-subgroup checks on key images. Ristretto removes that class of bugs
by construction (see blueprint §2.2).

```python
# Toy group: multiples of G mod p. Discrete log is easy here (tiny p) —
# only for learning the algebra of protocols.
p = 101          # prime modulus (toy)
G = 3            # generator (toy)
order = 100      # for demo; real groups have huge prime order

def point_mul(scalar: int, point: int = G) -> int:
    return pow(point, scalar, p)  # multiplicative notation: g^x mod p

def point_add(p1: int, p2: int) -> int:
    return (p1 * p2) % p          # g^a * g^b = g^{a+b}

# Keypair
x = 17                            # secret
P = point_mul(x)                  # public P = G^x
print("secret x =", x, "public P =", P)

# Shared secret (Diffie–Hellman): a*B = b*A
a, b = 5, 9
A, B = point_mul(a), point_mul(b)
assert point_mul(a, B) == point_mul(b, A)
print("DH shared =", point_mul(a, B))
```

---

### Hash-to-scalar `Hs` and hash-to-point `Hp`

| Symbol | Role |
|--------|------|
| **`Hs(data)`** | Hash → scalar (used in challenges, derivation) |
| **`Hp(P)`** | Hash → point (used in **key images**: `I = x·Hp(P)`) |

Domain separation matters: kohl prefixes strings like `kohl/clsag/hp/v1` so
the same bytes never mean two different things.

```python
import hashlib

def hs(*parts: bytes, mod: int = order) -> int:
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return int.from_bytes(h.digest(), "big") % mod

def hp(point_bytes: bytes) -> int:
    # Toy: map hash to a group element. Real: Ristretto Elligator.
    return point_mul(hs(b"hp", point_bytes) or 1)

P_bytes = P.to_bytes(1, "big")
print("Hs =", hs(b"msg", P_bytes), "Hp(P) =", hp(P_bytes))
```

---

### NUMS (Nothing-Up-My-Sleeve) point `H`

Second generator **`H`**, independent of `G`: nobody should know `h` with
`H = h·G`. If they did, they could open the same commitment to two amounts
and forge money.

In kohl, `H` is derived as a hash-to-point of a fixed string
(`kohl/pedersen/value-generator/v1`), not a random trusted setup.

```python
H = point_mul(hs(b"NUMS-H") or 1)  # toy NUMS
print("G =", G, "H =", H)
```

---

## 2. Money model (UTXO, not accounts)

### UTXO / output / TXO

**UTXO** = Unspent Transaction Output.

Bitcoin: “coins” are discrete outputs you fully spend (or change yourself).
Monero/kohl: same idea, but each output is a **one-time key + commitment**,
not an address balance.

**Substrate account model** (default FRAME): each `AccountId` has a nonce and
balance in `pallet-balances`. **kohl deliberately omits that** for user
money — value lives only in `pallet-ringct`’s output set.

### Global output index

Every output ever created gets a permanent index `0, 1, 2, …`.
Rings refer to members by these `u64` indices (compact), not full keys.
Outputs are **never deleted** (they remain as decoys forever).

### Coinbase

Block reward + fees minted by the miner. In Monero/kohl:

- Coinbase **amounts are public** (and commitments use zero blinding).
- After the first spend into a ring, value is confidential.

**Maturity:** kohl uses longer lock for coinbase (`CoinbaseMaturity = 60`
blocks) vs normal outputs (`SpendableAge = 10`).

### Fee

The **only public amount** in a normal transfer. Enforced by the balance
equation (lying about fee breaks the equation). Paid to the **next block’s
miner** via coinbase, not burned.

### Emission / tail emission

New coins from mining follow a smooth Monero-like curve, then a perpetual
**tail reward** so miners always have a security budget even if fees are low.

```python
ATOMIC = 100_000_000
MAX_CURVE = 92_000_000 * ATOMIC
TAIL = 3 * ATOMIC // 10
SHIFT = 19

def block_reward(emitted: int) -> int:
    curve = (MAX_CURVE - emitted) >> SHIFT if emitted < MAX_CURVE else 0
    return max(TAIL, curve)

print("block 0 reward (KOHL) ≈", block_reward(0) / ATOMIC)
print("late reward =", block_reward(MAX_CURVE) / ATOMIC, "KOHL (tail)")
```

---

## 3. Pillar 1 — Sender anonymity

### FCMP (full-chain membership proofs)

**Production sender anonymity on kohl.** A spend proves the real input is one of
**all mature (admitted) outputs** under a published Merkle root — not a
wallet-chosen ring of 16. Interim wire format **`FCMP0001`**: Path A digests +
CLSAG SA+L over the full non-EMPTY set (n≤64). See `docs/fcmp-design.md`.

| Term | Meaning |
|------|---------|
| **Membership root** | 32-byte Merkle root anchored in the tx |
| **Admitted / non-EMPTY** | Mature leaf `L(P,C)` openable by the proof |
| **EMPTY** | Immature slot; not in the mature set |
| **FCMP0001** | Interim proof tag (O(n); Path B for large n) |

### Ring signature (historical / SA+L building block)

A signature that proves: *“I know the private key of **one** of these public
keys”* without revealing which.

**Ring** = list of public keys (in Monero / inside kohl FCMP0001: mature outputs’
one-time keys paired with their commitments).

| Term | Meaning |
|------|---------|
| **Real member** | The output you actually spend |
| **Decoy / mixin** | Other outputs that could plausibly be the spend (historical ring path) |
| **Ring size** | Historical fixed rings: **16**. Production FCMP0001 uses full mature set ≤ **64** |
| **Anonymity set** | For FCMP: full mature set at the root (≤64 interim) |

### Linkable ring signature

Ordinary rings hide which key signed. **Linkable** rings also publish a
**key image** so that signing twice with the same key is detectable —
without revealing *which* ring member was used.

That is exactly the double-spend tool Monero and kohl need.

### MLSAG vs CLSAG

| | **MLSAG** | **CLSAG** |
|---|-----------|-----------|
| Full name | Multilayered Linkable Spontaneous Anonymous Group | Concise Linkable Spontaneous Anonymous Group |
| Era | Pre-2020 Monero | Monero since 2020; **kohl SA+L inside FCMP0001** |
| Size / speed | Larger, slower | Smaller, faster, same assumptions |
| Paper | — | Goodell–Noether–RandomRun, eprint 2019/654 |

**kohl uses CLSAG as the SA+L layer inside FCMP0001**, not as a standalone
ring-16 transfer path.

### Key image

```text
I = x · Hp(P)
```

where `P = x·G` is the one-time public key you spend.

Properties:

1. **Deterministic** for a given `x` → same spend always same `I`.
2. **Ring-independent** → different decoy sets still link.
3. **Does not reveal** which ring member is real (to an observer who does not
   already know `x`).
4. Chain stores all `I` forever; duplicate `I` ⇒ reject.

```python
def key_image(x: int, P: int) -> int:
    # I = Hp(P)^x   (multiplicative toy)
    return pow(hp(P.to_bytes(1, "big")), x, p)

x = 17
P = point_mul(x)
I1 = key_image(x, P)
I2 = key_image(x, P)
assert I1 == I2
print("key image I =", I1)

# Different secret → different image
assert key_image(18, point_mul(18)) != I1
```

### Pseudo-output commitment `C'`

When amounts are hidden, CLSAG does not only prove key ownership. For each
input it also proves:

```text
C_real − C' = z · G
```

for some secret `z` (blinding difference). So `C'` commits to the **same
amount** as the real ring member’s commitment, under a **fresh blinding**.

Why? So the transaction can check:

```text
Σ C'_inputs  ==  Σ C_outputs  +  fee · H
```

without revealing which ring commitment was the real input.

```python
def commit(amount: int, blinding: int) -> int:
    # C = H^amount * G^blinding   (toy)
    return (pow(H, amount, p) * pow(G, blinding, p)) % p

amount = 50
x_in = 3          # input blinding
C = commit(amount, x_in)
x_pseudo = 9      # fresh
C_prime = commit(amount, x_pseudo)
# C / C' = G^{x_in - x_pseudo}  → difference is only on G, amount cancels
z = (x_in - x_pseudo) % order
assert (C * pow(C_prime, p - 2, p)) % p == pow(G, z, p)
print("C =", C, "C' =", C_prime, "z =", z)
```

### Decoy selection / gamma sampler

Choosing decoys badly is the #1 *practical* deanonymization vector.
Monero samples decoys with a distribution over **output age** (gamma-shaped
heuristic from empirical chain analysis). Immature outputs are banned as
ring members (`SpendableAge`).

kohl’s wallet is responsible for sampling; the chain only enforces
shape/maturity rules.

### CLSAG (what the verifier checks, intuitively)

For a ring of pairs `(P_i, C_i)`, message `m`, key image `I`, pseudo `C'`,
signature `(c₀, s₀…sₙ₋₁, D)`:

> There exists an undisclosed index `ℓ` such that the signer knows `x, z`
> with `P_ℓ = x·G`, `I = x·Hp(P_ℓ)`, and `C_ℓ − C' = z·G`.

kohl runs this in a **native host function** (`verify_clsag_v1`) because pure
WASM would be too slow at block verification.

```python
# Extremely simplified "ring proof" toy — NOT CLSAG, only the idea:
# prove knowledge of one secret among a list without saying which.

def toy_ring_sign(secrets_and_pubs, real_index, message: bytes):
    """secrets_and_pubs: list of (x_i or None, P_i). Only real has x."""
    n = len(secrets_and_pubs)
    x, P_real = secrets_and_pubs[real_index]
    assert point_mul(x) == P_real
    # Fake challenges/responses for decoys; close the ring at real index.
    s = [hs(b"s", bytes([i])) for i in range(n)]
    c = [0] * n
    # Start after real
    i = (real_index + 1) % n
    c[i] = hs(b"c0", message, P_real.to_bytes(1, "big"))
    while i != real_index:
        # L = G^s * P^c  (toy verification equation shape)
        L = (pow(G, s[i], p) * pow(secrets_and_pubs[i][1], c[i], p)) % p
        nxt = (i + 1) % n
        c[nxt] = hs(b"c", message, L.to_bytes(2, "big"))
        i = nxt
    # Solve for real s:  L = G^s * P^c  ⇒ we set s so it consistency-holds
    # (skipped rigorous Fiat–Shamir; illustration only)
    s[real_index] = (x - c[real_index]) % order  # placeholder algebra
    return c[0], s

ring = [(None, point_mul(11)), (17, point_mul(17)), (None, point_mul(23))]
# mark decoy secrets as None
ring[0] = (None, ring[0][1])
ring[2] = (None, ring[2][1])
c0, s_vec = toy_ring_sign([(17 if i == 1 else None, ring[i][1]) for i in range(3)], 1, b"pay")
print("toy ring sig c0, s =", c0, s_vec)
```

> **Do not** use the toy above for anything real. Production CLSAG is in
> `primitives/ringct-crypto/src/clsag.rs`.

---

## 4. Pillar 2 — Receiver privacy

### Stealth address (CryptoNote dual-key)

Your **address** is two public keys:

```text
A = a·G   (view public)
B = b·G   (spend public)
```

Secrets: `a` (view), `b` (spend). In Monero/kohl wallets, `a` is usually
derived from `b` so one mnemonic restores both.

**The address never appears on chain.**

### One-time key (OTK) / output key `P`

Sender picks random **tx secret** `r`, publishes **tx public key** `R = r·G`.

For output index `i`:

```text
shared = r·A = a·R          (ECDH)
h      = Hs(shared ‖ i)
P      = h·G + B            (one-time public key on chain)
```

Receiver with `a` recomputes `shared = a·R`, derives `P'`, checks `P' == P`.
Spend secret for that output:

```text
x = h + b
```

so `P = x·G`. That `x` is what CLSAG signs with; key image uses that `x`.

```python
# Toy stealth derivation (additive group would be cleaner; we stay multiplicative)
def toy_derive(r, A, B, i=0):
    shared = pow(A, r, p)                       # r·A
    h = hs(b"otk", shared.to_bytes(2, "big"), bytes([i])) or 1
    # P = G^h * B   ≈ h·G + B
    P = (pow(G, h, p) * B) % p
    return shared, h, P

a, b = 7, 13
A, B = point_mul(a), point_mul(b)
r = 19
R = point_mul(r)
shared_s, h, P = toy_derive(r, A, B, 0)

# Receiver
shared_r = pow(R, a, p)
assert shared_s == shared_r
x = (h + b) % order
# In a true additive EC group, P = x·G. Multiplicative toy only shows ECDH + Hs.
print("R =", R, "P =", P, "spend scalar x =", x)
```

### View key vs spend key

| Key | Can do |
|-----|--------|
| **View key `a`** | Scan chain, detect incoming outputs, decrypt amounts |
| **Spend key `b`** | Authorize spends (with view key to compute `x`) |

**View-only wallet:** give a merchant/accountant `a` so they can audit
incoming payments without being able to steal funds.

### View tag

1-byte hint derived from the shared secret. Wallet checks the tag first;
≈255/256 outputs are rejected with one hash, then full derivation runs only
on candidates. Monero added this in 2022; kohl stores `view_tag` on each
output.

### Tx public key `R`

One per transaction (shared by its outputs). Required for scanning.
In kohl, `TransferTx.tx_pubkey` is this `R`.

### Encrypted amount / payload

Receiver must learn `amount` (and blinding) without putting them in cleartext.
Typical pattern (Monero-style):

```text
amount_enc = amount XOR Hs_amount(shared ‖ i)   # 8 bytes
```

kohl stores an opaque **`payload`** on outputs; the wallet convention is the
masked amount (+ blinding derived from shared secret).

```python
def mask_amount(amount: int, shared: int, i: int = 0) -> int:
    mask = hs(b"amount", shared.to_bytes(2, "big"), bytes([i])) & 0xFFFFFFFFFFFFFFFF
    return amount ^ mask

def unmask_amount(enc: int, shared: int, i: int = 0) -> int:
    return mask_amount(enc, shared, i)  # XOR twice undoes

amt = 123456
enc = mask_amount(amt, shared_r, 0)
assert unmask_amount(enc, shared_r, 0) == amt
print("encrypted amount =", enc)
```

---

## 5. Pillar 3 — Amount confidentiality

### Pedersen commitment

```text
C = amount · H  +  blinding · G
```

(kohl/Monero convention: **value on `H`**, **blinding on `G`**.)

Properties:

- **Hiding:** `C` does not reveal `amount` (if blinding is random).
- **Binding:** you cannot open `C` to two different amounts without knowing
  `log_G(H)` (NUMS assumption).
- **Homomorphic:**

```text
C(a,x) + C(b,y) = C(a+b, x+y)
```

so the chain can check sums of hidden amounts.

```python
def pedersen(amount: int, blinding: int) -> int:
    return (pow(H, amount, p) * pow(G, blinding, p)) % p

c1 = pedersen(30, 4)
c2 = pedersen(20, 5)
c_sum = (c1 * c2) % p
assert c_sum == pedersen(50, 9)
print("homomorphism ok:", c_sum)
```

### Commitment balance equation (RingCT)

```text
Σ C'_inputs  =  Σ C_outputs  +  fee · H
```

Fee has **no blinding** (public). If amounts and blindings both balance,
points match; if someone tries to create money, the equation fails (unless
they break the range proof / discrete log).

```python
fee = 2
in_amt, out1, out2 = 100, 60, 38
assert in_amt == out1 + out2 + fee

x_in = 10
x1, x2 = 3, 7
# last blinding chosen so sum blindings match
# x_in = x1 + x2  (fee has blinding 0)
assert x_in == x1 + x2

C_in = pedersen(in_amt, x_in)
C_o1 = pedersen(out1, x1)
C_o2 = pedersen(out2, x2)
fee_point = pow(H, fee, p)
right = (C_o1 * C_o2 * fee_point) % p
assert C_in == right
print("balance equation holds")
```

### Range proof

Commitments alone allow **negative amounts** (e.g. open −1000 and +1000
elsewhere) which mints coins. A **range proof** shows:

```text
amount ∈ [0, 2^64)
```

without revealing the amount.

### Bulletproofs / Bulletproofs+

Modern short range proofs (Bünz et al.). Logarithmic size in bit length;
aggregation proves many outputs in one proof.

| Term | Meaning |
|------|---------|
| **Bulletproof** | Range proof system used by Monero and kohl |
| **Aggregated proof** | One proof for all outputs of a tx |
| **Batch verification** | Verify many proofs faster together (kohl: per-tx aggregate; block-wide batch is future work) |

kohl: `verify_range_proof_v1` host function; transcript label
`kohl/rangeproof/v1`.

### RingCT

**Ring Confidential Transactions** = rings + commitments + range proofs
(+ key images). Name of the Monero privacy upgrade and of kohl’s pallet:
`pallet-ringct`.

---

## 6. End-to-end toy: one private payment

This stitches pillars together at story level (still toy crypto).

```python
"""
Alice pays Bob 40 units, fee 2, using one input of 42.
Ring size 3 (1 real + 2 decoys). Amounts hidden from observers.
"""
import hashlib

p, G = 101, 3
order = 100
H = pow(G, 11, p)  # pretend NUMS

def hs(*parts):
    h = hashlib.sha256(b"|".join(parts)).digest()
    return int.from_bytes(h, "big") % order or 1

def commit(a, x):
    return (pow(H, a, p) * pow(G, x, p)) % p

# --- Bob's stealth address ---
a_view, b_spend = 5, 8
A, B = pow(G, a_view, p), pow(G, b_spend, p)

# --- Alice's unspent output (the "real" one) ---
x_alice = 14
P_alice = pow(G, x_alice, p)
amt_in, blind_in = 42, 6
C_alice = commit(amt_in, blind_in)

# Decoys from chain history (Alice does not know their secrets)
decoys = [
    (pow(G, 21, p), commit(10, 1)),
    (pow(G, 22, p), commit(99, 2)),
]
ring = decoys + [(P_alice, C_alice)]  # real at index 2
real_index = 2

# --- Pseudo commitment (re-blind amount) ---
blind_pseudo = 9
C_pseudo = commit(amt_in, blind_pseudo)

# --- Outputs: Bob gets 40; (no change for simplicity) ---
fee = 2
amt_out = 40
assert amt_in == amt_out + fee
blind_out = blind_pseudo  # single out absorbs blinding
C_out = commit(amt_out, blind_out)
assert C_pseudo == (C_out * pow(H, fee, p)) % p
print("1) balance OK")

# --- Stealth OTK for Bob ---
r = 17
R = pow(G, r, p)
shared = pow(A, r, p)
h = hs(b"otk", shared.to_bytes(2, "big"), b"\x00")
P_bob = (pow(G, h, p) * B) % p
amount_enc = amt_out ^ hs(b"amt", shared.to_bytes(2, "big"))
print("2) Bob OTK P =", P_bob, "R =", R, "enc amount =", amount_enc)

# --- Key image of Alice's real spend ---
I = pow(hs(b"hp", P_alice.to_bytes(2, "big")) or 1, x_alice, p)
print("3) key image I =", I, "(chain stores this forever)")

# --- Bob scans ---
shared_b = pow(R, a_view, p)
assert shared_b == shared
assert (amount_enc ^ hs(b"amt", shared_b.to_bytes(2, "big"))) == amt_out
print("4) Bob detected payment of", amt_out)

# Observer sees: ring of 3, I, C_pseudo, C_out, fee, R, P_bob, proof blobs.
# Observer does NOT see: which ring member, Bob's address, or amounts (fee only).
print("5) observer learns fee =", fee, "and ring size =", len(ring))
```

---

## 7. Substrate / kohl node vocabulary

### L1 / solochain / parachain

| Term | Meaning |
|------|---------|
| **L1** | Layer-1 blockchain (its own consensus) |
| **Solochain** | Standalone Substrate chain (kohl) |
| **Parachain** | Chain secured by Polkadot relay validators (not kohl’s design) |

### Polkadot SDK / Substrate / FRAME

| Term | Meaning |
|------|---------|
| **Substrate** | Modular blockchain framework (now under Polkadot SDK) |
| **FRAME** | Pallet framework (`#[pallet]`, storage, events, errors) |
| **Runtime** | State transition function (WASM + native), upgradeable |
| **Pallet** | Runtime module (`pallet-ringct`, `pallet-difficulty`, …) |
| **Extrinsic** | Transaction / inherent submitted to a block |
| **Inherent** | Extrinsic inserted by block author (kohl: **coinbase**) |
| **Unsigned extrinsic** | No Substrate account signature; custom validation |
| **`ValidateUnsigned`** | Hook that admits RingCT transfers to the pool (legacy API; migrating to `authorize`) |

### Host function / `runtime_interface`

Heavy crypto runs **native** in the node, called from the WASM runtime like
a syscall. Required because CLSAG + Bulletproofs are too slow in interpreted
WASM. Changing a host function needs a **node upgrade**, not only a runtime
upgrade.

kohl host fns: `verify_clsag_v1`, `verify_balance_v1`, `verify_range_proof_v1`,
`value_commitment_v1`.

### PoW / RandomX / difficulty / LWMA

| Term | Meaning |
|------|---------|
| **PoW** | Proof of Work — miners burn CPU to produce blocks |
| **RandomX** | ASIC-resistant PoW algorithm (CPU-oriented), used by Monero |
| **Difficulty** | How hard the PoW target is |
| **LWMA** | Linear Weighted Moving Average — difficulty adjustment algorithm |
| **`sc-consensus-pow`** | Substrate crate wiring PoW consensus |
| **Fair launch** | Zero premine; supply starts at 0; anyone can mine block 1 |

PoS (Aura/BABE) needs an initial stake set — incompatible with kohl’s fair
launch goal.

### WASM runtime

Runtime compiles to WebAssembly for deterministic, sandboxed execution on
all nodes. Crypto host functions are **imports** into that WASM module.

---

## 8. Privacy attacks & honest limitations

| Term | Meaning |
|------|---------|
| **Traceability** | Linking which output was spent |
| **Linkability** (of users) | Linking two spends to the same person |
| **Linkability** (of key images) | Detecting two spends of the *same* output — *desired* |
| **Black-marble attack** | Adversary floods chain with outputs they own, poisoning decoy quality |
| **EAE** | Exchange–Attacker–Exchange correlation of timing/amounts metadata |
| **Dandelion++** | Tx gossip that reduces network-level origin leakage |
| **Anonymity set ≠ ring size** | Statistical analysis can reduce effective privacy |

Fixed-size ring signatures give **plausible deniability among ring members**.
kohl production uses **FCMP** (full mature set at a root; interim n≤64) — still
not a Sapling/Halo shielded pool, and not yet log-size Curve Trees.

---

## 9. kohl crate map (where code lives)

| Path | Role |
|------|------|
| `primitives/ringct-primitives` | Consensus constants, emission |
| `primitives/ringct-crypto` | FCMP0001, CLSAG SA+L, stealth, Pedersen/BP, host functions |
| `primitives/kohl-runtime-api` | RPC/runtime APIs for wallets |
| `pallets/ringct` | Monetary rules (§3.4 verification) |
| `pallets/difficulty` | LWMA difficulty state |
| `consensus/kohl-pow` | RandomX / PoW algorithm glue |
| `runtime` | Wire pallets + APIs |
| `node` | Runnable binary, miner, executor host fns |
| `wallet` | Scan, build, sign transfers |

### Signing domain / versioning

`SIGNING_DOMAIN = "kohl/transfer/v4"` is hashed into every FCMP transfer
message. Changing tx semantics requires bumping this (and often host fn
`*_v1` → `*_v2`) so old blocks stay unambiguously defined.

---

## 10. Acronym quick index

| Acronym | Expansion | One-line |
|---------|-----------|----------|
| **ASIC** | Application-Specific Integrated Circuit | Specialized mining hardware |
| **BP** | Bulletproof(s) | Short range proof |
| **CLSAG** | Concise Linkable Spontaneous Anonymous Group | Linkable ring sig; used inside FCMP0001 SA+L |
| **FCMP** | Full-Chain Membership Proof | Mature-set membership spend path |
| **CPU** | Central Processing Unit | RandomX target hardware |
| **CT** | Confidential Transactions | Hidden amounts via commitments |
| **DH / ECDH** | (Elliptic Curve) Diffie–Hellman | Shared secret `r·A = a·R` |
| **EAE** | Exchange–Attacker–Exchange | Metadata correlation attack |
| **FRAME** | Framework for Runtime Aggregation of Modularized Entities | Substrate pallet system |
| **GRANDPA** | GHOST-based Recursive ANcestor Deriving Prefix Agreement | Substrate finality gadget (not used for kohl block production) |
| **KI** | Key Image | Double-spend nullifier `I = x·Hp(P)` |
| **L1** | Layer 1 | Base blockchain |
| **LWMA** | Linear Weighted Moving Average | Difficulty adjustment |
| **MLSAG** | Multilayered Linkable Spontaneous Anonymous Group | Pre-CLSAG Monero rings |
| **NUMS** | Nothing Up My Sleeve | Transparent generator derivation |
| **OTK** | One-Time Key | Stealth output public key `P` |
| **PoS** | Proof of Stake | Stake-based consensus |
| **PoW** | Proof of Work | Mining-based consensus |
| **RingCT** | Ring Confidential Transactions | Historical name; kohl uses CT + FCMP spends |
| **RPC** | Remote Procedure Call | Node API for wallets |
| **SDK** | Software Development Kit | Polkadot SDK |
| **TXO / UTXO** | (Unspent) Transaction Output | Coin unit of the UTXO model |
| **WASM** | WebAssembly | Runtime bytecode |
| **XOR** | Exclusive or | Used in simple amount masking |

---

## 11. Symbol cheat sheet (Monero / kohl math)

| Symbol | Meaning |
|--------|---------|
| `G` | Base generator (blinding / keys) |
| `H` | NUMS value generator |
| `a, A` | View secret / view public |
| `b, B` | Spend secret / spend public |
| `r, R` | Tx secret / tx public key |
| `P` | One-time output key |
| `x` | One-time spend secret (`x = Hs(…) + b`) |
| `I` | Key image |
| `C` | Pedersen commitment |
| `C'` | Pseudo-output commitment (per input) |
| `fee` | Public fee amount |

**kohl balance:**

```text
Σ C'_i  =  Σ C_j  +  fee · H
```

**kohl FCMP (per input):** membership under `membership_root` + knowledge of one
mature member’s `x` and blinding difference tying `C` to `C'`, with key image `I`.

---

## 12. Suggested reading order

1. This glossary §0–§2 (picture + UTXO).
2. Python §3 key image + §5 Pedersen balance.
3. Python §4 stealth + §6 end-to-end toy.
4. `BLUEPRINT.md` §1 and §3.4 (exact chain rules).
5. `primitives/ringct-crypto/src/{stealth,fcmp,clsag}.rs` and
   `pallets/ringct/src/lib.rs` (`verify_transfer`).
6. `docs/fcmp-design.md` and papers: CryptoNote (2013), RingCT (2015/1098),
   Bulletproofs (2017/1066), CLSAG (2019/654), Curve Trees (2022/756).

---

## 13. FAQ

**Why can the chain not steal or freeze my funds?**  
There is no admin key over outputs. Only the one-time secret `x` produces a
valid FCMP spend (key image + membership). (Launch may temporarily use
`sudo` for upgrades — blueprint says burn it.)

**Why is the fee public?**  
Someone must pay miners; making fee public keeps the balance equation simple
and the fee market observable without revealing transfer amounts.

**Why not zk-SNARKs like Zcash?**  
Different tradeoff: no trusted setup for this stack, Monero-shaped keys and
nullifiers. FCMP targets full mature-set membership; Curve Trees / Path B scale
further without a SNARK pool (blueprint §9.3).

**Is kohl “as private as Monero”?**  
Same *pillars* (sender / receiver / amount). Production spends are **FCMP**
(full mature set, interim n≤64) rather than ring-16 decoys. Real privacy also
needs network privacy (Tor/Dandelion++), user behavior, and eventually log-size
proofs for large trees.

**Can I reuse a Monero address or seed on kohl?**  
No. Different group (Ristretto vs raw ed25519), different domain tags, different
chain.

---

*Document version: companion to `BLUEPRINT.md` and the FCMP-only (PR-7…11) codebase.
If prose and code disagree, code + blueprint + `docs/fcmp-*.md` win.*
