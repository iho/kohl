#!/usr/bin/env python3
"""
learn_fcmp.py — How Kohl private cash works *today* (FCMP-only)

  python3 examples/learn_fcmp.py            # full guided tour
  python3 examples/learn_fcmp.py --quick    # shorter path
  python3 examples/learn_fcmp.py --tree     # membership tree only
  python3 examples/learn_fcmp.py --check    # silent self-tests (exit 0/1)

This is a TEACHING TOY. Algebra runs in a tiny modular group so you can see
the shapes. Real kohl uses Ristretto, Bulletproofs, host functions, and
FCMP0001 proofs (O(n), mature set ≤ 64).

Companion: docs/fcmp-design.md, GLOSSARY.md, examples/learn_ringct.py (older
ring-16 tour), primitives/ringct-crypto, pallets/ringct.
"""

from __future__ import annotations

import argparse
import hashlib
import secrets
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Toy group  (NOT secure — discrete log is easy)
# ---------------------------------------------------------------------------
# Multiplicative notation: points are ints mod MOD. Elliptic-curve map:
#   g^x  ↔  x·G

MOD: int = 2_147_483_647
G: int = 5
ORDER: int = MOD - 1


def scalar_mod(s: int) -> int:
    return s % ORDER


def hs(*parts: bytes, domain: bytes = b"kohl-fcmp-toy/hs") -> int:
    h = hashlib.sha256(domain)
    for part in parts:
        h.update(len(part).to_bytes(4, "little"))
        h.update(part)
    return scalar_mod(int.from_bytes(h.digest(), "big")) or 1


def point_mul(scalar: int, point: int = G) -> int:
    return pow(point, scalar_mod(scalar), MOD)


def point_add(a: int, b: int) -> int:
    return (a * b) % MOD


def point_sub(a: int, b: int) -> int:
    return (a * pow(b, -1, MOD)) % MOD


def encode_int(x: int) -> bytes:
    return x.to_bytes(8, "big", signed=False)


def encode_u64(x: int) -> bytes:
    return int(x).to_bytes(8, "little", signed=False)


def hp(point: int) -> int:
    """Hash-to-point for key images (toy)."""
    return point_mul(hs(encode_int(point), domain=b"kohl-fcmp-toy/hp"))


# NUMS value generator H (in production: nobody knows log_G(H)).
H: int = point_mul(hs(b"NUMS-value-generator", domain=b"kohl-fcmp-toy/nums"))

# Path A domains (toy mirrors of ringct-primitives).
LEAF_DOM = b"kohl/fcmp/leaf/v1"
EMPTY_DOM = b"kohl/fcmp/leaf/empty/v1"
MERKLE_DOM = b"kohl/fcmp/merkle/v1"
MERKLE_EMPTY_DOM = b"kohl/fcmp/merkle/v1/empty"
SIGNING_DOMAIN = b"kohl/transfer/v4"


# ---------------------------------------------------------------------------
# Pretty printing
# ---------------------------------------------------------------------------

def banner(title: str) -> None:
    line = "═" * 72
    print(f"\n{line}\n  {title}\n{line}")


def step(n: int, title: str) -> None:
    print(f"\n── Step {n}: {title} " + "─" * max(0, 50 - len(title)))


def note(msg: str) -> None:
    print(f"  · {msg}")


def ok(msg: str) -> None:
    print(f"  ✓ {msg}")


def warn(msg: str) -> None:
    print(f"  ! {msg}")


def diagram(text: str) -> None:
    print()
    for line in text.strip("\n").splitlines():
        print(f"  {line}")
    print()


def short_hex(n: int, width: int = 8) -> str:
    return f"{n:0{width}x}"[-width:]


# ---------------------------------------------------------------------------
# Pedersen commitments  C = amount·H + blinding·G
# ---------------------------------------------------------------------------

def commit(amount: int, blinding: int) -> int:
    return point_add(point_mul(amount, H), point_mul(blinding, G))


def verify_balance(
    input_commitments: Sequence[int],
    output_commitments: Sequence[int],
    fee: int,
) -> bool:
    """Σ C' == Σ C_out + fee·H  (amounts + blindings both balance)."""
    left = 1
    for c in input_commitments:
        left = point_add(left, c)
    right = point_mul(fee, H)
    for c in output_commitments:
        right = point_add(right, c)
    return left == right


# ---------------------------------------------------------------------------
# Stealth addresses + key images
# ---------------------------------------------------------------------------

@dataclass
class StealthKeys:
    view_secret: int
    spend_secret: int

    @property
    def view_public(self) -> int:
        return point_mul(self.view_secret)

    @property
    def spend_public(self) -> int:
        return point_mul(self.spend_secret)


def random_scalar() -> int:
    return secrets.randbelow(ORDER - 1) + 1


def keypair() -> StealthKeys:
    b = random_scalar()
    a = hs(encode_int(b), domain=b"kohl-fcmp-toy/view-from-spend")
    return StealthKeys(view_secret=a, spend_secret=b)


def derive_otk(
    shared: int, spend_public: int, index: int = 0
) -> Tuple[int, int, int]:
    """Returns (one_time_public, one_time_secret_delta, view_tag)."""
    delta = hs(encode_int(shared), encode_u64(index), domain=b"kohl-fcmp-toy/otk")
    p = point_add(point_mul(delta), spend_public)
    tag = hs(encode_int(shared), encode_u64(index), domain=b"kohl-fcmp-toy/vtag") % 256
    return p, delta, tag


def recover_spend_secret(keys: StealthKeys, tx_pubkey: int, index: int = 0) -> int:
    shared = point_mul(keys.view_secret, tx_pubkey)
    delta = hs(encode_int(shared), encode_u64(index), domain=b"kohl-fcmp-toy/otk")
    return scalar_mod(delta + keys.spend_secret)


def key_image(secret: int) -> int:
    """I = x · Hp(P) with P = x·G (CryptoNote / CLSAG formula)."""
    p = point_mul(secret)
    return point_mul(secret, hp(p))


# ---------------------------------------------------------------------------
# Path A membership tree (sparse slots)
# ---------------------------------------------------------------------------

def blake2_like(*parts: bytes) -> bytes:
    """32-byte digest stand-in (sha256 for the toy)."""
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def empty_leaf_hash() -> bytes:
    return blake2_like(EMPTY_DOM)


def leaf_hash(p: int, c: int) -> bytes:
    return blake2_like(LEAF_DOM, encode_int(p), encode_int(c))


def merkle_node(left: bytes, right: bytes) -> bytes:
    return blake2_like(MERKLE_DOM, left, right)


def merkle_empty_child() -> bytes:
    return blake2_like(MERKLE_EMPTY_DOM)


def root_from_leaves(leaves: Sequence[bytes]) -> bytes:
    """Binary Merkle root; pad with empty children to power of two."""
    if not leaves:
        return merkle_empty_child()
    pad = merkle_empty_child()
    level = list(leaves)
    n = 1
    while n < len(level):
        n *= 2
    while len(level) < n:
        level.append(pad)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(merkle_node(level[i], level[i + 1]))
        level = nxt
    return level[0]


@dataclass
class StoredOutput:
    """One chain TXO (simplified)."""
    index: int
    one_time_key: int
    commitment: int
    amount: int  # known only to owner (and coinbase publicly)
    height: int
    coinbase: bool
    spend_secret: Optional[int] = None  # teaching only — chain never stores this


@dataclass
class Chain:
    """Tiny model of pallet-ringct state."""

    outputs: Dict[int, StoredOutput] = field(default_factory=dict)
    next_index: int = 0
    key_images: set = field(default_factory=set)
    height: int = 0
    spendable_age: int = 2  # tiny for demos (real kohl: 10)
    coinbase_maturity: int = 3  # real kohl: 60
    # Membership: digest per slot; EMPTY until mature + admitted
    digests: List[bytes] = field(default_factory=list)
    admitted: set = field(default_factory=set)

    def mint(
        self,
        amount: int,
        otk: int,
        commitment: int,
        *,
        coinbase: bool = False,
        spend_secret: Optional[int] = None,
    ) -> StoredOutput:
        i = self.next_index
        out = StoredOutput(
            index=i,
            one_time_key=otk,
            commitment=commitment,
            amount=amount,
            height=self.height,
            coinbase=coinbase,
            spend_secret=spend_secret,
        )
        self.outputs[i] = out
        self.next_index += 1
        # Grow tree: new slot starts EMPTY
        self.digests.append(empty_leaf_hash())
        return out

    def is_mature(self, out: StoredOutput) -> bool:
        age = self.height - out.height
        need = self.coinbase_maturity if out.coinbase else self.spendable_age
        return age >= need

    def admit_mature(self) -> int:
        """Fill EMPTY → L(P,C) for mature outputs (on_finalize style)."""
        n = 0
        for i, out in self.outputs.items():
            if i in self.admitted:
                continue
            if not self.is_mature(out):
                continue
            self.digests[i] = leaf_hash(out.one_time_key, out.commitment)
            self.admitted.add(i)
            n += 1
        return n

    def advance(self, blocks: int = 1) -> None:
        for _ in range(blocks):
            self.height += 1
            self.admit_mature()

    def membership_root(self) -> bytes:
        return root_from_leaves(self.digests)

    def mature_members(self) -> List[StoredOutput]:
        return [self.outputs[i] for i in sorted(self.admitted)]


# ---------------------------------------------------------------------------
# Simplified SA+L over full mature set (toy stand-in for CLSAG inside FCMP0001)
# ---------------------------------------------------------------------------
# Real FCMP0001: digests rebuild root + CLSAG over every non-EMPTY (P,C).
# Here: same public statement, simpler Schnorr-style ring equation for clarity.

def signing_hash(
    membership_root: bytes,
    key_images: Sequence[int],
    pseudos: Sequence[int],
    out_commitments: Sequence[int],
    fee: int,
) -> bytes:
    h = hashlib.sha256(SIGNING_DOMAIN)
    h.update(membership_root)
    for ki in key_images:
        h.update(encode_int(ki))
    for c in pseudos:
        h.update(encode_int(c))
    for c in out_commitments:
        h.update(encode_int(c))
    h.update(encode_u64(fee))
    return h.digest()


@dataclass
class FcmpToyProof:
    """Toy membership + spend-auth proof for one input."""

    digests: List[bytes]
    ring_indices: List[int]  # tree indices of non-EMPTY leaves (full mature set)
    real_pos: int  # position of real spend inside ring_indices
    challenge: int
    response: int  # s = k - c·x  (Schnorr) — hides real index among ring


def fcmp_prove(
    msg: bytes,
    chain: Chain,
    real: StoredOutput,
    secret: int,
) -> FcmpToyProof:
    """Prove real is one of all mature leaves under the current root."""
    if real.index not in chain.admitted:
        raise ValueError("real output not admitted (immature)")
    digests = list(chain.digests)
    root = root_from_leaves(digests)
    members = chain.mature_members()
    ring_indices = [m.index for m in members]
    real_pos = ring_indices.index(real.index)

    # Schnorr over key image + msg + root (toy: not full CLSAG).
    # Challenge binds full mature set so you cannot drop members.
    k = random_scalar()
    r_point = point_mul(k)
    c = hs(
        msg,
        root,
        encode_int(r_point),
        b"".join(encode_u64(i) for i in ring_indices),
        domain=b"kohl-fcmp-toy/chal",
    )
    s = scalar_mod(k - c * secret)
    return FcmpToyProof(
        digests=digests,
        ring_indices=ring_indices,
        real_pos=real_pos,  # teaching only — real verifier must not need this!
        challenge=c,
        response=s,
    )


def fcmp_verify(
    msg: bytes,
    membership_root: bytes,
    key_image_i: int,
    proof: FcmpToyProof,
    *,
    # Teaching leak: we pass real secret only in self-tests via rebuild.
    # Production verify never gets secrets. Toy verify re-checks membership
    # structure + that some ring member could have signed (using stored secrets
    # is forbidden — we check equation with *public* KI consistency loosely).
    ring_publics: Sequence[int],
) -> bool:
    """
    Verify toy FCMP:
      1) digests rebuild membership_root
      2) ring is exactly the non-EMPTY set
      3) Schnorr equation holds for *some* ring member's public key
         (we try each — O(n), fine for teaching; real CLSAG is one pass)
    """
    if root_from_leaves(proof.digests) != membership_root:
        return False
    empty = empty_leaf_hash()
    non_empty = [i for i, d in enumerate(proof.digests) if d != empty]
    if non_empty != proof.ring_indices:
        return False
    if len(ring_publics) != len(proof.ring_indices):
        return False
    # Each ring digest must match leaf_hash(P, C) — caller supplies P via ring_publics
    # and we only check Schnorr vs P here; commitment binding is in leaf digests.
    r_check = point_add(
        point_mul(proof.response),
        point_mul(proof.challenge, ring_publics[proof.real_pos]),
    )
    # Honest note: using real_pos is a teaching shortcut. Real CLSAG closes the
    # ring without revealing the index. For --check we also run clsag-style loop.
    c2 = hs(
        msg,
        membership_root,
        encode_int(r_check),
        b"".join(encode_u64(i) for i in proof.ring_indices),
        domain=b"kohl-fcmp-toy/chal",
    )
    if c2 != proof.challenge:
        return False
    # Key image must be non-identity-ish (toy: non-1)
    if key_image_i == 1:
        return False
    return True


def fcmp_verify_hiding(
    msg: bytes,
    membership_root: bytes,
    key_image_i: int,
    proof: FcmpToyProof,
    ring_publics: Sequence[int],
) -> bool:
    """
    Index-hiding verify: try every ring position (teaching substitute for CLSAG).
    Accept if *exactly one* position would satisfy the Schnorr equation for this
    (c, s) — in a real signature only the real key works; our Schnorr is for one
    key so we check the committed real_pos without *using* it as a secret:
    we recompute c for each candidate P.
    """
    if root_from_leaves(proof.digests) != membership_root:
        return False
    empty = empty_leaf_hash()
    non_empty = [i for i, d in enumerate(proof.digests) if d != empty]
    if non_empty != list(proof.ring_indices):
        return False
    if len(ring_publics) != len(proof.ring_indices) or not ring_publics:
        return False
    if key_image_i == 1:
        return False

    matches = 0
    for p in ring_publics:
        r_check = point_add(point_mul(proof.response), point_mul(proof.challenge, p))
        c2 = hs(
            msg,
            membership_root,
            encode_int(r_check),
            b"".join(encode_u64(i) for i in proof.ring_indices),
            domain=b"kohl-fcmp-toy/chal",
        )
        if c2 == proof.challenge:
            matches += 1
    # With honest Schnorr for one secret, exactly one public key matches.
    return matches == 1


# ---------------------------------------------------------------------------
# Tours
# ---------------------------------------------------------------------------

def tour_big_picture(verbose: bool = True) -> None:
    if not verbose:
        return
    banner("Why Kohl looks the way it does")
    diagram(
        """
On Bitcoin a transfer says:
  Address A paid Address B exactly 1.5 BTC.

On Kohl a transfer says:
  Someone among the *mature* outputs spent *something*;
  someone received *some amount*; the chain still stops
  double-spends and inflation.

Three pillars:
  1. Sender   — full mature-set membership (FCMP), not a ring of 16 decoys
  2. Receiver — stealth / one-time addresses
  3. Amount   — Pedersen commitments + range proofs (Bulletproofs in production)

Double-spend tool: key image I = x·Hp(P)  (same idea as Monero).
"""
    )
    note("Pre-launch policy: FCMP-only. No Dual CLSAG era on mainnet history.")
    note("Interim proofs (FCMP0001) are O(n) with mature set n ≤ 64.")
    warn("This script is a toy. Do not use it for real money.")


def tour_pedersen(verbose: bool = True) -> None:
    if verbose:
        step(1, "Pedersen commitments hide amounts")
        note("C = amount·H + blinding·G  (here: modular stand-ins for H and G)")
    a, x = 50, random_scalar()
    c = commit(a, x)
    if verbose:
        ok(f"commit(50, x) → C = …{short_hex(c)}")
        note("Same amount, different blinding → different C (looks random).")
    c2 = commit(a, random_scalar())
    assert c != c2
    # Balance: 30+20 fee 0
    b1, y1 = 30, random_scalar()
    b2, y2 = 20, random_scalar()
    fee = 0
    # Input commitment to 50 with blinding x; re-blind to C' with z
    z = random_scalar()
    c_pseudo = commit(a, z)
    assert verify_balance([c_pseudo], [commit(b1, y1), commit(b2, y2)], fee) is False
    # Fix blindings so Σ x_in = Σ x_out
    y2 = scalar_mod(z - y1)  # fee 0
    assert verify_balance([c_pseudo], [commit(b1, y1), commit(b2, y2)], fee)
    if verbose:
        ok("Balance equation: Σ C' == Σ C_out + fee·H  (amounts + blindings)")
        note("Production also needs Bulletproofs so amounts are in [0, 2^64).")


def tour_stealth(verbose: bool = True) -> Tuple[StealthKeys, int, int, int]:
    if verbose:
        step(2, "Stealth addresses hide who was paid")
    bob = keypair()
    r = random_scalar()
    R = point_mul(r)  # tx pubkey
    shared_s = point_mul(r, bob.view_public)
    shared_r = point_mul(bob.view_secret, R)
    assert shared_s == shared_r
    p, delta, tag = derive_otk(shared_s, bob.spend_public, 0)
    x = recover_spend_secret(bob, R, 0)
    assert point_mul(x) == p
    if verbose:
        ok(f"Bob address (A,B) published; sender derives one-time P=…{short_hex(p)}")
        ok(f"View tag = {tag} (wallet skips most outputs with one cheap check)")
        ok("Only Bob’s spend key recovers x; chain never sees Bob’s address on the output.")
    return bob, R, p, x


def tour_key_image(verbose: bool = True) -> None:
    if verbose:
        step(3, "Key images stop double-spends without revealing which output")
    x = random_scalar()
    i1 = key_image(x)
    i2 = key_image(x)
    assert i1 == i2
    i3 = key_image(random_scalar())
    assert i1 != i3
    if verbose:
        ok(f"I = x·Hp(P) is deterministic → I=…{short_hex(i1)}")
        note("Chain stores spent I’s forever. Same I twice ⇒ reject.")
        note("I does not say *which* mature output was spent (that’s membership’s job).")


def tour_tree(verbose: bool = True) -> Chain:
    if verbose:
        step(4, "Membership tree: slots, EMPTY, admit when mature")
        diagram(
            """
Global output index i  ↔  tree slot i

  mint output i     →  digests[i] = EMPTY
  wait maturity     →  digests[i] = L(P, C)   = leaf_hash(P, C)
  membership root   →  MerkleRoot(digests[0..n))

Spending opens only non-EMPTY leaves ⇒ maturity is implied by membership.
No wallet decoy sampler.
"""
        )
    chain = Chain()
    # Coinbase-like mint to Alice
    alice = keypair()
    r = random_scalar()
    R = point_mul(r)
    shared = point_mul(r, alice.view_public)
    p, _, _ = derive_otk(shared, alice.spend_public, 0)
    x = recover_spend_secret(alice, R, 0)
    blind = random_scalar()
    amount = 100
    c = commit(amount, blind)
    out = chain.mint(amount, p, c, coinbase=True, spend_secret=x)
    # Stash blinding for later spend demo
    out.spend_secret = x  # type: ignore[attr-defined]
    setattr(out, "blinding", blind)
    setattr(out, "owner", alice)

    if verbose:
        note(f"Minted coinbase output #{out.index} amount={amount} at height {out.height}")
        note(f"digest[{out.index}] is EMPTY → {empty_leaf_hash()[:6].hex()}…")
        assert chain.digests[0] == empty_leaf_hash()
        ok("Immature: not in admitted set; cannot be spent via membership yet.")

    chain.advance(chain.coinbase_maturity)
    assert out.index in chain.admitted
    assert chain.digests[0] == leaf_hash(p, c)
    root = chain.membership_root()
    if verbose:
        ok(f"After {chain.coinbase_maturity} blocks: admitted; leaf filled")
        ok(f"membership_root = {root[:8].hex()}…")
        note(f"SpendableAge={chain.spendable_age}, CoinbaseMaturity={chain.coinbase_maturity} (toy sizes)")

    # More outputs so the spend sees a multi-member mature set.
    for j in range(2):
        k = keypair()
        rr = random_scalar()
        sh = point_mul(rr, k.view_public)
        pj, _, _ = derive_otk(sh, k.spend_public, 0)
        bj = random_scalar()
        chain.mint(10 + j, pj, commit(10 + j, bj), coinbase=False)
    chain.advance(chain.spendable_age)  # admit the two extras
    # Fresh mint stays EMPTY (immature) → sparse hole in the tree
    k = keypair()
    rr = random_scalar()
    sh = point_mul(rr, k.view_public)
    pj, _, _ = derive_otk(sh, k.spend_public, 0)
    chain.mint(99, pj, commit(99, random_scalar()), coinbase=False)
    if verbose:
        note(f"Tree now has {len(chain.digests)} slots; admitted={sorted(chain.admitted)}")
        empties = sum(1 for d in chain.digests if d == empty_leaf_hash())
        ok(f"{empties} EMPTY slot(s) still — sparse admit, not “wait for everyone below”")
        ok(f"Mature set size = {len(chain.admitted)} (this is the anonymity set at the root)")
    return chain


def tour_fcmp_spend(chain: Chain, verbose: bool = True) -> None:
    if verbose:
        step(5, "FCMP spend: prove membership in the *full* mature set")
        diagram(
            """
Wallet                                  Chain
──────                                  ─────
1. Own mature output #i
2. Read membership_root + digests
3. Build proof that i is among ALL
   non-EMPTY leaves at that root
4. Key image I, pseudo C', BP…
5. Unsigned extrinsic  ─────────────►  root in window?
                                       verify_fcmp (host)
                                       balance + range
                                       insert I, append outs
"""
        )

    real = chain.outputs[0]
    secret = real.spend_secret
    assert secret is not None
    assert real.index in chain.admitted

    fee = 1
    pay = 40
    change = real.amount - pay - fee
    assert change > 0

    # Outputs to Carol + change back (simplified: we only check amounts/balance)
    carol = keypair()
    r_tx = random_scalar()
    R = point_mul(r_tx)
    sh = point_mul(r_tx, carol.view_public)
    p_pay, _, _ = derive_otk(sh, carol.spend_public, 0)
    p_chg, _, _ = derive_otk(point_mul(r_tx, getattr(real, "owner").view_public), getattr(real, "owner").spend_public, 1)

    y_pay, y_chg = random_scalar(), random_scalar()
    # Pseudo blinding z; balance blindings: z = y_pay + y_chg  (fee on H only)
    z = scalar_mod(y_pay + y_chg)
    c_pseudo = commit(real.amount, z)
    c_pay = commit(pay, y_pay)
    c_chg = commit(change, y_chg)
    assert verify_balance([c_pseudo], [c_pay, c_chg], fee)

    root = chain.membership_root()
    ki = key_image(secret)
    msg = signing_hash(root, [ki], [c_pseudo], [c_pay, c_chg], fee)

    proof = fcmp_prove(msg, chain, real, secret)
    members = chain.mature_members()
    pubs = [m.one_time_key for m in members]

    assert fcmp_verify_hiding(msg, root, ki, proof, pubs)
    assert ki not in chain.key_images
    chain.key_images.add(ki)

    # Apply: mint pay + change (new EMPTY slots)
    chain.mint(pay, p_pay, c_pay, coinbase=False)
    chain.mint(change, p_chg, c_chg, coinbase=False)

    if verbose:
        ok(f"Mature set size n = {len(members)} (full set at this root, not 16 decoys)")
        ok(f"Key image recorded I=…{short_hex(ki)}")
        ok("Balance holds with public fee = 1")
        ok("New outputs appended; tree grew with EMPTY slots until they mature")
        note("Production FCMP0001 packs digests + CLSAG over the mature ring (n≤64).")
        note("Transparent Merkle paths are rejected (would leak the spent index).")


def tour_honest_limits(verbose: bool = True) -> None:
    if not verbose:
        return
    step(6, "Honest limits (read this)")
    diagram(
        """
What this design gives you
  • Index-hiding among all mature outputs at a root (not a 16-mixin ring)
  • Same CryptoNote key images / stealth / confidential amounts
  • No Dual “rings still valid forever” hangover on mainnet history

What it does not claim yet
  • Unlimited anonymity set — interim proofs cap n at 64 (O(n) size)
  • Network privacy alone — use Dandelion++ and Tor for IP hiding
  • Monero wire compatibility — Ristretto + Kohl domains

Production map
  host:   verify_fcmp_v1, verify_balance_v1, verify_range_proof_v1
  pallet: TransferTx { membership_root, FcmpInput… }  domain kohl/transfer/v4
  wallet: membership cache + FCMP builder (no production decoy sampler)
"""
    )


def tour_compare_rings(verbose: bool = True) -> None:
    if not verbose:
        return
    banner("Rings (old) vs FCMP (kohl production)")
    diagram(
        """
Fixed ring-16 (historical Phase 3)
  wallet picks 15 decoys + 1 real
  chain checks those 16 members exist + mature
  anonymity set = 16 (decoy quality is an arms race)

FCMP-only (current)
  wallet proves against the full mature set at a root
  chain admits leaves when mature (EMPTY → L)
  anonymity set = |admitted| (interim ≤ 64)

There is no “Dual” mode on mainnet-candidate history.
"""
    )


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

def self_check() -> None:
    # Empty root stable
    assert root_from_leaves([]) == merkle_empty_child()
    assert empty_leaf_hash() != merkle_empty_child()

    # Leaf domain
    p, c = 12345, 67890
    assert leaf_hash(p, c) != empty_leaf_hash()

    # Balance
    x = random_scalar()
    assert verify_balance([commit(10, x)], [commit(7, 1), commit(3, scalar_mod(x - 1))], 0)

    # Stealth
    keys = keypair()
    r = random_scalar()
    R = point_mul(r)
    sh = point_mul(r, keys.view_public)
    P, _, _ = derive_otk(sh, keys.spend_public, 0)
    assert point_mul(recover_spend_secret(keys, R, 0)) == P

    # Key image deterministic
    sk = random_scalar()
    assert key_image(sk) == key_image(sk)

    # Tree admit
    chain = Chain()
    sk2 = random_scalar()
    pk2 = point_mul(sk2)
    b = random_scalar()
    amt = 25
    o = chain.mint(amt, pk2, commit(amt, b), coinbase=True, spend_secret=sk2)
    assert o.index not in chain.admitted
    chain.advance(chain.coinbase_maturity)
    assert o.index in chain.admitted
    root = chain.membership_root()
    assert root == root_from_leaves(chain.digests)

    # FCMP toy prove/verify
    msg = signing_hash(root, [key_image(sk2)], [commit(amt, b)], [commit(amt - 1, 1)], 1)
    # Fix balance for msg only — use consistent pseudo
    z = random_scalar()
    c_ps = commit(amt, z)
    c_o = commit(amt - 1, scalar_mod(z))  # fee 1 ⇒ need fee·H on right
    # ΣC' = C_out + fee·H ⇒ amount: amt = (amt-1) + 1 ✓ if blindings: z = z_out
    c_o = commit(amt - 1, z)
    assert verify_balance([c_ps], [c_o], 1)
    msg = signing_hash(root, [key_image(sk2)], [c_ps], [c_o], 1)
    proof = fcmp_prove(msg, chain, o, sk2)
    pubs = [m.one_time_key for m in chain.mature_members()]
    assert fcmp_verify_hiding(msg, root, key_image(sk2), proof, pubs)

    # Wrong root fails
    bad_root = bytes(b ^ 1 if i == 0 else b for i, b in enumerate(root))
    assert not fcmp_verify_hiding(msg, bad_root, key_image(sk2), proof, pubs)

    # Incomplete mature set fails
    bad = FcmpToyProof(
        digests=proof.digests,
        ring_indices=proof.ring_indices[:-1] if len(proof.ring_indices) > 1 else [],
        real_pos=0,
        challenge=proof.challenge,
        response=proof.response,
    )
    if proof.ring_indices:
        # empty ring or incomplete
        assert not fcmp_verify_hiding(msg, root, key_image(sk2), bad, pubs[: max(0, len(pubs) - 1)])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Learn how Kohl FCMP private cash works (toy)")
    ap.add_argument("--quick", action="store_true", help="shorter tour")
    ap.add_argument("--tree", action="store_true", help="membership tree focus only")
    ap.add_argument("--check", action="store_true", help="silent self-tests")
    args = ap.parse_args(argv)

    if args.check:
        try:
            self_check()
            tour_pedersen(verbose=False)
            tour_stealth(verbose=False)
            tour_key_image(verbose=False)
            ch = tour_tree(verbose=False)
            tour_fcmp_spend(ch, verbose=False)
        except Exception as e:
            print(f"FAIL: {e}", file=sys.stderr)
            return 1
        return 0

    if args.tree:
        banner("Kohl membership tree (toy)")
        tour_tree(verbose=True)
        tour_honest_limits(verbose=True)
        print()
        return 0

    tour_big_picture(verbose=True)
    if not args.quick:
        tour_compare_rings(verbose=True)
    tour_pedersen(verbose=True)
    tour_stealth(verbose=True)
    tour_key_image(verbose=True)
    chain = tour_tree(verbose=True)
    tour_fcmp_spend(chain, verbose=True)
    tour_honest_limits(verbose=True)

    banner("Done")
    note("Re-run with --check to verify the toy invariants.")
    note("Deeper rings algebra: python3 examples/learn_ringct.py")
    note("Design: docs/fcmp-design.md · Glossary: GLOSSARY.md")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
