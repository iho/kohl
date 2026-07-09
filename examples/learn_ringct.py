#!/usr/bin/env python3
"""
learn_ringct.py — Interactive tour of Monero-style private cash (as used by kohl)

  python3 examples/learn_ringct.py           # full guided tour
  python3 examples/learn_ringct.py --quick   # shorter path
  python3 examples/learn_ringct.py --clsag   # CLSAG verification loop only
  python3 examples/learn_ringct.py --check   # silent self-tests (exit 0/1)

This is a TEACHING TOY only. It uses a tiny modular group so the algebra is
visible. Real Monero/kohl use Ristretto (Curve25519), production CLSAG,
Bulletproofs, and domain-separated hashes. See GLOSSARY.md and BLUEPRINT.md.

Companion to: GLOSSARY.md §0–§6, primitives/ringct-crypto, pallets/ringct.
"""

from __future__ import annotations

import argparse
import hashlib
import secrets
import sys
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Toy group  (NOT secure — discrete log is easy)
# ---------------------------------------------------------------------------
# Multiplicative notation: points are integers mod P, "addition" is multiply,
# "scalar mult" is pow. Maps to elliptic-curve:  g^x  ↔  x·G.

MOD: int = 2_147_483_647  # large-ish prime so collisions are rare in demos
G: int = 5
ORDER: int = MOD - 1  # group order of (Z/p)* is p-1; we reduce scalars mod this


def scalar_mod(s: int) -> int:
    """Reduce a scalar mod the group order. Zero is allowed (e.g. coinbase blinding)."""
    return s % ORDER


def hs(*parts: bytes, domain: bytes = b"kohl-toy/hs") -> int:
    """Hash-to-scalar with domain separation (toy). Never returns 0."""
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
    """a - b  ≡  a * b^{-1}."""
    return (a * pow(b, -1, MOD)) % MOD


def point_neg(a: int) -> int:
    return pow(a, -1, MOD)


def encode_int(x: int) -> bytes:
    return x.to_bytes(8, "big", signed=False)


def hp(point: int) -> int:
    """Hash-to-point for key images (toy Elligator stand-in)."""
    return point_mul(hs(encode_int(point), domain=b"kohl-toy/hp"))


# NUMS value generator H (nobody "knows" discrete log vs G in a real system).
H: int = point_mul(hs(b"NUMS-value-generator", domain=b"kohl-toy/nums"))


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


def diagram(text: str) -> None:
    print()
    for line in text.strip("\n").splitlines():
        print(f"  {line}")
    print()


# ---------------------------------------------------------------------------
# Pedersen commitments  C = H^amount · G^blinding
# ---------------------------------------------------------------------------

def commit(amount: int, blinding: int) -> int:
    return point_add(point_mul(amount, H), point_mul(blinding, G))


def verify_balance(
    input_commitments: Sequence[int],
    output_commitments: Sequence[int],
    fee: int,
) -> bool:
    """Σ C_in == Σ C_out + fee·H  (kohl/Monero equation)."""
    left = 1
    for c in input_commitments:
        left = point_add(left, c)
    right = point_mul(fee, H)
    for c in output_commitments:
        right = point_add(right, c)
    return left == right


# ---------------------------------------------------------------------------
# Stealth addresses
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

    @property
    def address(self) -> Tuple[int, int]:
        return self.view_public, self.spend_public


def random_scalar() -> int:
    return secrets.randbelow(ORDER - 1) + 1


def keypair() -> StealthKeys:
    return StealthKeys(view_secret=random_scalar(), spend_secret=random_scalar())


def sender_shared(r: int, view_public: int) -> int:
    return point_mul(r, view_public)  # r·A


def receiver_shared(view_secret: int, tx_pubkey: int) -> int:
    return point_mul(view_secret, tx_pubkey)  # a·R


def derive_otk(shared: int, spend_public: int, index: int = 0) -> Tuple[int, int, int]:
    """Return (P, h, view_tag).  P = h·G + B."""
    h = hs(encode_int(shared), index.to_bytes(4, "little"), domain=b"kohl-toy/otk")
    P = point_add(point_mul(h, G), spend_public)
    tag = hs(encode_int(shared), index.to_bytes(4, "little"), domain=b"kohl-toy/tag") & 0xFF
    return P, h, tag


def recover_spend_secret(keys: StealthKeys, tx_pubkey: int, index: int = 0) -> int:
    shared = receiver_shared(keys.view_secret, tx_pubkey)
    h = hs(encode_int(shared), index.to_bytes(4, "little"), domain=b"kohl-toy/otk")
    return scalar_mod(h + keys.spend_secret)


def mask_amount(amount: int, shared: int, index: int = 0) -> int:
    mask = hs(encode_int(shared), index.to_bytes(4, "little"), domain=b"kohl-toy/amt")
    return amount ^ (mask & 0xFFFFFFFFFFFFFFFF)


# ---------------------------------------------------------------------------
# Key images
# ---------------------------------------------------------------------------

def key_image(secret: int, public: Optional[int] = None) -> int:
    """I = x · Hp(P) with P = x·G."""
    P = public if public is not None else point_mul(secret)
    return point_mul(secret, hp(P))


# ---------------------------------------------------------------------------
# Toy LSAG  (single-layer linkable ring signature)
# ---------------------------------------------------------------------------
# This is the *shape* of Monero's ring before CLSAG's commitment aggregation.
# Real CLSAG also binds amount via (C_i - C') and publishes auxiliary image D.
#
# Sign (real index ℓ, secret x, keys P_0..P_{n-1}, message m):
#
#            α random
#            c_{ℓ+1} = H(m ‖ αG ‖ α Hp(P_ℓ))
#            for i = ℓ+1, ℓ+2, … ℓ-1 (mod n):
#                s_i random
#                L_i = s_i·G + c_i·P_i
#                R_i = s_i·Hp(P_i) + c_i·I
#                c_{i+1} = H(m ‖ L_i ‖ R_i)
#            s_ℓ = α − c_ℓ·x
#
# Verify: recompute the ring of challenges; accept iff it closes (c_n == c_0)
# and I ≠ identity.

@dataclass
class ToyLsagSig:
    c0: int
    s: List[int]
    key_image: int


def lsag_sign(
    message: bytes,
    ring_pubs: Sequence[int],
    real_index: int,
    secret: int,
) -> ToyLsagSig:
    n = len(ring_pubs)
    assert 0 <= real_index < n
    assert point_mul(secret) == ring_pubs[real_index], "secret does not match ring member"

    I = key_image(secret, ring_pubs[real_index])
    s = [0] * n
    c = [0] * n

    alpha = random_scalar()
    L_seed = point_mul(alpha, G)
    R_seed = point_mul(alpha, hp(ring_pubs[real_index]))
    c_next = hs(
        message,
        encode_int(L_seed),
        encode_int(R_seed),
        domain=b"kohl-toy/lsag-round",
    )
    idx = (real_index + 1) % n
    c[idx] = c_next

    while idx != real_index:
        s[idx] = random_scalar()
        L = point_add(point_mul(s[idx], G), point_mul(c[idx], ring_pubs[idx]))
        R = point_add(
            point_mul(s[idx], hp(ring_pubs[idx])),
            point_mul(c[idx], I),
        )
        c_next = hs(
            message,
            encode_int(L),
            encode_int(R),
            domain=b"kohl-toy/lsag-round",
        )
        idx = (idx + 1) % n
        c[idx] = c_next

    # c[real_index] is now set; close the ring
    s[real_index] = scalar_mod(alpha - c[real_index] * secret)
    return ToyLsagSig(c0=c[0], s=s, key_image=I)


def lsag_verify(
    message: bytes,
    ring_pubs: Sequence[int],
    sig: ToyLsagSig,
    verbose: bool = False,
) -> bool:
    n = len(ring_pubs)
    if len(sig.s) != n:
        return False
    if sig.key_image == 1:  # identity in multiplicative group
        return False

    c = sig.c0
    if verbose:
        diagram(
            f"""
CLSAG/LSAG verification loop (n = {n})
=====================================

  Start with challenge c₀ = {sig.c0}

  for i in 0 .. n-1:
      Lᵢ = sᵢ·G + cᵢ·Pᵢ
      Rᵢ = sᵢ·Hp(Pᵢ) + cᵢ·I
      cᵢ₊₁ = H(message ‖ Lᵢ ‖ Rᵢ)

  Accept  ⇔  cₙ == c₀   (the ring closes)

  ┌──────┐   s0,c0    ┌──────┐   s1,c1    ┌──────┐
  │  P0  │ ─────────► │  P1  │ ─────────► │  P2  │ ── … ──┐
  └──┬───┘            └──┬───┘            └──┬───┘        │
     │                   │                   │            │
     └───────────────────┴───────────────────┴────────────┘
                    challenges wrap around
"""
        )

    for i in range(n):
        L = point_add(point_mul(sig.s[i], G), point_mul(c, ring_pubs[i]))
        R = point_add(
            point_mul(sig.s[i], hp(ring_pubs[i])),
            point_mul(c, sig.key_image),
        )
        c_next = hs(
            message,
            encode_int(L),
            encode_int(R),
            domain=b"kohl-toy/lsag-round",
        )
        if verbose:
            note(f"i={i}: c={c}  →  L={L}  R={R}  →  c'={c_next}")
        c = c_next

    closed = c == sig.c0
    if verbose:
        if closed:
            ok(f"ring closed: final challenge {c} == c₀")
        else:
            print(f"  ✗ ring did NOT close: {c} != {sig.c0}")
    return closed


# ---------------------------------------------------------------------------
# CLSAG-shaped extension: also prove C_real - C' = z·G  (amount link)
# ---------------------------------------------------------------------------
# Production CLSAG aggregates key+commitment into one ring with μ_P, μ_C.
# Here we run a *second* linked equation with the same challenges for teaching:
# we sign with secret z on the "commitment key" W_i = C_i / C'  (= G^z at real).

@dataclass
class ToyClsagSig:
    """Toy two-layer ring: key image I + aux image D, one (c0, s[]) vector."""

    c0: int
    s: List[int]
    key_image: int  # I = x · Hp(P)
    aux_image: int  # D = z · Hp(P)  (commitment side)
    pseudo: int  # C'


def clsag_sign(
    message: bytes,
    ring_keys: Sequence[int],
    ring_commits: Sequence[int],
    real_index: int,
    secret_key: int,
    input_blinding: int,
    pseudo_blinding: int,
) -> ToyClsagSig:
    """
    Prove knowledge of (x, z) for undisclosed ℓ:
      P_ℓ = x·G,  I = x·Hp(P_ℓ),
      C_ℓ - C' = z·G,  D = z·Hp(P_ℓ),
    with C' = commit(amount, pseudo_blinding) for the same amount as C_ℓ.
    """
    n = len(ring_keys)
    assert len(ring_commits) == n
    assert point_mul(secret_key) == ring_keys[real_index]

    z = scalar_mod(input_blinding - pseudo_blinding)
    # C' such that C_real / C' = G^z
    C_real = ring_commits[real_index]
    C_pseudo = point_sub(C_real, point_mul(z, G))
    # equivalently: if C = H^a G^{x_in}, C' = H^a G^{x'}, z = x_in - x'

    P_real = ring_keys[real_index]
    I = point_mul(secret_key, hp(P_real))
    D = point_mul(z, hp(P_real))

    # Aggregate "effective" public keys for the ring (toy CLSAG μ=1 for both).
    # W_i = P_i · (C_i / C')^{μ_C} with μ=1 → W_i = P_i · (C_i / C')
    def W(i: int) -> int:
        return point_add(ring_keys[i], point_sub(ring_commits[i], C_pseudo))

    # Combined secret w = x + z  (because μ_P = μ_C = 1)
    w = scalar_mod(secret_key + z)
    assert point_mul(w) == W(real_index), "aggregation check failed"

    # Key image side of combined secret: Ĩ = I·D = w · Hp(P) only at real...
    # For verification we use the standard dual (L,R) form with I and D.
    s = [0] * n
    c = [0] * n
    alpha = random_scalar()

    L0 = point_mul(alpha, G)
    R0 = point_mul(alpha, hp(P_real))
    c_next = hs(
        message,
        encode_int(C_pseudo),
        encode_int(L0),
        encode_int(R0),
        domain=b"kohl-toy/clsag-round",
    )
    idx = (real_index + 1) % n
    c[idx] = c_next

    while idx != real_index:
        s[idx] = random_scalar()
        # L = s·G + c·W_i
        L = point_add(point_mul(s[idx], G), point_mul(c[idx], W(idx)))
        # R = s·Hp(P_i) + c·(I·D)  with Ĩ = I * D  as points multiplied
        I_tilde = point_add(I, D)
        R = point_add(
            point_mul(s[idx], hp(ring_keys[idx])),
            point_mul(c[idx], I_tilde),
        )
        c_next = hs(
            message,
            encode_int(C_pseudo),
            encode_int(L),
            encode_int(R),
            domain=b"kohl-toy/clsag-round",
        )
        idx = (idx + 1) % n
        c[idx] = c_next

    s[real_index] = scalar_mod(alpha - c[real_index] * w)
    return ToyClsagSig(
        c0=c[0],
        s=s,
        key_image=I,
        aux_image=D,
        pseudo=C_pseudo,
    )


def clsag_verify(
    message: bytes,
    ring_keys: Sequence[int],
    ring_commits: Sequence[int],
    sig: ToyClsagSig,
    verbose: bool = False,
) -> bool:
    n = len(ring_keys)
    if len(ring_commits) != n or len(sig.s) != n:
        return False
    if sig.key_image == 1:
        return False

    I_tilde = point_add(sig.key_image, sig.aux_image)

    def W(i: int) -> int:
        return point_add(ring_keys[i], point_sub(ring_commits[i], sig.pseudo))

    if verbose:
        diagram(
            f"""
Toy CLSAG verification (keys + amount link)
==========================================

  For each ring member i:
      Wᵢ = Pᵢ + (Cᵢ − C')     # = G^{{x}} at the real spend only (with z)

  Combined key-image side:
      Ĩ = I + D               # I = x·Hp(P), D = z·Hp(P)

  Ring loop (same shape as LSAG):
      Lᵢ = sᵢ·G + cᵢ·Wᵢ
      Rᵢ = sᵢ·Hp(Pᵢ) + cᵢ·Ĩ
      cᵢ₊₁ = H(m ‖ C' ‖ Lᵢ ‖ Rᵢ)

  Accept ⇔ ring closes and I ≠ identity.

  Real kohl/Monero CLSAG uses aggregation coefficients μ_P, μ_C and a
  tighter encoding (c0 ‖ s0..sn-1 ‖ D). See clsag.rs.
"""
        )

    c = sig.c0
    for i in range(n):
        L = point_add(point_mul(sig.s[i], G), point_mul(c, W(i)))
        R = point_add(
            point_mul(sig.s[i], hp(ring_keys[i])),
            point_mul(c, I_tilde),
        )
        c = hs(
            message,
            encode_int(sig.pseudo),
            encode_int(L),
            encode_int(R),
            domain=b"kohl-toy/clsag-round",
        )
        if verbose:
            note(f"i={i}: challenge → {c}")

    closed = c == sig.c0
    if verbose:
        if closed:
            ok("CLSAG ring closed")
        else:
            print("  ✗ CLSAG ring did not close")
    return closed


# ---------------------------------------------------------------------------
# Tours
# ---------------------------------------------------------------------------

def tour_big_picture() -> None:
    banner("0. What Monero / kohl are doing")
    diagram(
        """
  Bitcoin tx (public)                    Monero / kohl tx (private)
  ───────────────────                    ─────────────────────────
  Alice ──1.5 BTC──► Bob                 {ring of 16 outs} ──?──► {one-time key}
  everyone sees:                         chain checks without learning:
    • who paid                             • WHICH input was real  (CLSAG)
    • who was paid                         • WHO was paid          (stealth)
    • exact amount                         • HOW MUCH (except fee) (Pedersen+BP)

  Double-spend stop: KEY IMAGE I = x·Hp(P)
    • same x always same I  →  second spend rejected
    • I does not say which ring member was real
"""
    )
    diagram(
        """
  Three pillars
  ─────────────
       ┌─────────────────────────────────────────────────┐
       │              pallet-ringct / monerod              │
       │                                                 │
       │   1. CLSAG rings     2. Stealth OTKs            │
       │      (sender)           (receiver)              │
       │              ╲         ╱                        │
       │               ╲       ╱                         │
       │            3. Pedersen + Bulletproofs           │
       │               (amounts)                         │
       └─────────────────────────────────────────────────┘
"""
    )


def tour_pedersen() -> None:
    banner("1. Pedersen commitments — hide amounts, keep sums")
    step(1, "Commit to 30 and 20, open the sum as 50")
    b1, b2 = random_scalar(), random_scalar()
    c1, c2 = commit(30, b1), commit(20, b2)
    c_sum = point_add(c1, c2)
    assert c_sum == commit(50, scalar_mod(b1 + b2))
    ok("C(30)+C(20) = C(50)  (homomorphism)")
    note(f"C1={c1}  C2={c2}  — amounts not visible in the integers alone")

    step(2, "Balance equation with public fee")
    fee = 2
    # in: 100 → out: 60 + 38 + fee 2
    xin, x1 = random_scalar(), random_scalar()
    x2 = scalar_mod(xin - x1)  # fee blinding 0
    cin = commit(100, xin)
    couts = [commit(60, x1), commit(38, x2)]
    assert verify_balance([cin], couts, fee)
    ok("Σ C_in == Σ C_out + fee·H")

    step(3, "Why range proofs?")
    note("Without a range proof you could commit to a huge number that wraps")
    note("or use negative amounts algebraically — minting money silently.")
    note("Bulletproofs show amount ∈ [0, 2^64) without revealing it.")
    note("(Bulletproofs not implemented in this toy — see ringct-crypto.)")


def tour_stealth() -> None:
    banner("2. Stealth addresses — receiver privacy")
    diagram(
        """
  Bob's address (never on chain):   A = a·G  (view) ,  B = b·G  (spend)

  Alice (sender)                         Bob (receiver)
  ──────────────                         ──────────────
  pick r random                          has a, b
  publish R = r·G
  shared = r·A  ─────────────────────►   shared = a·R   (same value)
  h = Hs(shared ‖ i)
  P = h·G + B   ── on chain ─────────►   recompute P'? match?
  amount_enc = amt ⊕ Hs_amt(shared)  ►   decrypt amount
                                         spend secret x = h + b
"""
    )
    bob = keypair()
    r = random_scalar()
    R = point_mul(r)
    shared_s = sender_shared(r, bob.view_public)
    shared_r = receiver_shared(bob.view_secret, R)
    assert shared_s == shared_r
    ok("ECDH shared secret matches on both sides")

    P, h, tag = derive_otk(shared_s, bob.spend_public, 0)
    x = recover_spend_secret(bob, R, 0)
    assert point_mul(x) == P
    ok(f"one-time key P derives from x = h+b  (tag={tag})")

    amt = 42_000_000
    enc = mask_amount(amt, shared_s, 0)
    assert mask_amount(enc, shared_r, 0) == amt
    ok(f"amount {amt} masked as {enc}, Bob recovers it")


def tour_key_image() -> None:
    banner("3. Key images — linkable, not traceable")
    x = random_scalar()
    P = point_mul(x)
    I1 = key_image(x, P)
    I2 = key_image(x, P)
    assert I1 == I2
    ok(f"same secret ⇒ same key image I={I1}")

    # Different ring, same real key → still same I
    ok("I is independent of which decoys you mix with")
    note("Chain stores every I forever. Duplicate I ⇒ double-spend rejected.")
    note("Observer still does not know which ring member had secret x.")


def tour_lsag(verbose: bool = True) -> None:
    banner("4. Linkable ring signature (LSAG core of CLSAG)")
    diagram(
        """
  Ring of public keys (one is yours):

      P0 (decoy)     P1 (YOU)      P2 (decoy)
         ○─────────────●─────────────○
                       │
                       │ secret x
                       ▼
                 key image I

  Signature proves: "I know x for ONE of these Pᵢ, and I = x·Hp(P)"
  without saying which i.
"""
    )
    # Build ring: 3 members, real at index 1
    secrets = [None, random_scalar(), None]
    pubs = [
        point_mul(random_scalar()),
        point_mul(secrets[1]),  # type: ignore[arg-type]
        point_mul(random_scalar()),
    ]
    msg = b"kohl/transfer/v3|demo-payment"
    sig = lsag_sign(msg, pubs, real_index=1, secret=secrets[1])  # type: ignore[arg-type]
    ok(f"signed: c0={sig.c0}  I={sig.key_image}")
    assert lsag_verify(msg, pubs, sig, verbose=verbose)
    ok("verification passed")

    # Tamper
    bad = ToyLsagSig(c0=sig.c0, s=list(sig.s), key_image=sig.key_image)
    bad.s[0] = scalar_mod(bad.s[0] + 1)
    assert not lsag_verify(msg, pubs, bad, verbose=False)
    ok("tampered s[0] fails verification")

    # Wrong message
    assert not lsag_verify(b"other", pubs, sig, verbose=False)
    ok("wrong message fails verification")


def tour_clsag(verbose: bool = True) -> None:
    banner("5. Toy CLSAG — rings + amount link via C'")
    # Real output amount 100 under blinding xin
    x = random_scalar()
    xin = random_scalar()
    amount = 100
    P_real = point_mul(x)
    C_real = commit(amount, xin)

    # Decoys
    ring_keys = [point_mul(random_scalar()), P_real, point_mul(random_scalar())]
    ring_commits = [
        commit(random_scalar() % 50 + 1, random_scalar()),
        C_real,
        commit(random_scalar() % 50 + 1, random_scalar()),
    ]
    real_index = 1
    x_pseudo = random_scalar()

    msg = b"demo-clsag-message"
    sig = clsag_sign(
        msg, ring_keys, ring_commits, real_index, x, xin, x_pseudo
    )
    ok(f"CLSAG formed: I={sig.key_image}  C'={sig.pseudo}")
    assert sig.pseudo == commit(amount, x_pseudo)
    ok("pseudo-commitment opens to the SAME amount under fresh blinding")
    assert clsag_verify(msg, ring_keys, ring_commits, sig, verbose=verbose)
    ok("CLSAG verifies")

    # Wrong amount in pseudo would be: forge C' = commit(101, x_pseudo) —
    # signature would not verify because C_real - C' ≠ z·G for the z used.
    bad_pseudo = commit(amount + 1, x_pseudo)
    bad = ToyClsagSig(
        c0=sig.c0, s=sig.s, key_image=sig.key_image, aux_image=sig.aux_image, pseudo=bad_pseudo
    )
    assert not clsag_verify(msg, ring_keys, ring_commits, bad, verbose=False)
    ok("wrong-amount pseudo-commitment fails CLSAG (cannot mint via C')")


def tour_end_to_end() -> None:
    banner("6. End-to-end: Alice pays Bob (toy chain)")
    diagram(
        """
  Wallet                                      Chain (pallet-ringct)
  ──────                                      ─────────────────────
  1. own output (P, C, x, amount, blinding)
  2. sample decoys → ring
  3. build C', CLSAG, (range proof)
  4. stealth OTK for Bob + mask amount
  5. submit unsigned extrinsic  ──────────►  shape checks
                                             CLSAG verify (host fn)
                                             balance Σ C' = Σ C + fee·H
                                             range proof (host fn)
                                             store key image + outputs
"""
    )

    # --- Bob ---
    bob = keypair()

    # --- Alice's unspent coinbase-like output ---
    x_alice = random_scalar()
    amt_in = 42
    blind_in = 0  # coinbase-style
    P_alice = point_mul(x_alice)
    C_alice = commit(amt_in, blind_in)

    # Decoys from "chain"
    decoy_keys = [point_mul(random_scalar()) for _ in range(2)]
    decoy_commits = [commit(10 + i, random_scalar()) for i in range(2)]
    ring_keys = decoy_keys + [P_alice]
    ring_commits = decoy_commits + [C_alice]
    real_index = 2

    fee = 2
    amt_out = amt_in - fee
    assert amt_out > 0

    # Pseudo re-blind
    blind_pseudo = random_scalar()
    C_pseudo = commit(amt_in, blind_pseudo)

    # Stealth pay to Bob
    r = random_scalar()
    R = point_mul(r)
    shared = sender_shared(r, bob.view_public)
    P_bob, _, tag = derive_otk(shared, bob.spend_public, 0)
    # Single output absorbs full pseudo blinding
    blind_out = blind_pseudo
    C_out = commit(amt_out, blind_out)
    amount_enc = mask_amount(amt_out, shared, 0)

    assert verify_balance([C_pseudo], [C_out], fee)
    ok("balance equation holds")

    # Message binds public tx fields (like kohl signing_hash)
    msg = hashlib.sha256(
        b"kohl/transfer/v3"
        + encode_int(C_pseudo)
        + encode_int(C_out)
        + encode_int(R)
        + encode_int(fee)
        + encode_int(P_bob)
    ).digest()

    sig = clsag_sign(
        msg,
        ring_keys,
        ring_commits,
        real_index,
        x_alice,
        blind_in,
        blind_pseudo,
    )
    assert sig.pseudo == C_pseudo
    assert clsag_verify(msg, ring_keys, ring_commits, sig)
    ok("CLSAG verifies for this transfer")

    # "Chain" accepts: record KI and new output
    spent_images = {sig.key_image}
    chain_outputs = [
        {
            "P": P_bob,
            "C": C_out,
            "R": R,
            "tag": tag,
            "payload": amount_enc,
        }
    ]
    ok(f"chain stored key image and 1 new output (view_tag={tag})")

    # Double-spend attempt
    sig2 = clsag_sign(
        msg + b"x",
        ring_keys,
        ring_commits,
        real_index,
        x_alice,
        blind_in,
        random_scalar(),
    )
    assert sig2.key_image in spent_images
    ok("second spend produces the SAME key image → rejected")

    # Bob scans
    found = None
    for out in chain_outputs:
        shared_b = receiver_shared(bob.view_secret, out["R"])
        P_chk, _, tag_chk = derive_otk(shared_b, bob.spend_public, 0)
        if tag_chk == out["tag"] and P_chk == out["P"]:
            amt = mask_amount(out["payload"], shared_b, 0)
            found = amt
    assert found == amt_out
    ok(f"Bob's wallet scanned the chain and recovered amount {found}")

    note("Observer saw: ring of 3, fee=2, I, C', C_out, R, P_bob")
    note("Observer did NOT see: Alice's identity, Bob's address, amount 40")


def tour_kohl_map() -> None:
    banner("7. Where this lives in the kohl repo")
    diagram(
        """
  GLOSSARY.md              ← concepts (you are here via the script)
  BLUEPRINT.md §3.4        ← exact verification rules
  examples/learn_ringct.py ← this tour

  primitives/ringct-crypto/
      stealth.rs           ← dual-key addresses, view tags, amount mask
      clsag.rs             ← production CLSAG sign/verify
      lib.rs               ← Pedersen, Bulletproofs, host functions

  pallets/ringct/src/lib.rs
      verify_transfer()    ← shape → rings → CLSAG → balance → BP → apply
      signing_hash()       ← message every CLSAG signs

  wallet/                  ← scan + build real transfers
  node/                    ← PoW, register host functions
"""
    )


def run_checks() -> None:
    """Silent assertions for CI / --check."""
    # Pedersen
    x1, x2 = 3, 7
    assert point_add(commit(10, x1), commit(5, x2)) == commit(15, x1 + x2)
    assert verify_balance([commit(100, 9)], [commit(60, 4), commit(38, 5)], 2)

    # Stealth
    bob = keypair()
    r = random_scalar()
    R = point_mul(r)
    assert sender_shared(r, bob.view_public) == receiver_shared(bob.view_secret, R)
    shared = sender_shared(r, bob.view_public)
    P, _, _ = derive_otk(shared, bob.spend_public, 0)
    assert point_mul(recover_spend_secret(bob, R, 0)) == P

    # LSAG
    sk = random_scalar()
    pubs = [point_mul(random_scalar()), point_mul(sk), point_mul(random_scalar())]
    sig = lsag_sign(b"m", pubs, 1, sk)
    assert lsag_verify(b"m", pubs, sig)
    assert not lsag_verify(b"n", pubs, sig)
    assert key_image(sk) == sig.key_image

    # CLSAG
    x, xin, xp = random_scalar(), random_scalar(), random_scalar()
    amt = 77
    keys = [point_mul(random_scalar()), point_mul(x), point_mul(random_scalar())]
    commits = [commit(1, 1), commit(amt, xin), commit(2, 2)]
    csig = clsag_sign(b"c", keys, commits, 1, x, xin, xp)
    assert csig.pseudo == commit(amt, xp)
    assert clsag_verify(b"c", keys, commits, csig)
    print("all self-checks passed")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--quick", action="store_true", help="skip verbose CLSAG loop dump")
    parser.add_argument("--clsag", action="store_true", help="only LSAG/CLSAG sections")
    parser.add_argument("--check", action="store_true", help="run silent self-tests")
    args = parser.parse_args(argv)

    if args.check:
        run_checks()
        return 0

    print(
        "kohl / Monero RingCT learning tour\n"
        "Toy crypto only — see GLOSSARY.md for the full glossary.\n"
        "Production code: primitives/ringct-crypto + pallets/ringct"
    )

    if args.clsag:
        tour_lsag(verbose=True)
        tour_clsag(verbose=True)
        return 0

    tour_big_picture()
    tour_pedersen()
    tour_stealth()
    tour_key_image()
    tour_lsag(verbose=not args.quick)
    tour_clsag(verbose=not args.quick)
    tour_end_to_end()
    tour_kohl_map()

    banner("Done")
    print(
        """
  Next steps:
    • Re-read GLOSSARY.md §3–§6 with this mental model
    • Read BLUEPRINT.md §1.3 and §3.4
    • Open primitives/ringct-crypto/src/clsag.rs
    • Run:  cargo test -p ringct-crypto -p pallet-ringct

  Re-run options:
    python3 examples/learn_ringct.py --quick
    python3 examples/learn_ringct.py --clsag
    python3 examples/learn_ringct.py --check
"""
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
