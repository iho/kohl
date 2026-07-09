//! CryptoNote dual-key stealth addresses with Monero-style view tags.
//!
//! Entirely wallet-side: the chain only ever sees one-time keys, tx pubkeys
//! and view tags; addresses are never published on chain.
//!
//! * Address: `(A, B) = (a·G, b·G)` — view and spend keypairs.
//! * Sender: random tx secret `r`, publishes `R = r·G`; per output `i`
//!   derives `h = Hs(r·A ‖ i)` and one-time key `P = h·G + B`.
//! * Receiver scanning: shared secret `a·R == r·A`; the 1-byte view tag
//!   rejects ~255/256 foreign outputs with a single hash before the full
//!   derivation check.
//! * Spending: `x = h + b` (so `P = x·G`); `x` feeds the CLSAG and its key
//!   image — one-time keys make every payment unlinkable to the address.
//! * The shared secret also derives the output's commitment blinding and an
//!   8-byte amount mask, so the receiver reconstructs (amount, blinding)
//!   from the chain alone — no out-of-band data.

use crate::clsag::hs;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};

const DOM_OTK: &[u8] = b"kohl/stealth/otk/v1";
const DOM_VIEW_TAG: &[u8] = b"kohl/stealth/view-tag/v1";
const DOM_BLINDING: &[u8] = b"kohl/stealth/blinding/v1";
const DOM_AMOUNT: &[u8] = b"kohl/stealth/amount/v1";

/// Wallet secrets. In a real wallet `view_secret` is derived from
/// `spend_secret` (mnemonic recovers both); independent here for clarity.
pub struct StealthKeys {
    pub view_secret: [u8; 32],
    pub spend_secret: [u8; 32],
}

/// The public address `(A, B)`.
#[derive(Clone, Copy)]
pub struct StealthAddress {
    pub view_public: [u8; 32],
    pub spend_public: [u8; 32],
}

fn scalar(bytes: &[u8; 32]) -> Option<Scalar> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes))
}

fn decompress(bytes: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto::from_slice(bytes).ok()?.decompress()
}

fn address_of(a: Scalar, b: Scalar) -> (StealthKeys, StealthAddress) {
    (
        StealthKeys { view_secret: a.to_bytes(), spend_secret: b.to_bytes() },
        StealthAddress {
            view_public: (G * a).compress().to_bytes(),
            spend_public: (G * b).compress().to_bytes(),
        },
    )
}

pub fn keypair() -> (StealthKeys, StealthAddress) {
    let mut rng = rand::rngs::OsRng;
    address_of(Scalar::random(&mut rng), Scalar::random(&mut rng))
}

/// Deterministic wallet keys from a 32-byte seed (e.g. a mnemonic's entropy).
/// The same seed always recovers the same address and secrets.
pub fn keypair_from_seed(seed: &[u8; 32]) -> (StealthKeys, StealthAddress) {
    let a = crate::clsag::hs(b"kohl/wallet/view/v1", &[seed]);
    let b = crate::clsag::hs(b"kohl/wallet/spend/v1", &[seed]);
    address_of(a, b)
}

/// Fresh per-transaction keypair `(r, R = r·G)`.
pub fn tx_keypair() -> ([u8; 32], [u8; 32]) {
    let r = Scalar::random(&mut rand::rngs::OsRng);
    (r.to_bytes(), (G * r).compress().to_bytes())
}

/// Sender side: `r·A`, compressed.
pub fn sender_shared_secret(tx_secret: &[u8; 32], view_public: &[u8; 32]) -> Option<[u8; 32]> {
    Some((decompress(view_public)? * scalar(tx_secret)?).compress().to_bytes())
}

/// Receiver side: `a·R`, compressed — equals the sender's `r·A`.
pub fn receiver_shared_secret(view_secret: &[u8; 32], tx_pubkey: &[u8; 32]) -> Option<[u8; 32]> {
    Some((decompress(tx_pubkey)? * scalar(view_secret)?).compress().to_bytes())
}

fn derivation_scalar(shared: &[u8; 32], output_index: u32) -> Scalar {
    hs(DOM_OTK, &[shared, &output_index.to_le_bytes()])
}

pub fn view_tag(shared: &[u8; 32], output_index: u32) -> u8 {
    hs(DOM_VIEW_TAG, &[shared, &output_index.to_le_bytes()]).to_bytes()[0]
}

/// Sender: derive the one-time key and view tag for output `output_index`.
pub fn derive_one_time_key(
    shared: &[u8; 32],
    spend_public: &[u8; 32],
    output_index: u32,
) -> Option<([u8; 32], u8)> {
    let p = G * derivation_scalar(shared, output_index) + decompress(spend_public)?;
    Some((p.compress().to_bytes(), view_tag(shared, output_index)))
}

/// Receiver scanning: does this output belong to `(view_secret, spend_public)`?
/// Checks the cheap view tag first, then the full derivation.
pub fn matches_output(
    view_secret: &[u8; 32],
    spend_public: &[u8; 32],
    tx_pubkey: &[u8; 32],
    output_index: u32,
    one_time_key: &[u8; 32],
    tag: u8,
) -> bool {
    let Some(shared) = receiver_shared_secret(view_secret, tx_pubkey) else {
        return false;
    };
    if view_tag(&shared, output_index) != tag {
        return false;
    }
    derive_one_time_key(&shared, spend_public, output_index)
        .is_some_and(|(p, _)| p == *one_time_key)
}

/// Receiver: the one-time secret `x = Hs(a·R ‖ i) + b` (needs both keys).
pub fn recover_spend_secret(
    keys: &StealthKeys,
    tx_pubkey: &[u8; 32],
    output_index: u32,
) -> Option<[u8; 32]> {
    let shared = receiver_shared_secret(&keys.view_secret, tx_pubkey)?;
    Some((derivation_scalar(&shared, output_index) + scalar(&keys.spend_secret)?).to_bytes())
}

/// Deterministic commitment blinding for an output — both sides derive it,
/// so only the 8-byte masked amount needs to ride on chain.
pub fn derive_blinding(shared: &[u8; 32], output_index: u32) -> [u8; 32] {
    hs(DOM_BLINDING, &[shared, &output_index.to_le_bytes()]).to_bytes()
}

/// XOR mask for the public 8-byte encrypted amount (symmetric: call again
/// to decrypt).
pub fn mask_amount(shared: &[u8; 32], output_index: u32, amount: u64) -> [u8; 8] {
    let mask = hs(DOM_AMOUNT, &[shared, &output_index.to_le_bytes()]).to_bytes();
    let mut out = amount.to_le_bytes();
    for (o, m) in out.iter_mut().zip(mask) {
        *o ^= m;
    }
    out
}

pub fn unmask_amount(shared: &[u8; 32], output_index: u32, masked: &[u8; 8]) -> u64 {
    let mask = hs(DOM_AMOUNT, &[shared, &output_index.to_le_bytes()]).to_bytes();
    let mut out = *masked;
    for (o, m) in out.iter_mut().zip(mask) {
        *o ^= m;
    }
    u64::from_le_bytes(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;

    #[test]
    fn full_stealth_roundtrip() {
        let (keys, addr) = keypair();
        let (r, tx_pub) = tx_keypair();

        let shared_s = sender_shared_secret(&r, &addr.view_public).unwrap();
        let shared_r = receiver_shared_secret(&keys.view_secret, &tx_pub).unwrap();
        assert_eq!(shared_s, shared_r);

        let (otk, tag) = derive_one_time_key(&shared_s, &addr.spend_public, 3).unwrap();
        assert!(matches_output(&keys.view_secret, &addr.spend_public, &tx_pub, 3, &otk, tag));
        // Wrong index or wrong wallet: no match.
        assert!(!matches_output(&keys.view_secret, &addr.spend_public, &tx_pub, 4, &otk, tag));
        let (other, _) = keypair();
        assert!(!matches_output(&other.view_secret, &addr.spend_public, &tx_pub, 3, &otk, tag));

        // Recovered secret actually opens the one-time key.
        let x = recover_spend_secret(&keys, &tx_pub, 3).unwrap();
        let x_scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(x)).unwrap();
        assert_eq!((G * x_scalar).compress().to_bytes(), otk);

        // Amount + blinding derivation round-trips.
        let masked = mask_amount(&shared_s, 3, 123_456_789);
        assert_eq!(unmask_amount(&shared_r, 3, &masked), 123_456_789);
        assert_eq!(derive_blinding(&shared_s, 3), derive_blinding(&shared_r, 3));
    }

    #[test]
    fn view_only_wallet_cannot_spend() {
        let (keys, addr) = keypair();
        let (r, tx_pub) = tx_keypair();
        let shared = sender_shared_secret(&r, &addr.view_public).unwrap();
        let (otk, tag) = derive_one_time_key(&shared, &addr.spend_public, 0).unwrap();

        // View key alone detects…
        assert!(matches_output(&keys.view_secret, &addr.spend_public, &tx_pub, 0, &otk, tag));
        // …but a wrong spend secret does not produce the right key.
        let (other, _) = keypair();
        let fake = StealthKeys {
            view_secret: keys.view_secret,
            spend_secret: other.spend_secret,
        };
        let x = recover_spend_secret(&fake, &tx_pub, 0).unwrap();
        let x_scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(x)).unwrap();
        assert_ne!((G * x_scalar).compress().to_bytes(), otk);
    }
}
