//! Wallet core for the kohl chain (BLUEPRINT.md §5.2): deterministic key
//! management, chain scanning, and RingCT transfer construction. Everything
//! here is offline and pure — the CLI (`main.rs`) adds RPC I/O on top.
//!
//! The transfer builder produces transactions that pass the *same*
//! verification the runtime runs (CLSAG, the balance equation, and the
//! aggregated range proof), which the unit tests assert directly.

use pallet_ringct::{Output, RingInput, StoredOutput, TransferTx};
use ringct_crypto::{clsag, native as crypto, stealth};
use ringct_primitives::MAX_OUTPUTS;

pub mod decoy;
pub mod rpc;

pub use decoy::{sample_decoys, DecoyCandidate, DecoyError};

pub type BlockNumber = u32;
pub type StoredOut = StoredOutput<BlockNumber>;

#[derive(Debug)]
pub enum WalletError {
    NotEnoughFunds { needed: u64, have: u64 },
    RingTooSmall,
    Crypto(&'static str),
    Bounds,
}

impl core::fmt::Display for WalletError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WalletError::NotEnoughFunds { needed, have } => {
                write!(f, "not enough funds: need {needed}, have {have}")
            }
            WalletError::RingTooSmall => write!(f, "not enough decoys to form the ring"),
            WalletError::Crypto(s) => write!(f, "crypto error: {s}"),
            WalletError::Bounds => write!(f, "a bounded vector overflowed"),
        }
    }
}
impl std::error::Error for WalletError {}

/// An output the wallet owns and can spend.
#[derive(Clone, Debug)]
pub struct OwnedOutput {
    pub global_index: u64,
    pub local_index: u32,
    pub amount: u64,
    pub blinding: [u8; 32],
    pub secret: [u8; 32],
    pub key_image: [u8; 32],
    pub one_time_key: [u8; 32],
    pub commitment: [u8; 32],
    pub height: BlockNumber,
    pub coinbase: bool,
}

/// A prospective ring member (a decoy pulled from the chain's output set).
#[derive(Clone, Debug)]
pub struct RingMember {
    pub global_index: u64,
    pub one_time_key: [u8; 32],
    pub commitment: [u8; 32],
}

pub struct Wallet {
    pub keys: stealth::StealthKeys,
    pub address: stealth::StealthAddress,
}

impl Wallet {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let (keys, address) = stealth::keypair_from_seed(seed);
        Self { keys, address }
    }

    /// Bech32-free textual address: `kohl:<view_pub><spend_pub>` in hex.
    pub fn address_string(&self) -> String {
        format!(
            "kohl:{}{}",
            hex::encode(self.address.view_public),
            hex::encode(self.address.spend_public)
        )
    }

    /// Scan `(global_index, output)` pairs and return the ones we own, with
    /// everything needed to spend them.
    pub fn scan(&self, outputs: &[(u64, StoredOut)]) -> Vec<OwnedOutput> {
        outputs.iter().filter_map(|(gi, out)| self.try_own(*gi, out)).collect()
    }

    fn try_own(&self, global_index: u64, out: &StoredOut) -> Option<OwnedOutput> {
        let shared = stealth::receiver_shared_secret(&self.keys.view_secret, &out.tx_pubkey)?;
        // We don't store the local output index on chain, so try the small
        // range [0, MAX_OUTPUTS): the one-time key derivation pins it down.
        for li in 0..MAX_OUTPUTS {
            let (otk, _tag) =
                stealth::derive_one_time_key(&shared, &self.address.spend_public, li)?;
            if otk != out.one_time_key {
                continue;
            }
            let secret = stealth::recover_spend_secret(&self.keys, &out.tx_pubkey, li)?;
            let (amount, blinding) = match out.amount {
                // Coinbase: amount is public, blinding is zero.
                Some(a) => (a, [0u8; 32]),
                // Confidential: recover the amount from the masked payload and
                // the blinding from the shared secret; verify the commitment.
                None => {
                    let payload = out.payload.as_slice();
                    if payload.len() < 8 {
                        return None;
                    }
                    let mut masked = [0u8; 8];
                    masked.copy_from_slice(&payload[..8]);
                    let amount = stealth::unmask_amount(&shared, li, &masked);
                    let blinding = stealth::derive_blinding(&shared, li);
                    if crypto::commit(amount, &blinding)? != out.commitment {
                        continue;
                    }
                    (amount, blinding)
                }
            };
            let key_image = clsag::key_image(&secret)?;
            return Some(OwnedOutput {
                global_index,
                local_index: li,
                amount,
                blinding,
                secret,
                key_image,
                one_time_key: out.one_time_key,
                commitment: out.commitment,
                height: out.height,
                coinbase: out.coinbase,
            });
        }
        None
    }

    /// Build a RingCT transfer spending `input`, hidden in a ring with
    /// `decoys`, sending `send_amount` to `dest` and the change back to self.
    /// The produced transaction is chain-valid (its CLSAG, balance equation,
    /// and range proof all verify).
    pub fn build_transfer(
        &self,
        input: &OwnedOutput,
        decoys: &[RingMember],
        dest: &stealth::StealthAddress,
        send_amount: u64,
        fee: u64,
    ) -> Result<TransferTx, WalletError> {
        if decoys.is_empty() {
            return Err(WalletError::RingTooSmall);
        }
        let total = send_amount.checked_add(fee).ok_or(WalletError::Bounds)?;
        if input.amount < total {
            return Err(WalletError::NotEnoughFunds { needed: total, have: input.amount });
        }
        let change = input.amount - total;

        // --- assemble the ring (sorted by global index) ---
        let mut ring: Vec<RingMember> = decoys.to_vec();
        ring.push(RingMember {
            global_index: input.global_index,
            one_time_key: input.one_time_key,
            commitment: input.commitment,
        });
        ring.sort_by_key(|m| m.global_index);
        ring.dedup_by_key(|m| m.global_index);
        let position = ring
            .iter()
            .position(|m| m.global_index == input.global_index)
            .ok_or(WalletError::RingTooSmall)?;
        let ring_indices: Vec<u64> = ring.iter().map(|m| m.global_index).collect();
        let mut ring_blob = Vec::with_capacity(ring.len() * 64);
        for m in &ring {
            ring_blob.extend_from_slice(&m.one_time_key);
            ring_blob.extend_from_slice(&m.commitment);
        }

        // --- build the two outputs (dest + change) under one tx keypair ---
        let (tx_secret, tx_pubkey) = stealth::tx_keypair();
        let (out0, b0) = self.make_output(&tx_secret, dest, 0, send_amount)?;
        let (out1, b1) = self.make_output(&tx_secret, &self.address, 1, change)?;

        // Pseudo-output blinding balances the single input: Σ pseudo = Σ out.
        let pseudo_blinding = crypto::balancing_blinding(&[b0, b1], &[])
            .ok_or(WalletError::Crypto("blinding sum"))?;
        let pseudo_commitment =
            crypto::commit(input.amount, &pseudo_blinding).ok_or(WalletError::Crypto("commit"))?;

        // Aggregated range proof over the output amounts.
        let (proof, _commits) = crypto::prove_range(&[send_amount, change], &[b0, b1])
            .ok_or(WalletError::Crypto("range proof"))?;

        let ring_input = RingInput {
            ring: bounded(ring_indices)?,
            key_image: input.key_image,
            pseudo_commitment,
            clsag: bounded(Vec::new())?,
        };
        let mut tx = TransferTx {
            inputs: bounded(vec![ring_input])?,
            outputs: bounded(vec![out0, out1])?,
            tx_pubkey,
            range_proof: bounded(proof)?,
            fee,
        };

        // Sign every input's CLSAG over the binding hash of the whole tx.
        let msg = pallet_ringct::signing_hash(&tx);
        let sig = clsag::sign(
            &msg,
            &ring_blob,
            position,
            &input.secret,
            &input.blinding,
            &pseudo_blinding,
        )
        .ok_or(WalletError::Crypto("clsag sign"))?;
        debug_assert_eq!(sig.key_image, input.key_image);
        debug_assert_eq!(sig.pseudo_commitment, pseudo_commitment);
        tx.inputs[0].clsag = bounded(sig.signature)?;
        Ok(tx)
    }

    /// Build one stealth output to `recipient` at local index `li` for
    /// `amount`; returns the output and its (ECDH-derived) blinding.
    fn make_output(
        &self,
        tx_secret: &[u8; 32],
        recipient: &stealth::StealthAddress,
        li: u32,
        amount: u64,
    ) -> Result<(Output, [u8; 32]), WalletError> {
        let shared = stealth::sender_shared_secret(tx_secret, &recipient.view_public)
            .ok_or(WalletError::Crypto("shared secret"))?;
        let (one_time_key, view_tag) =
            stealth::derive_one_time_key(&shared, &recipient.spend_public, li)
                .ok_or(WalletError::Crypto("one-time key"))?;
        let blinding = stealth::derive_blinding(&shared, li);
        let commitment =
            crypto::commit(amount, &blinding).ok_or(WalletError::Crypto("commit"))?;
        let payload = bounded(stealth::mask_amount(&shared, li, amount).to_vec())?;
        Ok((Output { one_time_key, commitment, view_tag, payload }, blinding))
    }
}

fn bounded<T, S: frame_support::traits::Get<u32>>(
    v: Vec<T>,
) -> Result<frame_support::BoundedVec<T, S>, WalletError> {
    frame_support::BoundedVec::try_from(v).map_err(|_| WalletError::Bounds)
}

#[cfg(test)]
mod tests;
