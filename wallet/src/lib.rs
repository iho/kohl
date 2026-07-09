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
        // Local output index is not on chain; try [0, MAX_OUTPUTS). View tags
        // reject ~255/256 candidates with one hash before full derivation.
        for li in 0..MAX_OUTPUTS {
            // Fast reject: view tag must match before full OTK derivation.
            if stealth::view_tag(&shared, li) != out.view_tag {
                continue;
            }
            let (otk, _tag) =
                stealth::derive_one_time_key(&shared, &self.address.spend_public, li)?;
            if otk != out.one_time_key {
                continue;
            }
            let secret = stealth::recover_spend_secret(&self.keys, &out.tx_pubkey, li)?;
            let (amount, blinding) = match out.amount {
                // Coinbase: amount is public, blinding is zero.
                Some(a) => (a, [0u8; 32]),
                // Confidential: recover amount + blinding; verify commitment.
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

    /// Single-input convenience wrapper around [`Self::build_transfer_multi`].
    pub fn build_transfer(
        &self,
        input: &OwnedOutput,
        decoys: &[RingMember],
        dest: &stealth::StealthAddress,
        send_amount: u64,
        fee: u64,
    ) -> Result<TransferTx, WalletError> {
        self.build_transfer_multi(
            core::slice::from_ref(input),
            &[decoys.to_vec()],
            dest,
            send_amount,
            fee,
        )
    }

    /// Build a RingCT transfer spending one or more owned outputs.
    ///
    /// `rings_decoys[i]` is the decoy set for `inputs[i]` (must have the same
    /// length as `inputs`). Each input is hidden in a ring of
    /// `decoys + self`. Inputs are sorted by key image before signing (chain
    /// canonical form). Always emits **two** outputs (payment + change) for
    /// uniform shape.
    pub fn build_transfer_multi(
        &self,
        inputs: &[OwnedOutput],
        rings_decoys: &[Vec<RingMember>],
        dest: &stealth::StealthAddress,
        send_amount: u64,
        fee: u64,
    ) -> Result<TransferTx, WalletError> {
        if inputs.is_empty() || inputs.len() != rings_decoys.len() {
            return Err(WalletError::Bounds);
        }
        let total_in: u64 = inputs.iter().try_fold(0u64, |acc, i| {
            acc.checked_add(i.amount).ok_or(WalletError::Bounds)
        })?;
        let total_needed = send_amount.checked_add(fee).ok_or(WalletError::Bounds)?;
        if total_in < total_needed {
            return Err(WalletError::NotEnoughFunds { needed: total_needed, have: total_in });
        }
        let change = total_in - total_needed;

        // --- outputs (dest + change) under one tx keypair ---
        let (tx_secret, tx_pubkey) = stealth::tx_keypair();
        let (out0, b0) = self.make_output(&tx_secret, dest, 0, send_amount)?;
        let (out1, b1) = self.make_output(&tx_secret, &self.address, 1, change)?;

        // Pseudo blindings: free for first n−1 inputs; last closes
        // Σ C' = Σ C_out  (i.e. Σ x' = b0 + b1).
        let mut free: Vec<[u8; 32]> =
            (0..inputs.len().saturating_sub(1)).map(|_| crypto::random_blinding()).collect();
        let last = crypto::balancing_blinding(&[b0, b1], &free)
            .ok_or(WalletError::Crypto("blinding sum"))?;
        free.push(last);
        let pseudo_blindings = free;

        // Build unsigned inputs (CLSAG filled after signing_hash).
        struct Prepared {
            input: OwnedOutput,
            ring: Vec<RingMember>,
            position: usize,
            ring_blob: Vec<u8>,
            pseudo_blinding: [u8; 32],
            pseudo_commitment: [u8; 32],
        }
        let mut prepared = Vec::with_capacity(inputs.len());
        for (input, (decoys, pb)) in
            inputs.iter().zip(rings_decoys.iter().zip(pseudo_blindings.iter()))
        {
            if decoys.is_empty() {
                return Err(WalletError::RingTooSmall);
            }
            let mut ring = decoys.clone();
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
            let mut ring_blob = Vec::with_capacity(ring.len() * 64);
            for m in &ring {
                ring_blob.extend_from_slice(&m.one_time_key);
                ring_blob.extend_from_slice(&m.commitment);
            }
            let pseudo_commitment =
                crypto::commit(input.amount, pb).ok_or(WalletError::Crypto("commit"))?;
            prepared.push(Prepared {
                input: input.clone(),
                ring,
                position,
                ring_blob,
                pseudo_blinding: *pb,
                pseudo_commitment,
            });
        }

        // Canonical order by key image (matches chain rule).
        prepared.sort_by_key(|p| p.input.key_image);

        let (proof, _commits) = crypto::prove_range(&[send_amount, change], &[b0, b1])
            .ok_or(WalletError::Crypto("range proof"))?;

        let ring_inputs: Vec<RingInput> = prepared
            .iter()
            .map(|p| {
                let indices: Vec<u64> = p.ring.iter().map(|m| m.global_index).collect();
                Ok(RingInput {
                    ring: bounded(indices)?,
                    key_image: p.input.key_image,
                    pseudo_commitment: p.pseudo_commitment,
                    clsag: bounded(Vec::new())?,
                })
            })
            .collect::<Result<_, WalletError>>()?;

        let mut tx = TransferTx {
            inputs: bounded(ring_inputs)?,
            outputs: bounded(vec![out0, out1])?,
            tx_pubkey,
            range_proof: bounded(proof)?,
            fee,
        };

        let msg = pallet_ringct::signing_hash(&tx);
        for (i, p) in prepared.iter().enumerate() {
            let sig = clsag::sign(
                &msg,
                &p.ring_blob,
                p.position,
                &p.input.secret,
                &p.input.blinding,
                &p.pseudo_blinding,
            )
            .ok_or(WalletError::Crypto("clsag sign"))?;
            debug_assert_eq!(sig.key_image, p.input.key_image);
            debug_assert_eq!(sig.pseudo_commitment, p.pseudo_commitment);
            tx.inputs[i].clsag = bounded(sig.signature)?;
        }
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
