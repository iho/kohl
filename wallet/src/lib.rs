//! Wallet core for the kohl chain (BLUEPRINT.md §5.2): deterministic key
//! management, chain scanning, and **FCMP** transfer construction (PR-7/8).
//! Offline and pure — the CLI (`main.rs`) adds RPC I/O on top.
//!
//! ## PR-8
//!
//! * [`membership::MembershipCache`] — witness cache + reorg resync
//! * Production path has **no decoy sampler** (FCMP full mature-set)
//! * Optional `legacy-decoy` feature keeps the old Monero-style sampler for experiments

use pallet_ringct::{FcmpInput, Output, StoredOutput, TransferTx};
use ringct_crypto::{
    clsag,
    fcmp::{self, ProveWitness, RingMember as FcmpTreeMember},
    native as crypto, stealth,
};
use ringct_primitives::{MAX_FCMP_INPUTS, MAX_OUTPUTS};

pub mod membership;
pub mod rpc;

#[cfg(feature = "legacy-decoy")]
pub mod decoy;

#[cfg(test)]
mod tests;

#[cfg(feature = "legacy-decoy")]
pub use decoy::{sample_decoys, DecoyCandidate, DecoyError};

pub use membership::{snapshot_from_frontier, MembershipCache};

pub type BlockNumber = u32;
pub type StoredOut = StoredOutput<BlockNumber>;

#[derive(Debug)]
pub enum WalletError {
    NotEnoughFunds {
        needed: u64,
        have: u64,
    },
    /// Membership tree / admitted set too small or missing the spend.
    MembershipIncomplete,
    /// Cached root/slots no longer match the chain (reorg or lag).
    MembershipStale,
    /// Interim FCMP0001 cannot prove trees larger than `MAX_FCMP_ANON_SET`.
    TreeTooLarge,
    Crypto(&'static str),
    Bounds,
}

impl core::fmt::Display for WalletError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WalletError::NotEnoughFunds { needed, have } => {
                write!(f, "not enough funds: need {needed}, have {have}")
            }
            WalletError::MembershipIncomplete => {
                write!(f, "membership tree incomplete for this spend")
            }
            WalletError::MembershipStale => {
                write!(f, "membership cache stale (reorg or root moved); refresh")
            }
            WalletError::TreeTooLarge => write!(f, "membership tree exceeds FCMP interim limit"),
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

/// Snapshot of the on-chain membership tree for proving (from RPC / node).
#[derive(Clone, Debug)]
pub struct MembershipSnapshot {
    pub root: [u8; 32],
    /// Leaf digests `0..tree_slots`.
    pub digests: Vec<[u8; 32]>,
    /// All admitted `(tree_index, P, C)` sorted by index.
    pub admitted: Vec<FcmpTreeMember>,
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

    pub fn address_string(&self) -> String {
        format!(
            "kohl:{}{}",
            hex::encode(self.address.view_public),
            hex::encode(self.address.spend_public)
        )
    }

    pub fn scan(&self, outputs: &[(u64, StoredOut)]) -> Vec<OwnedOutput> {
        outputs
            .iter()
            .filter_map(|(gi, out)| self.try_own(*gi, out))
            .collect()
    }

    fn try_own(&self, global_index: u64, out: &StoredOut) -> Option<OwnedOutput> {
        let shared = stealth::receiver_shared_secret(&self.keys.view_secret, &out.tx_pubkey)?;
        for li in 0..MAX_OUTPUTS {
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
                Some(a) => (a, [0u8; 32]),
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

    /// Single-input FCMP transfer.
    pub fn build_transfer(
        &self,
        input: &OwnedOutput,
        membership: &MembershipSnapshot,
        dest: &stealth::StealthAddress,
        send_amount: u64,
        fee: u64,
    ) -> Result<TransferTx, WalletError> {
        self.build_transfer_multi(
            core::slice::from_ref(input),
            membership,
            dest,
            send_amount,
            fee,
        )
    }

    /// Build an FCMP transfer spending one or more owned **admitted** outputs.
    ///
    /// `membership` must be the full mature-set snapshot under the root that
    /// will be published in the tx (from [`MembershipCache`] / RPC). Always
    /// emits two outputs (payment + change).
    pub fn build_transfer_multi(
        &self,
        inputs: &[OwnedOutput],
        membership: &MembershipSnapshot,
        dest: &stealth::StealthAddress,
        send_amount: u64,
        fee: u64,
    ) -> Result<TransferTx, WalletError> {
        if inputs.is_empty() || inputs.len() as u32 > MAX_FCMP_INPUTS {
            return Err(WalletError::Bounds);
        }
        if membership.digests.len() > ringct_primitives::MAX_FCMP_ANON_SET as usize {
            return Err(WalletError::TreeTooLarge);
        }
        if membership.admitted.is_empty() {
            return Err(WalletError::MembershipIncomplete);
        }
        if fcmp::root_from_leaves(&membership.digests) != membership.root {
            return Err(WalletError::MembershipStale);
        }
        for input in inputs {
            if !membership
                .admitted
                .iter()
                .any(|m| m.tree_index == input.global_index)
            {
                return Err(WalletError::MembershipIncomplete);
            }
        }

        let total_in: u64 = inputs.iter().try_fold(0u64, |acc, i| {
            acc.checked_add(i.amount).ok_or(WalletError::Bounds)
        })?;
        let total_needed = send_amount.checked_add(fee).ok_or(WalletError::Bounds)?;
        if total_in < total_needed {
            return Err(WalletError::NotEnoughFunds {
                needed: total_needed,
                have: total_in,
            });
        }
        let change = total_in - total_needed;

        let (tx_secret, tx_pubkey) = stealth::tx_keypair();
        let (out0, b0) = self.make_output(&tx_secret, dest, 0, send_amount)?;
        let (out1, b1) = self.make_output(&tx_secret, &self.address, 1, change)?;

        let out_blindings = [b0, b1];
        let mut free: Vec<[u8; 32]> = (0..inputs.len().saturating_sub(1))
            .map(|_| crypto::random_blinding())
            .collect();
        let last = crypto::balancing_blinding(&out_blindings, &free)
            .ok_or(WalletError::Crypto("blinding sum"))?;
        free.push(last);
        let pseudo_blindings = free;

        // Stage by key image.
        let mut staged: Vec<(OwnedOutput, [u8; 32], usize, [u8; 32])> = Vec::new();
        for (input, pb) in inputs.iter().zip(pseudo_blindings.iter()) {
            let real_index = membership
                .admitted
                .iter()
                .position(|m| m.tree_index == input.global_index)
                .ok_or(WalletError::MembershipIncomplete)?;
            let c_prime = crypto::commit(input.amount, pb).ok_or(WalletError::Crypto("commit"))?;
            staged.push((input.clone(), *pb, real_index, c_prime));
        }
        staged.sort_by_key(|s| s.0.key_image);

        let mut skeleton = Vec::with_capacity(staged.len());
        for (input, _, _, c_prime) in &staged {
            skeleton.push(FcmpInput {
                key_image: input.key_image,
                pseudo_commitment: *c_prime,
                fcmp_proof: bounded(vec![0u8; 32])?,
            });
        }

        let (proof, _commits) = crypto::prove_range(&[send_amount, change], &out_blindings)
            .ok_or(WalletError::Crypto("range proof"))?;

        let mut tx = TransferTx {
            membership_root: membership.root,
            inputs: bounded(skeleton)?,
            outputs: bounded(vec![out0, out1])?,
            tx_pubkey,
            range_proof: bounded(proof)?,
            fee,
        };
        let msg = pallet_ringct::signing_hash(&tx);

        let mut final_inputs = Vec::new();
        for (input, pb, real_index, c_prime) in &staged {
            let witness = ProveWitness {
                digests: membership.digests.clone(),
                admitted: membership.admitted.clone(),
                real_index: *real_index,
                secret_key: input.secret,
                input_blinding: input.blinding,
                pseudo_blinding: *pb,
            };
            let res = fcmp::prove(&msg, &witness).ok_or(WalletError::Crypto("fcmp prove"))?;
            if res.key_image != input.key_image || res.pseudo_commitment != *c_prime {
                return Err(WalletError::Crypto("fcmp ki/commitment mismatch"));
            }
            final_inputs.push(FcmpInput {
                key_image: input.key_image,
                pseudo_commitment: *c_prime,
                fcmp_proof: bounded(res.proof)?,
            });
        }
        tx.inputs = bounded(final_inputs)?;
        Ok(tx)
    }

    /// Rough encoded-size estimate for fee calculation (FCMP0001 scales with n).
    pub fn estimate_tx_bytes(tree_slots: u64, inputs: usize) -> u64 {
        let n = tree_slots.max(1);
        let per_input = 8 + n * 32 + n * 72 + 32 * (n + 2) + 256;
        2_000u64
            .saturating_add(per_input.saturating_mul(inputs.max(1) as u64))
            .min(60_000)
    }

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
        let commitment = crypto::commit(amount, &blinding).ok_or(WalletError::Crypto("commit"))?;
        let payload = bounded(stealth::mask_amount(&shared, li, amount).to_vec())?;
        Ok((
            Output {
                one_time_key,
                commitment,
                view_tag,
                payload,
            },
            blinding,
        ))
    }
}

fn bounded<T, const N: u32>(
    v: Vec<T>,
) -> Result<frame_support::BoundedVec<T, frame_support::traits::ConstU32<N>>, WalletError> {
    frame_support::BoundedVec::try_from(v).map_err(|_| WalletError::Bounds)
}
