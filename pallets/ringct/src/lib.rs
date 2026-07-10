//! # pallet-ringct — the kohl monetary system
//!
//! **PR-7: FCMP-only spends.** Mandatory privacy (BLUEPRINT.md §1.3):
//!
//! 1. **Sender anonymity** — full mature-set membership under the Path A
//!    Merkle root (`FCMP0001` + CLSAG SA+L; see `ringct_crypto::fcmp`).
//! 2. **Receiver privacy** — one-time stealth keys + view tags.
//! 3. **Amount confidentiality** — Pedersen commitments + Bulletproofs;
//!    balance `Σ C_pseudo == Σ C_out + fee·H`.
//!
//! Double spends: permanent **key images**. Transfers are unsigned
//! self-authenticating extrinsics (`AuthorizeCall`). Membership tree
//! (PR-1/2) admits mature leaves; maturity is implied by non-EMPTY membership.
//! Host verify: `verify_fcmp_v1` (PR-4/5). Weights: `transfer_fcmp` (PR-6).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::{pallet_prelude::*, BoundedVec};
use frame_system::pallet_prelude::*;
use ringct_primitives::{
    block_reward, FCMP_ADMIT_MAX_LEAVES_PER_BLOCK, FCMP_GROW_CATCHUP_MAX_PER_BLOCK,
    FCMP_ROOT_MAX_AGE_BLOCKS, MAX_FCMP_ANON_SET, MAX_FCMP_INPUTS, MAX_FCMP_PROOF_BYTES,
    MAX_OUTPUTS, MAX_PAYLOAD_BYTES, MAX_RANGE_PROOF_BYTES,
};
use scale_info::TypeInfo;
use sp_runtime::transaction_validity::{InvalidTransaction, ValidTransaction};

pub use pallet::*;
pub mod membership;
pub mod weights;
pub use weights::WeightInfo;

/// Legacy mode constant (tree + CLSAG); no longer returned by [`Pallet::fcmp_mode`].
pub const FCMP_MODE_BUILDING: u8 = 1;
/// Production: FCMP-only spends (PR-7).
pub const FCMP_MODE_FCMP_ONLY: u8 = 2;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

#[cfg(test)]
mod mainnet_invariants;
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

/// Domain-separation prefix for the FCMP transfer signing hash (v4).
/// Changing tx semantics MUST change this string (consensus-critical).
pub const SIGNING_DOMAIN: [u8; 16] = *b"kohl/transfer/v4";

/// Alias matching design doc name.
pub const FCMP_SIGNING_DOMAIN: [u8; 16] = SIGNING_DOMAIN;

/// Inherent identifier for the coinbase call.
pub const INHERENT_IDENTIFIER: sp_inherents::InherentIdentifier = *b"ringct0b";

/// Opaque per-output wallet payload. Convention: the 8-byte masked amount
/// (`stealth::mask_amount`); the blinding is derived from the shared secret.
pub type Payload = BoundedVec<u8, ConstU32<MAX_PAYLOAD_BYTES>>;

/// Inherent data a mining node supplies for its coinbase: the payout
/// destination `(one_time_key, tx_pubkey, view_tag)`. The reward amount is
/// computed by the runtime, not the miner (see `ProvideInherent::create_inherent`).
pub type CoinbaseInherent = ([u8; 32], [u8; 32], u8);

/// The message every FCMP input proves against: binds membership root, key
/// images, pseudo-commitments, outputs, tx pubkey and fee — not the proof
/// blobs or range proof (those bind via their own transcripts).
///
/// Free function so wallets can build/sign without a runtime.
pub fn signing_hash(tx: &TransferTx) -> [u8; 32] {
    let key_images: Vec<[u8; 32]> = tx.inputs.iter().map(|i| i.key_image).collect();
    let pseudos: Vec<[u8; 32]> = tx.inputs.iter().map(|i| i.pseudo_commitment).collect();
    sp_io::hashing::blake2_256(
        &(
            SIGNING_DOMAIN,
            tx.membership_root,
            key_images,
            pseudos,
            &tx.outputs,
            tx.tx_pubkey,
            tx.fee,
        )
            .encode(),
    )
}

/// A newly created confidential output as it appears inside a transaction.
#[derive(
    Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct Output {
    /// One-time stealth key `P = Hs(rA‖i)·G + B` (compressed Ristretto).
    pub one_time_key: [u8; 32],
    /// Pedersen commitment to the amount.
    pub commitment: [u8; 32],
    /// 1-byte scan hint: wallets skip ~255/256 outputs with one hash.
    pub view_tag: u8,
    /// Opaque payload for the receiver's wallet (masked amount).
    pub payload: Payload,
}

/// A coinbase output: amount is public (as in Monero); the chain derives its
/// commitment as `amount·H` (zero blinding), so it participates in later
/// confidential balance equations like any other output.
#[derive(
    Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct CoinbaseOutput {
    /// One-time key of the miner (stealth-derived like any output).
    pub one_time_key: [u8; 32],
    pub amount: u64,
    /// View tag for wallet scanning (same convention as confidential outs).
    pub view_tag: u8,
}

/// A stored output: the on-chain record plus consensus bookkeeping.
#[derive(
    Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct StoredOutput<BlockNumber> {
    pub one_time_key: [u8; 32],
    pub commitment: [u8; 32],
    /// The transaction pubkey `R = r·G` this output was created under —
    /// wallets need it to scan.
    pub tx_pubkey: [u8; 32],
    pub view_tag: u8,
    /// Receiver payload (masked amount) — empty for coinbase outputs, whose
    /// amount is already public.
    pub payload: Payload,
    /// Public amount — `Some` only for coinbase outputs.
    pub amount: Option<u64>,
    /// Block in which the output was created (maturity rules).
    pub height: BlockNumber,
    /// Coinbase outputs have a longer maturity (`CoinbaseMaturity`).
    pub coinbase: bool,
}

/// One FCMP spend inside a transfer.
#[derive(
    Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct FcmpInput {
    /// Key image `I = x·Hp(P)` — the permanent nullifier.
    pub key_image: [u8; 32],
    /// Pseudo-output commitment `C'`: same amount as the real input under a
    /// fresh blinding; feeds the tx balance equation.
    pub pseudo_commitment: [u8; 32],
    /// `FCMP0001` proof blob (membership + SA+L).
    pub fcmp_proof: BoundedVec<u8, ConstU32<MAX_FCMP_PROOF_BYTES>>,
}

/// Deprecated name: production inputs are [`FcmpInput`] (no ring indices).
pub type RingInput = FcmpInput;

/// A complete FCMP transfer: unsigned self-authenticating extrinsic.
#[derive(
    Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct TransferTx {
    /// Single membership root anchor for all inputs (D13).
    pub membership_root: [u8; 32],
    pub inputs: BoundedVec<FcmpInput, ConstU32<MAX_FCMP_INPUTS>>,
    pub outputs: BoundedVec<Output, ConstU32<MAX_OUTPUTS>>,
    /// Per-tx pubkey `R = r·G` for stealth derivation.
    pub tx_pubkey: [u8; 32],
    /// One aggregated Bulletproof covering all output commitments.
    pub range_proof: BoundedVec<u8, ConstU32<MAX_RANGE_PROOF_BYTES>>,
    /// The one public amount. Consensus: Σ C_pseudo == Σ C_out + fee·H.
    pub fee: u64,
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use ringct_crypto::ringct_crypto as crypto_host;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        #[allow(deprecated)]
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Blocks before a non-coinbase output may be admitted (tree fill).
        #[pallet::constant]
        type SpendableAge: Get<BlockNumberFor<Self>>;

        /// Blocks before a coinbase output may be admitted (tree fill).
        #[pallet::constant]
        type CoinbaseMaturity: Get<BlockNumberFor<Self>>;

        /// Spam floor: required fee per encoded byte of the transfer.
        #[pallet::constant]
        type MinFeePerByte: Get<u64>;

        /// Extrinsic weights (see [`weights`]).
        type WeightInfo: weights::WeightInfo;
    }

    /// Append-only output set, keyed by global output index.
    #[pallet::storage]
    pub type Outputs<T: Config> =
        StorageMap<_, Twox64Concat, u64, StoredOutput<BlockNumberFor<T>>, OptionQuery>;

    /// Next global output index (== total outputs ever created).
    #[pallet::storage]
    pub type NextOutputIndex<T> = StorageValue<_, u64, ValueQuery>;

    /// Spent key images. Presence = spent. Never pruned.
    #[pallet::storage]
    pub type KeyImages<T> = StorageMap<_, Blake2_128Concat, [u8; 32], (), OptionQuery>;

    /// Total coins emitted so far. Public: supply is auditable even though
    /// individual amounts are not.
    #[pallet::storage]
    pub type Emitted<T> = StorageValue<_, u64, ValueQuery>;

    /// Fees accumulated since the last coinbase; claimed by the next one.
    #[pallet::storage]
    pub type BlockFees<T> = StorageValue<_, u64, ValueQuery>;

    /// Whether a coinbase has already been included in the current block.
    #[pallet::storage]
    pub type CoinbaseDone<T> = StorageValue<_, bool, ValueQuery>;

    // ---- FCMP Path A membership tree (PR-1/PR-2; maintenance only) ----

    /// Number of tree slots grown (`0..TreeSlots` have leaf digests).
    /// Steady state: equals `NextOutputIndex`. Lag mode: may trail.
    #[pallet::storage]
    pub type TreeSlots<T> = StorageValue<_, u64, ValueQuery>;

    /// Leaf digests for slots `i < TreeSlots` (`EMPTY` or `L(P,C)` hash).
    #[pallet::storage]
    pub type MembershipLeafDigest<T: Config> =
        StorageMap<_, Twox64Concat, u64, [u8; 32], OptionQuery>;

    /// Whether slot `i` has been filled with `L(P,C)` (mature admission).
    #[pallet::storage]
    pub type Admitted<T: Config> = StorageMap<_, Twox64Concat, u64, (), OptionQuery>;

    /// Resume cursor for fill scans (PR-2). Walks round-robin over
    /// `0..TreeSlots` so mature leaves are found without a full prefix scan
    /// every block, while still allowing sparse admit (skip immature lower
    /// indices and come back later).
    #[pallet::storage]
    pub type AdmitScanCursor<T> = StorageValue<_, u64, ValueQuery>;

    /// Current membership Merkle root over sparse slots.
    #[pallet::storage]
    pub type MembershipRoot<T: Config> = StorageValue<_, [u8; 32], ValueQuery, EmptyMembershipRoot>;

    /// Historical roots by block number (wallet anchoring / reorg window).
    #[pallet::storage]
    pub type MembershipRootAt<T: Config> =
        StorageMap<_, Twox64Concat, BlockNumberFor<T>, [u8; 32], OptionQuery>;

    /// Default empty-tree root (Path A `EMPTY_MEMBERSHIP_ROOT`).
    pub struct EmptyMembershipRoot;
    impl Get<[u8; 32]> for EmptyMembershipRoot {
        fn get() -> [u8; 32] {
            membership::empty_membership_root()
        }
    }

    /// Snapshot of membership backfill / lag state (PR-2; tests + future RPC).
    #[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, TypeInfo, MaxEncodedLen)]
    pub struct MembershipBackfillStatus {
        pub tree_slots: u64,
        pub next_output_index: u64,
        /// `tree_slots < next_output_index` — catch-up grow still needed.
        pub lagging: bool,
        pub admit_scan_cursor: u64,
        pub membership_root: [u8; 32],
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A transfer was executed. Contains only already-public data —
        /// key images and output indices reveal nothing about sender,
        /// receiver or amounts.
        Transferred {
            key_images: Vec<[u8; 32]>,
            first_output_index: u64,
            output_count: u32,
            fee: u64,
        },
        /// The block author claimed the block reward plus accumulated fees.
        CoinbaseMinted {
            first_output_index: u64,
            output_count: u32,
            reward: u64,
            fees: u64,
        },
        /// Membership tree maintenance ran at end of block.
        MembershipTreeUpdated {
            tree_slots: u64,
            next_output_index: u64,
            root: [u8; 32],
            admitted_this_block: u32,
            catchup_grown: u32,
            /// Still lagging after this block's catch-up budget.
            lagging: bool,
            admit_scan_cursor: u64,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// A transfer must have at least one input and one output.
        EmptyInputsOrOutputs,
        /// Inputs must be strictly ordered by key image (canonical form,
        /// also rules out duplicate key images inside one tx).
        InputsNotSortedUnique,
        /// This key image has already been spent.
        KeyImageAlreadySpent,
        /// One-time key, tx pubkey, or key image is not a valid non-identity Ristretto point.
        InvalidPoint,
        /// FCMP+SA+L proof failed verification.
        FcmpInvalid,
        /// Membership root is outside the accepted window.
        RootStale,
        /// FCMP proof exceeds `MAX_FCMP_PROOF_BYTES`.
        FcmpProofTooLarge,
        /// Too many FCMP inputs (> `MAX_FCMP_INPUTS`).
        TooManyInputs,
        /// Tree too large for interim FCMP0001 (`MAX_FCMP_ANON_SET`).
        TreeTooLargeForFcmp,
        /// Σ C_pseudo != Σ C_out + fee·H (or a commitment failed to decode).
        BalanceCheckFailed,
        /// The aggregated range proof did not verify.
        RangeProofInvalid,
        /// Fee below the per-byte floor.
        FeeTooLow,
        /// Checked arithmetic overflow (fees / emission bookkeeping).
        ArithmeticOverflow,
        /// Only one coinbase per block.
        CoinbaseAlreadyIncluded,
        /// Coinbase outputs must be non-zero and sum to reward + fees.
        CoinbaseAmountInvalid,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(_n: BlockNumberFor<T>) -> Weight {
            CoinbaseDone::<T>::kill();
            T::DbWeight::get().writes(1)
        }

        /// Fill mature EMPTY→L leaves (budgeted), catch-up grow if lagging,
        /// recompute root, record `MembershipRootAt`.
        fn on_finalize(n: BlockNumberFor<T>) {
            let (admitted, grown) = Self::maintain_membership_tree();
            let root = MembershipRoot::<T>::get();
            MembershipRootAt::<T>::insert(n, root);
            // Prune roots outside the anchoring window.
            let max_age = BlockNumberFor::<T>::from(FCMP_ROOT_MAX_AGE_BLOCKS);
            if n > max_age {
                MembershipRootAt::<T>::remove(n - max_age);
            }
            let status = Self::membership_backfill_status();
            Self::deposit_event(Event::MembershipTreeUpdated {
                tree_slots: status.tree_slots,
                next_output_index: status.next_output_index,
                root: status.membership_root,
                admitted_this_block: admitted,
                catchup_grown: grown,
                lagging: status.lagging,
                admit_scan_cursor: status.admit_scan_cursor,
            });
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// The only user-facing operation: an FCMP confidential transfer.
        /// Self-authorizing via [`pallet::authorize`] — the FCMP proofs *are*
        /// the authorization. Requires `frame_system::AuthorizeCall`.
        #[pallet::call_index(0)]
        #[pallet::weight({
            let slots = TreeSlots::<T>::get().min(MAX_FCMP_ANON_SET as u64) as u32;
            let w = T::WeightInfo::transfer_fcmp(
                tx.inputs.len() as u32,
                tx.outputs.len() as u32,
                slots,
            );
            (w, DispatchClass::Normal, Pays::No)
        })]
        #[pallet::weight_of_authorize(T::WeightInfo::authorize_fcmp(tx.inputs.len() as u32))]
        #[pallet::authorize(|source, tx: &TransferTx| -> TransactionValidityWithRefund {
            let _ = source;
            Self::authorize_transfer(tx).map(|v| (v, Weight::zero()))
        })]
        pub fn transfer(origin: OriginFor<T>, tx: TransferTx) -> DispatchResult {
            ensure_authorized(origin)?;
            Self::verify_transfer(&tx)?;
            Self::apply_transfer(tx)
        }

        /// Inherent-only: the block author mints `block_reward + fees` as new
        /// outputs. Coinbase amounts are public (as in Monero) and enter the
        /// confidential domain on first spend.
        ///
        /// Bare inherent (not a general transaction) — uses `ensure_none`, not
        /// `#[pallet::authorize]`. Gossiped coinbase extrinsics are rejected
        /// by the node/inherent filter (`is_inherent`).
        #[pallet::call_index(1)]
        #[pallet::weight({
            let w = T::WeightInfo::coinbase(outputs.len() as u32);
            (w, DispatchClass::Mandatory, Pays::No)
        })]
        pub fn coinbase(
            origin: OriginFor<T>,
            outputs: BoundedVec<CoinbaseOutput, ConstU32<MAX_OUTPUTS>>,
            tx_pubkey: [u8; 32],
        ) -> DispatchResult {
            ensure_none(origin)?;
            ensure!(
                !CoinbaseDone::<T>::get(),
                Error::<T>::CoinbaseAlreadyIncluded
            );
            ensure!(!outputs.is_empty(), Error::<T>::EmptyInputsOrOutputs);
            ensure!(
                crypto_host::is_valid_point_v1(&tx_pubkey),
                Error::<T>::InvalidPoint
            );

            let reward = block_reward(Emitted::<T>::get());
            let fees = BlockFees::<T>::get();
            let entitled = reward
                .checked_add(fees)
                .ok_or(Error::<T>::CoinbaseAmountInvalid)?;

            let mut total: u64 = 0;
            for out in &outputs {
                ensure!(out.amount > 0, Error::<T>::CoinbaseAmountInvalid);
                ensure!(
                    crypto_host::is_valid_point_v1(&out.one_time_key),
                    Error::<T>::InvalidPoint
                );
                total = total
                    .checked_add(out.amount)
                    .ok_or(Error::<T>::CoinbaseAmountInvalid)?;
            }
            ensure!(total == entitled, Error::<T>::CoinbaseAmountInvalid);

            BlockFees::<T>::kill();
            Emitted::<T>::try_mutate(|e| -> DispatchResult {
                *e = e
                    .checked_add(reward)
                    .ok_or(Error::<T>::ArithmeticOverflow)?;
                Ok(())
            })?;
            CoinbaseDone::<T>::put(true);

            let height = frame_system::Pallet::<T>::block_number();
            let first = NextOutputIndex::<T>::get();
            let mut next = first;
            for out in &outputs {
                let commitment = crypto_host::value_commitment_v1(out.amount);
                Outputs::<T>::insert(
                    next,
                    StoredOutput {
                        one_time_key: out.one_time_key,
                        commitment,
                        tx_pubkey,
                        view_tag: out.view_tag,
                        payload: Default::default(),
                        amount: Some(out.amount),
                        height,
                        coinbase: true,
                    },
                );
                Self::maybe_grow_empty_on_create(next);
                next += 1;
            }
            NextOutputIndex::<T>::put(next);

            Self::deposit_event(Event::CoinbaseMinted {
                first_output_index: first,
                output_count: outputs.len() as u32,
                reward,
                fees,
            });
            Ok(())
        }
    }

    #[pallet::inherent]
    impl<T: Config> ProvideInherent for Pallet<T> {
        type Call = Call<T>;
        type Error = sp_inherents::MakeFatalError<()>;
        const INHERENT_IDENTIFIER: sp_inherents::InherentIdentifier = INHERENT_IDENTIFIER;

        fn create_inherent(data: &InherentData) -> Option<Self::Call> {
            // The miner supplies only its payout destination; the pallet
            // computes the entitled amount (reward + carried-over fees) from
            // chain state, so a miner can never over-claim via the inherent
            // data (and the `coinbase` dispatch re-checks it anyway).
            let (one_time_key, tx_pubkey, view_tag): CoinbaseInherent =
                data.get_data(&Self::INHERENT_IDENTIFIER).ok().flatten()?;
            let amount = block_reward(Emitted::<T>::get()).checked_add(BlockFees::<T>::get())?;
            if amount == 0 {
                return None;
            }
            let outputs = BoundedVec::try_from(alloc::vec![CoinbaseOutput {
                one_time_key,
                amount,
                view_tag,
            }])
            .ok()?;
            Some(Call::coinbase { outputs, tx_pubkey })
        }

        fn check_inherent(_call: &Self::Call, _data: &InherentData) -> Result<(), Self::Error> {
            // Amount/shape rules are enforced at dispatch; nothing extra here.
            Ok(())
        }

        fn is_inherent(call: &Self::Call) -> bool {
            matches!(call, Call::coinbase { .. })
        }
    }

    impl<T: Config> Pallet<T> {
        /// The message every FCMP input proves (see free [`signing_hash`]).
        pub fn signing_hash(tx: &TransferTx) -> [u8; 32] {
            super::signing_hash(tx)
        }

        /// Cheap pool-side checks for `#[pallet::authorize]` on `transfer`.
        /// Full FCMP / balance / range proof run at dispatch.
        pub fn authorize_transfer(
            tx: &TransferTx,
        ) -> Result<ValidTransaction, sp_runtime::transaction_validity::TransactionValidityError>
        {
            let encoded_len = tx.encoded_size() as u64;
            if tx.fee < T::MinFeePerByte::get().saturating_mul(encoded_len) {
                return Err(InvalidTransaction::Payment.into());
            }
            if tx.inputs.is_empty() || tx.outputs.is_empty() {
                return Err(InvalidTransaction::BadProof.into());
            }
            if tx.inputs.len() as u32 > MAX_FCMP_INPUTS {
                return Err(InvalidTransaction::BadProof.into());
            }
            for input in &tx.inputs {
                if input.fcmp_proof.len() as u32 > MAX_FCMP_PROOF_BYTES {
                    return Err(InvalidTransaction::BadProof.into());
                }
                if KeyImages::<T>::contains_key(input.key_image) {
                    return Err(InvalidTransaction::Stale.into());
                }
            }
            // Best-effort root window (full check at dispatch).
            if !Self::membership_root_accepted(&tx.membership_root) {
                return Err(InvalidTransaction::Stale.into());
            }
            Ok(ValidTransaction {
                priority: tx.fee / encoded_len.max(1),
                requires: Vec::new(),
                provides: tx
                    .inputs
                    .iter()
                    .map(|i| (b"kohl/ki", i.key_image).encode())
                    .collect(),
                longevity: FCMP_ROOT_MAX_AGE_BLOCKS as u64,
                propagate: true,
            })
        }

        /// Full consensus verification of an FCMP transfer.
        fn verify_transfer(tx: &TransferTx) -> DispatchResult {
            ensure!(
                !tx.inputs.is_empty() && !tx.outputs.is_empty(),
                Error::<T>::EmptyInputsOrOutputs
            );
            ensure!(
                (tx.inputs.len() as u32) <= MAX_FCMP_INPUTS,
                Error::<T>::TooManyInputs
            );
            ensure!(
                tx.inputs
                    .windows(2)
                    .all(|w| w[0].key_image < w[1].key_image),
                Error::<T>::InputsNotSortedUnique
            );
            ensure!(
                tx.fee >= T::MinFeePerByte::get().saturating_mul(tx.encoded_size() as u64),
                Error::<T>::FeeTooLow
            );
            ensure!(
                crypto_host::is_valid_point_v1(&tx.tx_pubkey),
                Error::<T>::InvalidPoint
            );
            for out in &tx.outputs {
                ensure!(
                    crypto_host::is_valid_point_v1(&out.one_time_key),
                    Error::<T>::InvalidPoint
                );
            }

            // Interim FCMP0001 cannot encode trees larger than the anon-set cap.
            let slots = TreeSlots::<T>::get();
            ensure!(
                slots <= MAX_FCMP_ANON_SET as u64,
                Error::<T>::TreeTooLargeForFcmp
            );

            ensure!(
                Self::membership_root_accepted(&tx.membership_root),
                Error::<T>::RootStale
            );

            let msg = Self::signing_hash(tx);
            let mut pseudo_commitments = Vec::with_capacity(tx.inputs.len() * 32);
            for input in &tx.inputs {
                ensure!(
                    (input.fcmp_proof.len() as u32) <= MAX_FCMP_PROOF_BYTES,
                    Error::<T>::FcmpProofTooLarge
                );
                ensure!(
                    !KeyImages::<T>::contains_key(input.key_image),
                    Error::<T>::KeyImageAlreadySpent
                );
                ensure!(
                    crypto_host::is_valid_point_v1(&input.key_image),
                    Error::<T>::InvalidPoint
                );
                ensure!(
                    crypto_host::is_valid_point_v1(&input.pseudo_commitment),
                    Error::<T>::InvalidPoint
                );
                ensure!(
                    crypto_host::verify_fcmp_v1(
                        &msg,
                        &tx.membership_root,
                        &input.pseudo_commitment,
                        &input.key_image,
                        &input.fcmp_proof,
                    ),
                    Error::<T>::FcmpInvalid
                );
                pseudo_commitments.extend_from_slice(&input.pseudo_commitment);
            }

            let mut output_commitments = Vec::with_capacity(tx.outputs.len() * 32);
            for out in &tx.outputs {
                output_commitments.extend_from_slice(&out.commitment);
            }
            ensure!(
                crypto_host::verify_balance_v1(&pseudo_commitments, &output_commitments, tx.fee),
                Error::<T>::BalanceCheckFailed
            );
            ensure!(
                crypto_host::verify_range_proof_v1(&tx.range_proof, &output_commitments),
                Error::<T>::RangeProofInvalid
            );
            Ok(())
        }

        /// True if `root` is the live membership root or appears in
        /// `MembershipRootAt` within the age window.
        pub(crate) fn membership_root_accepted(root: &[u8; 32]) -> bool {
            use sp_runtime::traits::{One, Saturating};
            if MembershipRoot::<T>::get() == *root {
                return true;
            }
            let tip = frame_system::Pallet::<T>::block_number();
            let max_age = BlockNumberFor::<T>::from(FCMP_ROOT_MAX_AGE_BLOCKS);
            let mut h = tip.saturating_sub(max_age);
            loop {
                if MembershipRootAt::<T>::get(h).as_ref() == Some(root) {
                    return true;
                }
                if h >= tip {
                    break;
                }
                h = h.saturating_add(One::one());
            }
            false
        }

        /// State changes — only reached after every check passed.
        fn apply_transfer(tx: TransferTx) -> DispatchResult {
            let key_images: Vec<[u8; 32]> = tx.inputs.iter().map(|i| i.key_image).collect();
            for ki in &key_images {
                KeyImages::<T>::insert(ki, ());
            }
            BlockFees::<T>::try_mutate(|f| -> DispatchResult {
                *f = f
                    .checked_add(tx.fee)
                    .ok_or(Error::<T>::ArithmeticOverflow)?;
                Ok(())
            })?;

            let height = frame_system::Pallet::<T>::block_number();
            let first = NextOutputIndex::<T>::get();
            let mut next = first;
            for out in &tx.outputs {
                Outputs::<T>::insert(
                    next,
                    StoredOutput {
                        one_time_key: out.one_time_key,
                        commitment: out.commitment,
                        tx_pubkey: tx.tx_pubkey,
                        view_tag: out.view_tag,
                        payload: out.payload.clone(),
                        amount: None,
                        height,
                        coinbase: false,
                    },
                );
                Self::maybe_grow_empty_on_create(next);
                next += 1;
            }
            NextOutputIndex::<T>::put(next);

            Self::deposit_event(Event::Transferred {
                key_images,
                first_output_index: first,
                output_count: tx.outputs.len() as u32,
                fee: tx.fee,
            });
            Ok(())
        }

        // ---- Membership tree (PR-1 / PR-2) ------------------------------

        /// Lag-aware grow: append EMPTY only when `index == TreeSlots`
        /// (steady state). While lagging (`TreeSlots < index`), no-op.
        pub(crate) fn maybe_grow_empty_on_create(index: u64) {
            if TreeSlots::<T>::get() != index {
                return;
            }
            Self::grow_empty_slot();
            // Keep root current mid-block for queries (finalize refreshes too).
            Self::refresh_membership_root();
        }

        fn grow_empty_slot() {
            let i = TreeSlots::<T>::get();
            // Only grow when the corresponding output already exists (lag
            // catch-up) or is being minted at this index (steady state).
            MembershipLeafDigest::<T>::insert(i, membership::empty_leaf_hash());
            TreeSlots::<T>::put(i + 1);
        }

        /// Fill mature slots EMPTY→L (cursor scan), then catch-up grow.
        /// Returns `(admitted_count, catchup_grown)`.
        ///
        /// Order is consensus-critical (D16): **fill first**, then grow, so
        /// high lag never starves mature admissions.
        pub(crate) fn maintain_membership_tree() -> (u32, u32) {
            let admitted = Self::admit_mature_leaves_budgeted();
            let grown = Self::catchup_grow_budgeted();
            Self::refresh_membership_root();
            (admitted, grown)
        }

        /// Round-robin fill from [`AdmitScanCursor`] up to
        /// `FCMP_ADMIT_MAX_LEAVES_PER_BLOCK`.
        fn admit_mature_leaves_budgeted() -> u32 {
            let now = frame_system::Pallet::<T>::block_number();
            let slots = TreeSlots::<T>::get();
            if slots == 0 {
                AdmitScanCursor::<T>::kill();
                return 0;
            }

            let mut admitted = 0u32;
            let mut i = AdmitScanCursor::<T>::get() % slots;
            // At most one full lap so immature slots are retried next block
            // without unbounded DB reads when everything is already admitted.
            let mut scanned = 0u64;

            while admitted < FCMP_ADMIT_MAX_LEAVES_PER_BLOCK && scanned < slots {
                if !Admitted::<T>::contains_key(i) {
                    if let Some(out) = Outputs::<T>::get(i) {
                        if Self::output_is_mature(&out, now) {
                            let digest = membership::leaf_hash(&out.one_time_key, &out.commitment);
                            MembershipLeafDigest::<T>::insert(i, digest);
                            Admitted::<T>::insert(i, ());
                            admitted += 1;
                        }
                    }
                }
                i = i.saturating_add(1);
                if i >= slots {
                    i = 0;
                }
                scanned += 1;
            }

            AdmitScanCursor::<T>::put(i);
            admitted
        }

        /// Sequential catch-up grow while `TreeSlots < NextOutputIndex`.
        /// Sole `TreeSlots` advancer in lag mode (D16).
        fn catchup_grow_budgeted() -> u32 {
            let mut grown = 0u32;
            let next_out = NextOutputIndex::<T>::get();
            while grown < FCMP_GROW_CATCHUP_MAX_PER_BLOCK {
                let slots_now = TreeSlots::<T>::get();
                if slots_now >= next_out {
                    break;
                }
                // Output must already exist (minted earlier without tree grow).
                debug_assert!(
                    Outputs::<T>::contains_key(slots_now),
                    "catch-up grow requires Outputs[TreeSlots]"
                );
                Self::grow_empty_slot();
                grown += 1;
            }
            grown
        }

        pub(crate) fn refresh_membership_root() {
            let n = TreeSlots::<T>::get();
            let mut leaves = Vec::with_capacity(n as usize);
            for i in 0..n {
                let d =
                    MembershipLeafDigest::<T>::get(i).unwrap_or_else(membership::empty_leaf_hash);
                leaves.push(d);
            }
            MembershipRoot::<T>::put(membership::root_from_leaves(&leaves));
        }

        fn output_is_mature(out: &StoredOutput<BlockNumberFor<T>>, now: BlockNumberFor<T>) -> bool {
            let age = if out.coinbase {
                T::CoinbaseMaturity::get()
            } else {
                T::SpendableAge::get()
            };
            now >= out.height + age
        }

        /// `TreeSlots < NextOutputIndex` — historical / reorg lag.
        pub fn is_membership_lagging() -> bool {
            TreeSlots::<T>::get() < NextOutputIndex::<T>::get()
        }

        /// Slots have caught the output tip (steady state for grow-on-create).
        pub fn is_membership_slot_caught_up() -> bool {
            !Self::is_membership_lagging()
        }

        /// Snapshot for operators / runtime API (PR-3).
        pub fn membership_backfill_status() -> MembershipBackfillStatus {
            MembershipBackfillStatus {
                tree_slots: TreeSlots::<T>::get(),
                next_output_index: NextOutputIndex::<T>::get(),
                lagging: Self::is_membership_lagging(),
                admit_scan_cursor: AdmitScanCursor::<T>::get(),
                membership_root: MembershipRoot::<T>::get(),
            }
        }

        /// Public helpers for tests / runtime API / RPC.
        pub fn membership_root() -> [u8; 32] {
            MembershipRoot::<T>::get()
        }

        pub fn membership_root_at(at: BlockNumberFor<T>) -> Option<[u8; 32]> {
            MembershipRootAt::<T>::get(at)
        }

        pub fn tree_slots() -> u64 {
            TreeSlots::<T>::get()
        }

        pub fn admit_scan_cursor() -> u64 {
            AdmitScanCursor::<T>::get()
        }

        pub fn is_admitted(index: u64) -> bool {
            Admitted::<T>::contains_key(index)
        }

        pub fn membership_leaf_digest(index: u64) -> Option<[u8; 32]> {
            MembershipLeafDigest::<T>::get(index)
        }

        /// SCALE-encoded `Vec<[u8; 32]>` of leaf digests for `0..TreeSlots`.
        ///
        /// v1 full dump for provers (O(n)); replace with peak/frontier codec
        /// when tree size warrants it.
        pub fn membership_frontier() -> Vec<u8> {
            use codec::Encode;
            let n = TreeSlots::<T>::get();
            let mut leaves = Vec::with_capacity(n as usize);
            for i in 0..n {
                leaves.push(
                    MembershipLeafDigest::<T>::get(i).unwrap_or_else(membership::empty_leaf_hash),
                );
            }
            leaves.encode()
        }

        /// Spend-path mode: always [`FCMP_MODE_FCMP_ONLY`] after PR-7.
        pub fn fcmp_mode() -> u8 {
            FCMP_MODE_FCMP_ONLY
        }
    }
}
