//! # pallet-ringct — the kohl monetary system
//!
//! **Phase 3 (current): full RingCT.** All three Monero privacy pillars are
//! active (BLUEPRINT.md §1.3):
//!
//! 1. **Sender anonymity** — every input is a ring of `T::RingSize` outputs
//!    (decoys + 1 real) proven by a CLSAG; the chain learns only the ring.
//! 2. **Receiver privacy** — outputs are one-time stealth keys with view
//!    tags; addresses never appear on chain (derivation is wallet-side, see
//!    `ringct_crypto::stealth`).
//! 3. **Amount confidentiality** — Pedersen commitments + one aggregated
//!    Bulletproof per tx; per-input *pseudo-output commitments* re-blind the
//!    real input amounts so the balance equation
//!    `Σ C_pseudo == Σ C_out + fee·H` verifies without linking ring members.
//!
//! Double spends are prevented by **key images** (`I = x·Hp(P)`): stored
//! forever, deterministic per output, revealing nothing about which ring
//! member was spent. Transfers are unsigned self-authenticating extrinsics;
//! the fee is the single public amount and goes to the block author via the
//! coinbase inherent. Heavy verification (CLSAG, Bulletproofs, balance) runs
//! natively through versioned host functions (BLUEPRINT.md §1.6).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::{pallet_prelude::*, BoundedVec};
use frame_system::pallet_prelude::*;
use ringct_primitives::{
    block_reward, CLSAG_MAX_BYTES, MAX_INPUTS, MAX_OUTPUTS, MAX_PAYLOAD_BYTES,
    MAX_RANGE_PROOF_BYTES, MAX_RING_SIZE,
};
use scale_info::TypeInfo;
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionSource, TransactionValidity, ValidTransaction,
};

pub use pallet::*;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

/// Domain-separation prefix for the transfer signing hash. Versioned:
/// changing tx semantics MUST change this string (consensus-critical).
pub const SIGNING_DOMAIN: [u8; 16] = *b"kohl/transfer/v3";

/// Inherent identifier for the coinbase call.
pub const INHERENT_IDENTIFIER: sp_inherents::InherentIdentifier = *b"ringct0b";

/// Opaque per-output wallet payload. Convention: the 8-byte masked amount
/// (`stealth::mask_amount`); the blinding is derived from the shared secret.
pub type Payload = BoundedVec<u8, ConstU32<MAX_PAYLOAD_BYTES>>;

/// Inherent data a mining node supplies for its coinbase: the payout
/// destination `(one_time_key, tx_pubkey)`. The reward amount is computed by
/// the runtime, not the miner (see `ProvideInherent::create_inherent`).
pub type CoinbaseInherent = ([u8; 32], [u8; 32]);

/// The message every CLSAG in a transfer signs: a hash binding the rings,
/// key images, pseudo-commitments, all outputs, the tx pubkey and the fee —
/// everything except the signatures themselves (and the range proof, which
/// its own transcript binds to the commitments).
///
/// A free function (not a pallet method) so wallets can build and sign
/// transactions without a runtime.
pub fn signing_hash(tx: &TransferTx) -> [u8; 32] {
    let rings: Vec<&BoundedVec<u64, ConstU32<MAX_RING_SIZE>>> =
        tx.inputs.iter().map(|i| &i.ring).collect();
    let key_images: Vec<[u8; 32]> = tx.inputs.iter().map(|i| i.key_image).collect();
    let pseudos: Vec<[u8; 32]> = tx.inputs.iter().map(|i| i.pseudo_commitment).collect();
    sp_io::hashing::blake2_256(
        &(SIGNING_DOMAIN, rings, key_images, pseudos, &tx.outputs, tx.tx_pubkey, tx.fee).encode(),
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

/// One ring spend inside a transfer.
#[derive(
    Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct RingInput {
    /// Global output indices of the ring members (strictly increasing;
    /// exactly `T::RingSize` of them — one is the real spend, the chain
    /// cannot tell which).
    pub ring: BoundedVec<u64, ConstU32<MAX_RING_SIZE>>,
    /// Key image `I = x·Hp(P)` — the permanent nullifier.
    pub key_image: [u8; 32],
    /// Pseudo-output commitment `C'`: same amount as the real input under a
    /// fresh blinding; feeds the tx balance equation.
    pub pseudo_commitment: [u8; 32],
    /// CLSAG signature: `c0 ‖ s_0..s_{n−1} ‖ D`.
    pub clsag: BoundedVec<u8, ConstU32<CLSAG_MAX_BYTES>>,
}

/// A complete RingCT transfer, submitted as an *unsigned* extrinsic: like a
/// Monero transaction it is self-authenticating — the CLSAGs are the
/// authorization; there is no account, no signer, no nonce.
#[derive(
    Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct TransferTx {
    pub inputs: BoundedVec<RingInput, ConstU32<MAX_INPUTS>>,
    pub outputs: BoundedVec<Output, ConstU32<MAX_OUTPUTS>>,
    /// Per-tx pubkey `R = r·G` for stealth derivation.
    pub tx_pubkey: [u8; 32],
    /// One aggregated Bulletproof covering all output commitments.
    /// Not part of the signed message: it is already bound to the
    /// commitments by its transcript.
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

        /// Exact required ring size (production: 16). Must be ≤ MAX_RING_SIZE.
        #[pallet::constant]
        type RingSize: Get<u32>;

        /// Blocks before an output may be spent *or used as a decoy*
        /// (reorg safety + ring quality).
        #[pallet::constant]
        type SpendableAge: Get<BlockNumberFor<Self>>;

        /// Blocks before a coinbase output may be spent or used as a decoy.
        #[pallet::constant]
        type CoinbaseMaturity: Get<BlockNumberFor<Self>>;

        /// Spam floor: required fee per encoded byte of the transfer.
        #[pallet::constant]
        type MinFeePerByte: Get<u64>;
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
    }

    #[pallet::error]
    pub enum Error<T> {
        /// A transfer must have at least one input and one output.
        EmptyInputsOrOutputs,
        /// Inputs must be strictly ordered by key image (canonical form,
        /// also rules out duplicate key images inside one tx).
        InputsNotSortedUnique,
        /// A ring does not have exactly `T::RingSize` members.
        RingSizeInvalid,
        /// Ring indices must be strictly increasing (sorted, no duplicates).
        RingIndicesInvalid,
        /// A ring member does not exist.
        UnknownOutput,
        /// A ring member has not reached spendable age / maturity.
        OutputImmature,
        /// This key image has already been spent.
        KeyImageAlreadySpent,
        /// The CLSAG did not verify.
        ClsagInvalid,
        /// Σ C_pseudo != Σ C_out + fee·H (or a commitment failed to decode).
        BalanceCheckFailed,
        /// The aggregated range proof did not verify.
        RangeProofInvalid,
        /// Fee below the per-byte floor.
        FeeTooLow,
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
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// The only user-facing operation on this chain: a RingCT transfer.
        /// Unsigned — authorization is carried inside `tx` itself.
        #[pallet::call_index(0)]
        #[pallet::weight((
            // Placeholder until Phase 4 benchmarking; dominated by native
            // CLSAG (≈ 2·ring_size scalar mults per input) + Bulletproof.
            Weight::from_parts(
                500_000_000_u64.saturating_add(300_000_000 * tx.inputs.len() as u64),
                0,
            )
            .saturating_add(T::DbWeight::get().reads_writes(
                (T::RingSize::get() as u64 + 1) * tx.inputs.len() as u64,
                tx.inputs.len() as u64 + tx.outputs.len() as u64 + 2,
            )),
            DispatchClass::Normal,
            Pays::No,
        ))]
        pub fn transfer(origin: OriginFor<T>, tx: TransferTx) -> DispatchResult {
            ensure_none(origin)?;
            Self::verify_transfer(&tx)?;
            Self::apply_transfer(tx)
        }

        /// Inherent-only: the block author mints `block_reward + fees` as new
        /// outputs. Coinbase amounts are public (as in Monero) and enter the
        /// confidential domain on first spend.
        #[pallet::call_index(1)]
        #[pallet::weight((
            Weight::from_parts(50_000_000, 0)
                .saturating_add(T::DbWeight::get().reads_writes(3, outputs.len() as u64 + 4)),
            DispatchClass::Mandatory,
            Pays::No,
        ))]
        pub fn coinbase(
            origin: OriginFor<T>,
            outputs: BoundedVec<CoinbaseOutput, ConstU32<MAX_OUTPUTS>>,
            tx_pubkey: [u8; 32],
        ) -> DispatchResult {
            ensure_none(origin)?;
            ensure!(!CoinbaseDone::<T>::get(), Error::<T>::CoinbaseAlreadyIncluded);
            ensure!(!outputs.is_empty(), Error::<T>::EmptyInputsOrOutputs);

            let reward = block_reward(Emitted::<T>::get());
            let fees = BlockFees::<T>::get();
            let entitled = reward.checked_add(fees).ok_or(Error::<T>::CoinbaseAmountInvalid)?;

            let mut total: u64 = 0;
            for out in &outputs {
                ensure!(out.amount > 0, Error::<T>::CoinbaseAmountInvalid);
                total = total.checked_add(out.amount).ok_or(Error::<T>::CoinbaseAmountInvalid)?;
            }
            ensure!(total == entitled, Error::<T>::CoinbaseAmountInvalid);

            BlockFees::<T>::kill();
            Emitted::<T>::mutate(|e| *e = e.saturating_add(reward));
            CoinbaseDone::<T>::put(true);

            let height = frame_system::Pallet::<T>::block_number();
            let first = NextOutputIndex::<T>::get();
            let mut next = first;
            for out in &outputs {
                Outputs::<T>::insert(
                    next,
                    StoredOutput {
                        one_time_key: out.one_time_key,
                        commitment: crypto_host::value_commitment_v1(out.amount),
                        tx_pubkey,
                        view_tag: 0,
                        payload: Default::default(),
                        amount: Some(out.amount),
                        height,
                        coinbase: true,
                    },
                );
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

    // TODO(Phase 4): migrate to `#[pallet::authorize]` + `frame_system::AuthorizeCall`
    // (ValidateUnsigned is deprecated in stable2606, removal after April 2027;
    // see https://github.com/paritytech/polkadot-sdk/issues/2415).
    #[allow(deprecated)]
    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;

        fn validate_unsigned(source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            let tx = match call {
                Call::transfer { tx } => tx,
                // The coinbase is a bare inherent: the executive validates it
                // through this path (`pre_dispatch` → source `InBlock`) when
                // applying the block. Accept it there, but never from the
                // gossip pool — and only once per block. Its amount is still
                // checked by the dispatch logic.
                Call::coinbase { .. } if matches!(source, TransactionSource::InBlock) => {
                    return ValidTransaction::with_tag_prefix("RingCtCoinbase")
                        .and_provides([b"kohl/coinbase".as_slice()].concat())
                        .longevity(1)
                        .propagate(false)
                        .build();
                }
                _ => return InvalidTransaction::Call.into(),
            };

            // Cheap pre-validation only; full verification happens at dispatch.
            let encoded_len = tx.encoded_size() as u64;
            if tx.fee < T::MinFeePerByte::get().saturating_mul(encoded_len) {
                return InvalidTransaction::Payment.into();
            }
            if tx.inputs.is_empty() || tx.outputs.is_empty() {
                return InvalidTransaction::BadProof.into();
            }
            for input in &tx.inputs {
                if KeyImages::<T>::contains_key(input.key_image) {
                    return InvalidTransaction::Stale.into();
                }
            }

            Ok(ValidTransaction {
                priority: tx.fee / encoded_len.max(1),
                requires: Vec::new(),
                // One tag per key image: the pool auto-rejects conflicting
                // spends of the same output and keeps the higher-priority tx.
                provides: tx
                    .inputs
                    .iter()
                    .map(|i| (b"kohl/ki", i.key_image).encode())
                    .collect(),
                longevity: 64,
                propagate: true,
            })
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
            let (one_time_key, tx_pubkey): CoinbaseInherent =
                data.get_data(&Self::INHERENT_IDENTIFIER).ok().flatten()?;
            let amount =
                block_reward(Emitted::<T>::get()).checked_add(BlockFees::<T>::get())?;
            if amount == 0 {
                return None;
            }
            let outputs =
                BoundedVec::try_from(alloc::vec![CoinbaseOutput { one_time_key, amount }]).ok()?;
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
        /// The message every CLSAG signs (see the free [`signing_hash`]).
        pub fn signing_hash(tx: &TransferTx) -> [u8; 32] {
            super::signing_hash(tx)
        }

        /// Full consensus verification of a transfer (BLUEPRINT.md §3.4).
        fn verify_transfer(tx: &TransferTx) -> DispatchResult {
            ensure!(
                !tx.inputs.is_empty() && !tx.outputs.is_empty(),
                Error::<T>::EmptyInputsOrOutputs
            );
            // Canonical input order by key image ⇒ no in-tx duplicates.
            ensure!(
                tx.inputs.windows(2).all(|w| w[0].key_image < w[1].key_image),
                Error::<T>::InputsNotSortedUnique
            );
            ensure!(
                tx.fee >= T::MinFeePerByte::get().saturating_mul(tx.encoded_size() as u64),
                Error::<T>::FeeTooLow
            );

            let now = frame_system::Pallet::<T>::block_number();
            let ring_size = T::RingSize::get() as usize;
            let msg = Self::signing_hash(tx);

            let mut pseudo_commitments = Vec::with_capacity(tx.inputs.len() * 32);
            for input in &tx.inputs {
                ensure!(input.ring.len() == ring_size, Error::<T>::RingSizeInvalid);
                ensure!(
                    input.ring.windows(2).all(|w| w[0] < w[1]),
                    Error::<T>::RingIndicesInvalid
                );
                ensure!(
                    !KeyImages::<T>::contains_key(input.key_image),
                    Error::<T>::KeyImageAlreadySpent
                );

                // Assemble the ring blob; every member (decoys included)
                // must exist and be mature — a ring is only as private as
                // its weakest member.
                let mut ring_blob = Vec::with_capacity(ring_size * 64);
                for index in &input.ring {
                    let member = Outputs::<T>::get(index).ok_or(Error::<T>::UnknownOutput)?;
                    let age = if member.coinbase {
                        T::CoinbaseMaturity::get()
                    } else {
                        T::SpendableAge::get()
                    };
                    ensure!(now >= member.height + age, Error::<T>::OutputImmature);
                    ring_blob.extend_from_slice(&member.one_time_key);
                    ring_blob.extend_from_slice(&member.commitment);
                }

                ensure!(
                    crypto_host::verify_clsag_v1(
                        &msg,
                        &ring_blob,
                        &input.pseudo_commitment,
                        &input.key_image,
                        &input.clsag,
                    ),
                    Error::<T>::ClsagInvalid
                );
                pseudo_commitments.extend_from_slice(&input.pseudo_commitment);
            }

            let mut output_commitments = Vec::with_capacity(tx.outputs.len() * 32);
            for out in &tx.outputs {
                output_commitments.extend_from_slice(&out.commitment);
            }

            // Balance equation: Σ C_pseudo == Σ C_out + fee·H.
            ensure!(
                crypto_host::verify_balance_v1(&pseudo_commitments, &output_commitments, tx.fee),
                Error::<T>::BalanceCheckFailed
            );
            // Every output amount ∈ [0, 2^64): no negative-amount minting.
            ensure!(
                crypto_host::verify_range_proof_v1(&tx.range_proof, &output_commitments),
                Error::<T>::RangeProofInvalid
            );
            Ok(())
        }

        /// State changes — only reached after every check passed.
        fn apply_transfer(tx: TransferTx) -> DispatchResult {
            let key_images: Vec<[u8; 32]> = tx.inputs.iter().map(|i| i.key_image).collect();
            for ki in &key_images {
                KeyImages::<T>::insert(ki, ());
            }
            BlockFees::<T>::mutate(|f| *f = f.saturating_add(tx.fee));

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
    }
}
