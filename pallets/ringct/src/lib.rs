//! # pallet-ringct — the kohl monetary system
//!
//! **Phase 2 (current): confidential amounts.** Outputs carry Pedersen
//! commitments instead of plaintext amounts; every transfer proves the
//! balance equation `Σ C_in == Σ C_out + fee·B` and carries one aggregated
//! Bulletproof showing every output amount lies in [0, 2^64). The fee is the
//! single public amount (Monero-style). Ownership is still a plain sr25519
//! signature per input; Phase 3 replaces it with CLSAG rings + key images
//! and adds stealth addresses (see BLUEPRINT.md §6).
//!
//! Heavy verification runs natively through the versioned host functions in
//! `ringct-crypto` (BLUEPRINT.md §1.6); the runtime never executes curve
//! arithmetic in WASM.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::{pallet_prelude::*, BoundedVec};
use frame_system::pallet_prelude::*;
use ringct_primitives::{
    block_reward, MAX_INPUTS, MAX_OUTPUTS, MAX_PAYLOAD_BYTES, MAX_RANGE_PROOF_BYTES,
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
pub const SIGNING_DOMAIN: [u8; 16] = *b"kohl/transfer/v2";

/// Inherent identifier for the coinbase call.
pub const INHERENT_IDENTIFIER: sp_inherents::InherentIdentifier = *b"ringct0b";

/// Opaque per-output wallet payload (encrypted amount + blinding for the
/// receiver; format finalized with stealth-address ECDH in Phase 3).
pub type Payload = BoundedVec<u8, ConstU32<MAX_PAYLOAD_BYTES>>;

/// A newly created confidential output as it appears inside a transaction.
#[derive(
    Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct Output {
    /// sr25519 public key allowed to spend this output.
    /// (Phase 3: becomes a one-time stealth key.)
    pub owner: [u8; 32],
    /// Pedersen commitment to the amount (compressed Ristretto point).
    pub commitment: [u8; 32],
    /// Opaque payload for the receiver's wallet.
    pub payload: Payload,
}

/// A coinbase output: amount is public (as in Monero); the chain derives its
/// commitment as `amount·B` (zero blinding), so it participates in later
/// confidential balance equations like any other output.
#[derive(
    Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct CoinbaseOutput {
    pub owner: [u8; 32],
    pub amount: u64,
}

/// A stored output: the on-chain record plus consensus bookkeeping.
#[derive(
    Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct StoredOutput<BlockNumber> {
    pub owner: [u8; 32],
    pub commitment: [u8; 32],
    /// Public amount — `Some` only for coinbase outputs.
    pub amount: Option<u64>,
    /// Block in which the output was created (maturity rules).
    pub height: BlockNumber,
    /// Coinbase outputs have a longer maturity (`CoinbaseMaturity`).
    pub coinbase: bool,
}

/// One spend inside a transfer.
///
/// Phase 2: a direct reference to the spent output plus the owner's
/// signature. Phase 3 replaces this with a ring of decoy indices, a key
/// image, a pseudo-output commitment and a CLSAG.
#[derive(
    Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct Input {
    /// Global index of the output being spent.
    pub index: u64,
    /// sr25519 signature by the output's owner over [`Pallet::signing_hash`].
    pub signature: [u8; 64],
}

/// A complete confidential transfer, submitted as an *unsigned* extrinsic:
/// like a Monero transaction it is self-authenticating — the input
/// signatures are the authorization; there is no account or nonce.
#[derive(
    Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct TransferTx {
    pub inputs: BoundedVec<Input, ConstU32<MAX_INPUTS>>,
    pub outputs: BoundedVec<Output, ConstU32<MAX_OUTPUTS>>,
    /// One aggregated Bulletproof covering all output commitments.
    /// Not signed: it is already cryptographically bound to the commitments.
    pub range_proof: BoundedVec<u8, ConstU32<MAX_RANGE_PROOF_BYTES>>,
    /// The one public amount. Consensus: Σ C_in == Σ C_out + fee·B.
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

        /// Blocks before a regular output may be spent (reorg safety; also a
        /// decoy-quality rule once rings land).
        #[pallet::constant]
        type SpendableAge: Get<BlockNumberFor<Self>>;

        /// Blocks before a coinbase output may be spent.
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

    /// Phase-2 nullifier set: spent global output indices. Never pruned.
    /// (Phase 3 replaces this with the key-image set.)
    #[pallet::storage]
    pub type SpentOutputs<T> = StorageMap<_, Twox64Concat, u64, (), OptionQuery>;

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
        /// A transfer was executed. Contains only already-public data.
        Transferred {
            spent: Vec<u64>,
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
        /// Input indices must be strictly increasing (sorted, no duplicates).
        InputsNotSortedUnique,
        /// Referenced output does not exist.
        UnknownOutput,
        /// Referenced output was already spent.
        OutputAlreadySpent,
        /// Referenced output has not reached spendable age / maturity.
        OutputImmature,
        /// An input signature does not verify against the output's owner.
        BadSignature,
        /// Σ C_in != Σ C_out + fee·B (or a commitment failed to decode).
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
        /// The only user-facing operation on this chain: a confidential
        /// transfer. Unsigned — authorization is carried inside `tx` itself.
        #[pallet::call_index(0)]
        #[pallet::weight((
            // Placeholder until Phase 4 benchmarking; dominated by the
            // native Bulletproof + balance verification.
            Weight::from_parts(500_000_000, 0)
                .saturating_add(T::DbWeight::get().reads_writes(
                    2 * tx.inputs.len() as u64,
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
                        owner: out.owner,
                        commitment: crypto_host::value_commitment_v1(out.amount),
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

        fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            let Call::transfer { tx } = call else {
                // `coinbase` is inherent-only: never valid from the pool.
                return InvalidTransaction::Call.into();
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
                if SpentOutputs::<T>::contains_key(input.index) {
                    return InvalidTransaction::Stale.into();
                }
                if !Outputs::<T>::contains_key(input.index) {
                    return InvalidTransaction::Future.into();
                }
            }

            Ok(ValidTransaction {
                priority: tx.fee / encoded_len.max(1),
                requires: Vec::new(),
                // One tag per spent output: the pool auto-rejects conflicting
                // spends and keeps the higher-priority tx.
                provides: tx.inputs.iter().map(|i| (b"kohl/out", i.index).encode()).collect(),
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
            let outputs: Vec<CoinbaseOutput> =
                data.get_data(&Self::INHERENT_IDENTIFIER).ok().flatten()?;
            let outputs = BoundedVec::try_from(outputs).ok()?;
            Some(Call::coinbase { outputs })
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
        /// The message every input owner signs: a hash binding the exact
        /// input set, all outputs (keys, commitments, payloads) and the fee.
        /// The range proof is deliberately excluded — it is already bound to
        /// the commitments by its transcript.
        pub fn signing_hash(indices: &[u64], outputs: &[Output], fee: u64) -> [u8; 32] {
            sp_io::hashing::blake2_256(&(SIGNING_DOMAIN, indices, outputs, fee).encode())
        }

        /// Full consensus verification of a transfer (BLUEPRINT.md §3.4).
        fn verify_transfer(tx: &TransferTx) -> DispatchResult {
            ensure!(
                !tx.inputs.is_empty() && !tx.outputs.is_empty(),
                Error::<T>::EmptyInputsOrOutputs
            );
            ensure!(
                tx.inputs.windows(2).all(|w| w[0].index < w[1].index),
                Error::<T>::InputsNotSortedUnique
            );
            ensure!(
                tx.fee >= T::MinFeePerByte::get().saturating_mul(tx.encoded_size() as u64),
                Error::<T>::FeeTooLow
            );

            let now = frame_system::Pallet::<T>::block_number();
            let indices: Vec<u64> = tx.inputs.iter().map(|i| i.index).collect();
            let msg = Self::signing_hash(&indices, &tx.outputs, tx.fee);

            let mut input_commitments = Vec::with_capacity(tx.inputs.len() * 32);
            for input in &tx.inputs {
                ensure!(
                    !SpentOutputs::<T>::contains_key(input.index),
                    Error::<T>::OutputAlreadySpent
                );
                let stored = Outputs::<T>::get(input.index).ok_or(Error::<T>::UnknownOutput)?;

                let age = if stored.coinbase {
                    T::CoinbaseMaturity::get()
                } else {
                    T::SpendableAge::get()
                };
                ensure!(now >= stored.height + age, Error::<T>::OutputImmature);

                let sig = sp_core::sr25519::Signature::from_raw(input.signature);
                let owner = sp_core::sr25519::Public::from_raw(stored.owner);
                ensure!(
                    sp_io::crypto::sr25519_verify(&sig, &msg, &owner),
                    Error::<T>::BadSignature
                );

                input_commitments.extend_from_slice(&stored.commitment);
            }

            let mut output_commitments = Vec::with_capacity(tx.outputs.len() * 32);
            for out in &tx.outputs {
                output_commitments.extend_from_slice(&out.commitment);
            }

            // Balance equation over commitments: Σ C_in == Σ C_out + fee·B.
            ensure!(
                crypto_host::verify_balance_v1(&input_commitments, &output_commitments, tx.fee),
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
            let spent: Vec<u64> = tx.inputs.iter().map(|i| i.index).collect();
            for index in &spent {
                SpentOutputs::<T>::insert(index, ());
            }
            BlockFees::<T>::mutate(|f| *f = f.saturating_add(tx.fee));

            let height = frame_system::Pallet::<T>::block_number();
            let first = NextOutputIndex::<T>::get();
            let mut next = first;
            for out in &tx.outputs {
                Outputs::<T>::insert(
                    next,
                    StoredOutput {
                        owner: out.owner,
                        commitment: out.commitment,
                        amount: None,
                        height,
                        coinbase: false,
                    },
                );
                next += 1;
            }
            NextOutputIndex::<T>::put(next);

            Self::deposit_event(Event::Transferred {
                spent,
                first_output_index: first,
                output_count: tx.outputs.len() as u32,
                fee: tx.fee,
            });
            Ok(())
        }
    }
}
