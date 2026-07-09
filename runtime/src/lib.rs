//! The kohl runtime — a pure private-cash L1.
//!
//! Deliberately tiny: `frame-system`, `pallet-timestamp`, `pallet-difficulty`
//! (LWMA PoW difficulty) and `pallet-ringct` (the entire monetary system).
//! No balances, no transaction-payment, no contracts, no governance — value
//! moves only through confidential RingCT transfers and fees are internal to
//! the pallet (BLUEPRINT.md §4). Consensus is RandomX PoW, so there is no
//! Aura/GRANDPA authority set and no session keys.

#![cfg_attr(not(feature = "std"), no_std)]

// Injected by the wasm builder; `None` when SKIP_WASM_BUILD is set.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

#[cfg(feature = "runtime-benchmarks")]
mod benchmarks;

extern crate alloc;
use alloc::{vec, vec::Vec};

use frame_support::{
    derive_impl,
    dispatch::DispatchClass,
    genesis_builder_helper::{build_state, get_preset},
    parameter_types,
    traits::{ConstU32, ConstU64, Get},
    weights::{
        constants::{RocksDbWeight, WEIGHT_REF_TIME_PER_SECOND},
        Weight,
    },
};
use frame_system::limits::{BlockLength, BlockWeights};
use pallet_ringct::StoredOutput;
use sp_core::{crypto::KeyTypeId, OpaqueMetadata, U256};
use sp_runtime::{
    generic, impl_opaque_keys,
    traits::{BlakeTwo256, Block as BlockT, IdentifyAccount, Verify},
    transaction_validity::{TransactionSource, TransactionValidity},
    ApplyExtrinsicResult, MultiAddress, MultiSignature, Perbill,
};
#[cfg(feature = "std")]
use sp_version::NativeVersion;
use sp_version::RuntimeVersion;

/// An index to a block.
pub type BlockNumber = u32;
/// Signature type (present only to satisfy the extrinsic format; the chain
/// has no signed user transactions).
pub type Signature = MultiSignature;
/// Account identifier (kept for `frame-system` bookkeeping; the chain has no
/// account balances — value lives in the confidential output set).
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;
/// Address format for the extrinsic type.
pub type Address = MultiAddress<AccountId, ()>;
/// Transaction index within an account.
pub type Nonce = u32;
/// Block hash type.
pub type Hash = sp_core::H256;

/// Opaque types for the outer node, agnostic to runtime specifics.
pub mod opaque {
    use super::*;
    pub use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;
    pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
    pub type Block = generic::Block<Header, UncheckedExtrinsic>;
}

impl_opaque_keys! {
    pub struct SessionKeys {}
}

#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: alloc::borrow::Cow::Borrowed("kohl"),
    impl_name: alloc::borrow::Cow::Borrowed("kohl"),
    authoring_version: 1,
    spec_version: 1,
    impl_version: 1,
    apis: RUNTIME_API_VERSIONS,
    transaction_version: 1,
    system_version: 1,
};

#[cfg(feature = "std")]
pub fn native_version() -> NativeVersion {
    NativeVersion {
        runtime_version: VERSION,
        can_author_with: Default::default(),
    }
}

pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
pub type Block = generic::Block<Header, UncheckedExtrinsic>;

/// Transaction extension pipeline.
///
/// RingCT transfers are **general** (unsigned) extrinsics authorized by
/// `#[pallet::authorize]` via [`frame_system::AuthorizeCall`] — the CLSAG is
/// the proof of authority. Coinbase is a bare inherent (`ensure_none`), not
/// a general transaction. There is no fee-charging extension: fees live
/// inside the RingCT balance equation.
pub type TxExtension = (
    frame_system::AuthorizeCall<Runtime>,
    frame_system::CheckNonZeroSender<Runtime>,
    frame_system::CheckSpecVersion<Runtime>,
    frame_system::CheckTxVersion<Runtime>,
    frame_system::CheckGenesis<Runtime>,
    frame_system::CheckEra<Runtime>,
    frame_system::CheckNonce<Runtime>,
    frame_system::CheckWeight<Runtime>,
);

pub type UncheckedExtrinsic =
    generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, TxExtension>;

pub type Executive = frame_executive::Executive<
    Runtime,
    Block,
    frame_system::ChainContext<Runtime>,
    Runtime,
    AllPalletsWithSystem,
>;

const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);

parameter_types! {
    pub const Version: RuntimeVersion = VERSION;
    pub RuntimeBlockWeights: BlockWeights = BlockWeights::with_sensible_defaults(
        Weight::from_parts(2u64 * WEIGHT_REF_TIME_PER_SECOND, u64::MAX),
        NORMAL_DISPATCH_RATIO,
    );
    // Generous block length: RingCT transfers with 16-member rings + a
    // Bulletproof are a few KiB each; keep the base cap conservative.
    pub RuntimeBlockLength: BlockLength = BlockLength::builder()
        .max_length(300 * 1024)
        .modify_max_length_for_class(DispatchClass::Normal, |m| *m = NORMAL_DISPATCH_RATIO * *m)
        .build();
    /// LWMA floor difficulty (see pallet-difficulty).
    pub const MinDifficulty: u128 = 10_000;
}

#[frame_support::runtime]
mod runtime {
    #[runtime::runtime]
    #[runtime::derive(
        RuntimeCall,
        RuntimeEvent,
        RuntimeError,
        RuntimeOrigin,
        RuntimeTask,
        RuntimeViewFunction
    )]
    pub struct Runtime;

    #[runtime::pallet_index(0)]
    pub type System = frame_system;

    #[runtime::pallet_index(1)]
    pub type Timestamp = pallet_timestamp;

    #[runtime::pallet_index(2)]
    pub type Difficulty = pallet_difficulty;

    #[runtime::pallet_index(3)]
    pub type RingCt = pallet_ringct;
}

#[derive_impl(frame_system::config_preludes::SolochainDefaultConfig)]
impl frame_system::Config for Runtime {
    type Block = Block;
    type BlockWeights = RuntimeBlockWeights;
    type BlockLength = RuntimeBlockLength;
    type AccountId = AccountId;
    type Nonce = Nonce;
    type Hash = Hash;
    type DbWeight = RocksDbWeight;
    type Version = Version;
    /// No balances: accounts carry no data.
    type AccountData = ();
    type MaxConsumers = ConstU32<16>;
}

impl pallet_timestamp::Config for Runtime {
    type Moment = u64;
    type OnTimestampSet = ();
    /// PoW has no slots; only enforce a small monotonic minimum.
    type MinimumPeriod = ConstU64<3_000>;
    type WeightInfo = ();
}

impl pallet_difficulty::Config for Runtime {
    type TargetBlockTime = ConstU64<{ ringct_primitives::TARGET_BLOCK_TIME_MS }>;
    type BlockWindow = ConstU32<90>;
    type MinDifficulty = MinDifficulty;
}

impl pallet_ringct::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RingSize = ConstU32<16>;
    type SpendableAge = ConstU32<10>;
    type CoinbaseMaturity = ConstU32<60>;
    type MinFeePerByte = ConstU64<1_000>;
    type WeightInfo = pallet_ringct::weights::SubstrateWeight<Runtime>;
}

// ---- Genesis presets ----------------------------------------------------

/// Fair launch: zero supply, only the initial PoW difficulty is set.
fn kohl_genesis(initial_difficulty: u128) -> serde_json::Value {
    let config = RuntimeGenesisConfig {
        difficulty: DifficultyConfig {
            initial_difficulty,
            _marker: core::marker::PhantomData,
        },
        ..Default::default()
    };
    serde_json::to_value(config).expect("genesis config serializes")
}

fn get_genesis_preset(id: &sp_genesis_builder::PresetId) -> Option<Vec<u8>> {
    let value = match id.as_ref() {
        "development" => kohl_genesis(MinDifficulty::get()),
        // Local testnet: harder than pure dev, still easy for a laptop miner.
        "kohl-ash" => kohl_genesis(100_000),
        "mainnet" => kohl_genesis(50_000_000),
        _ => return None,
    };
    Some(
        serde_json::to_string(&value)
            .expect("preset serializes")
            .into_bytes(),
    )
}

// ---- Runtime APIs -------------------------------------------------------

sp_api::impl_runtime_apis! {
    impl sp_api::Core<Block> for Runtime {
        fn version() -> RuntimeVersion { VERSION }
        fn execute_block(block: <Block as BlockT>::LazyBlock) {
            Executive::execute_block(block);
        }
        fn initialize_block(
            header: &<Block as BlockT>::Header,
        ) -> sp_runtime::ExtrinsicInclusionMode {
            Executive::initialize_block(header)
        }
    }

    impl sp_api::Metadata<Block> for Runtime {
        fn metadata() -> OpaqueMetadata {
            OpaqueMetadata::new(Runtime::metadata().into())
        }
        fn metadata_at_version(version: u32) -> Option<OpaqueMetadata> {
            Runtime::metadata_at_version(version)
        }
        fn metadata_versions() -> Vec<u32> {
            Runtime::metadata_versions()
        }
    }

    impl frame_support::view_functions::runtime_api::RuntimeViewFunction<Block> for Runtime {
        fn execute_view_function(
            id: frame_support::view_functions::ViewFunctionId,
            input: Vec<u8>,
        ) -> Result<Vec<u8>, frame_support::view_functions::ViewFunctionDispatchError> {
            Runtime::execute_view_function(id, input)
        }
    }

    impl sp_block_builder::BlockBuilder<Block> for Runtime {
        fn apply_extrinsic(extrinsic: <Block as BlockT>::Extrinsic) -> ApplyExtrinsicResult {
            Executive::apply_extrinsic(extrinsic)
        }
        fn finalize_block() -> <Block as BlockT>::Header {
            Executive::finalize_block()
        }
        fn inherent_extrinsics(
            data: sp_inherents::InherentData,
        ) -> Vec<<Block as BlockT>::Extrinsic> {
            data.create_extrinsics()
        }
        fn check_inherents(
            block: <Block as BlockT>::LazyBlock,
            data: sp_inherents::InherentData,
        ) -> sp_inherents::CheckInherentsResult {
            data.check_extrinsics(&block)
        }
    }

    impl sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block> for Runtime {
        fn validate_transaction(
            source: TransactionSource,
            tx: <Block as BlockT>::Extrinsic,
            block_hash: <Block as BlockT>::Hash,
        ) -> TransactionValidity {
            Executive::validate_transaction(source, tx, block_hash)
        }
    }

    impl sp_offchain::OffchainWorkerApi<Block> for Runtime {
        fn offchain_worker(header: &<Block as BlockT>::Header) {
            Executive::offchain_worker(header)
        }
    }

    impl frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, Nonce> for Runtime {
        fn account_nonce(account: AccountId) -> Nonce {
            System::account_nonce(account)
        }
    }

    impl sp_session::SessionKeys<Block> for Runtime {
        fn generate_session_keys(
            owner: Vec<u8>,
            seed: Option<Vec<u8>>,
        ) -> sp_session::OpaqueGeneratedSessionKeys {
            SessionKeys::generate(&owner, seed).into()
        }

        fn decode_session_keys(encoded: Vec<u8>) -> Option<Vec<(Vec<u8>, KeyTypeId)>> {
            SessionKeys::decode_into_raw_public_keys(&encoded)
        }
    }

    impl sp_genesis_builder::GenesisBuilder<Block> for Runtime {
        fn build_state(config: Vec<u8>) -> sp_genesis_builder::Result {
            build_state::<RuntimeGenesisConfig>(config)
        }
        fn get_preset(id: &Option<sp_genesis_builder::PresetId>) -> Option<Vec<u8>> {
            get_preset::<RuntimeGenesisConfig>(id, get_genesis_preset)
        }
        fn preset_names() -> Vec<sp_genesis_builder::PresetId> {
            vec![
                sp_genesis_builder::PresetId::from("development"),
                sp_genesis_builder::PresetId::from("kohl-ash"),
                sp_genesis_builder::PresetId::from("mainnet"),
            ]
        }
    }

    impl kohl_runtime_api::DifficultyApi<Block> for Runtime {
        fn difficulty() -> U256 {
            Difficulty::difficulty()
        }
    }

    impl kohl_runtime_api::RingCtApi<Block> for Runtime {
        fn outputs_in_range(
            from: BlockNumber,
            to: BlockNumber,
        ) -> Vec<(u64, StoredOutput<BlockNumber>)> {
            pallet_ringct::Outputs::<Runtime>::iter()
                .filter(|(_, o)| o.height >= from && o.height <= to)
                .collect()
        }

        fn output_distribution(from: BlockNumber, to: BlockNumber) -> Vec<u64> {
            let span = to.saturating_sub(from) as usize + 1;
            let mut buckets = vec![0u64; span];
            for (_, o) in pallet_ringct::Outputs::<Runtime>::iter() {
                if o.height >= from && o.height <= to {
                    buckets[(o.height - from) as usize] += 1;
                }
            }
            buckets
        }

        fn output_count() -> u64 {
            pallet_ringct::NextOutputIndex::<Runtime>::get()
        }

        fn is_key_image_spent(key_image: [u8; 32]) -> bool {
            pallet_ringct::KeyImages::<Runtime>::contains_key(key_image)
        }

        fn min_fee_per_byte() -> u64 {
            <Runtime as pallet_ringct::Config>::MinFeePerByte::get()
        }

        fn membership_root() -> [u8; 32] {
            pallet_ringct::Pallet::<Runtime>::membership_root()
        }

        fn membership_root_at(block: BlockNumber) -> Option<[u8; 32]> {
            pallet_ringct::Pallet::<Runtime>::membership_root_at(block)
        }

        fn tree_slots() -> u64 {
            pallet_ringct::Pallet::<Runtime>::tree_slots()
        }

        fn is_admitted(index: u64) -> bool {
            pallet_ringct::Pallet::<Runtime>::is_admitted(index)
        }

        fn membership_leaf_digest(index: u64) -> Option<[u8; 32]> {
            pallet_ringct::Pallet::<Runtime>::membership_leaf_digest(index)
        }

        fn membership_frontier() -> Vec<u8> {
            pallet_ringct::Pallet::<Runtime>::membership_frontier()
        }

        fn fcmp_mode() -> u8 {
            pallet_ringct::Pallet::<Runtime>::fcmp_mode()
        }

        fn admit_scan_cursor() -> u64 {
            pallet_ringct::Pallet::<Runtime>::admit_scan_cursor()
        }

        fn membership_backfill_status() -> pallet_ringct::MembershipBackfillStatus {
            pallet_ringct::Pallet::<Runtime>::membership_backfill_status()
        }
    }

    #[cfg(feature = "runtime-benchmarks")]
    impl frame_benchmarking::Benchmark<Block> for Runtime {
        fn benchmark_metadata(
            extra: bool,
        ) -> (
            Vec<frame_benchmarking::BenchmarkList>,
            Vec<frame_support::traits::StorageInfo>,
        ) {
            use frame_benchmarking::BenchmarkList;
            use frame_support::traits::StorageInfoTrait;

            let mut list = Vec::<BenchmarkList>::new();
            list_benchmarks!(list, extra);

            let storage_info = AllPalletsWithSystem::storage_info();
            (list, storage_info)
        }

        #[allow(non_local_definitions)]
        fn dispatch_benchmark(
            config: frame_benchmarking::BenchmarkConfig,
        ) -> Result<Vec<frame_benchmarking::BenchmarkBatch>, alloc::string::String> {
            use frame_benchmarking::BenchmarkBatch;
            use frame_support::traits::WhitelistedStorageKeys;
            use sp_storage::TrackedStorageKey;

            let whitelist: Vec<TrackedStorageKey> = AllPalletsWithSystem::whitelisted_storage_keys();
            let mut batches = Vec::<BenchmarkBatch>::new();
            let params = (&config, &whitelist);
            add_benchmarks!(params, batches);
            Ok(batches)
        }
    }
}
