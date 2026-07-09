//! Full-node RPC extensions.
//!
//! * frame-system RPC (account nonce / dry-run)
//! * custom `ringct_*` methods wrapping the runtime `RingCtApi` so wallets
//!   do not need raw `state_call` encoding (BLUEPRINT.md §4.4 / §5.2)

#![warn(missing_docs)]

use std::sync::Arc;

use jsonrpsee::{core::async_trait, proc_macros::rpc, types::ErrorObjectOwned, RpcModule};
use kohl_runtime::{opaque::Block, AccountId, Nonce};
use kohl_runtime_api::RingCtApi as RuntimeRingCtApi;
use pallet_ringct::StoredOutput;
use sc_transaction_pool_api::TransactionPool;
use sp_api::ProvideRuntimeApi;
use sp_block_builder::BlockBuilder;
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};

/// Full client dependencies.
pub struct FullDeps<C, P> {
    /// The client instance.
    pub client: Arc<C>,
    /// Transaction pool instance.
    pub pool: Arc<P>,
}

/// Instantiate all full RPC extensions.
pub fn create_full<C, P>(
    deps: FullDeps<C, P>,
) -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>>
where
    C: ProvideRuntimeApi<Block>,
    C: HeaderBackend<Block> + HeaderMetadata<Block, Error = BlockChainError> + 'static,
    C: Send + Sync + 'static,
    C::Api: substrate_frame_rpc_system::AccountNonceApi<Block, AccountId, Nonce>,
    C::Api: BlockBuilder<Block>,
    C::Api: RuntimeRingCtApi<Block>,
    P: TransactionPool + 'static,
{
    use substrate_frame_rpc_system::{System, SystemApiServer};

    let mut module = RpcModule::new(());
    let FullDeps { client, pool } = deps;
    module.merge(System::new(client.clone(), pool).into_rpc())?;
    module.merge(RingCtRpc::new(client).into_rpc())?;
    Ok(module)
}

// ---- ringct_* RPC -------------------------------------------------------

/// Wallet-facing RingCT queries (hex-friendly JSON over the runtime API).
#[rpc(server)]
pub trait RingCtRpcApi {
    /// Total outputs ever created.
    #[method(name = "ringct_outputCount")]
    fn output_count(&self) -> Result<u64, ErrorObjectOwned>;

    /// Minimum fee per encoded extrinsic byte.
    #[method(name = "ringct_minFeePerByte")]
    fn min_fee_per_byte(&self) -> Result<u64, ErrorObjectOwned>;

    /// Whether a key image (32-byte hex, optional 0x) has been spent.
    #[method(name = "ringct_isKeyImageSpent")]
    fn is_key_image_spent(&self, key_image_hex: String) -> Result<bool, ErrorObjectOwned>;

    /// Outputs created in block range `[from, to]` (inclusive), as hex-encoded
    /// SCALE of `Vec<(u64, StoredOutput)>` (same encoding as the runtime API).
    #[method(name = "ringct_outputsInRange")]
    fn outputs_in_range(&self, from: u32, to: u32) -> Result<String, ErrorObjectOwned>;

    /// Current membership Merkle root (32-byte hex).
    #[method(name = "ringct_membershipRoot")]
    fn membership_root(&self) -> Result<String, ErrorObjectOwned>;

    /// Historical membership root at block end (32-byte hex), if retained.
    #[method(name = "ringct_membershipRootAt")]
    fn membership_root_at(&self, block: u32) -> Result<Option<String>, ErrorObjectOwned>;

    /// Number of grown membership tree slots.
    #[method(name = "ringct_treeSlots")]
    fn tree_slots(&self) -> Result<u64, ErrorObjectOwned>;

    /// Whether global output index has been admitted (`L(P,C)` leaf).
    #[method(name = "ringct_isAdmitted")]
    fn is_admitted(&self, index: u64) -> Result<bool, ErrorObjectOwned>;

    /// Leaf digest at index (32-byte hex), if the slot exists.
    #[method(name = "ringct_membershipLeafDigest")]
    fn membership_leaf_digest(&self, index: u64) -> Result<Option<String>, ErrorObjectOwned>;

    /// SCALE `Vec<[u8;32]>` of leaf digests `0..treeSlots` as 0x-hex.
    #[method(name = "ringct_membershipFrontier")]
    fn membership_frontier(&self) -> Result<String, ErrorObjectOwned>;

    /// Spend-path mode: `1` Building (CLSAG+tree), `2` FcmpOnly.
    #[method(name = "ringct_fcmpMode")]
    fn fcmp_mode(&self) -> Result<u8, ErrorObjectOwned>;

    /// Admit scan cursor (round-robin fill position).
    #[method(name = "ringct_admitScanCursor")]
    fn admit_scan_cursor(&self) -> Result<u64, ErrorObjectOwned>;

    /// Lag / catch-up status as JSON-friendly object.
    #[method(name = "ringct_membershipBackfillStatus")]
    fn membership_backfill_status(&self) -> Result<MembershipBackfillRpc, ErrorObjectOwned>;
}

/// JSON view of [`pallet_ringct::MembershipBackfillStatus`].
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MembershipBackfillRpc {
    /// Grown tree slots.
    pub tree_slots: u64,
    /// Next output index (tip).
    pub next_output_index: u64,
    /// True while `tree_slots < next_output_index`.
    pub lagging: bool,
    /// Round-robin admit cursor.
    pub admit_scan_cursor: u64,
    /// Current root as 0x-hex.
    pub membership_root: String,
}

/// RPC implementation backed by the runtime API at the best block.
pub struct RingCtRpc<C> {
    client: Arc<C>,
}

impl<C> RingCtRpc<C> {
    /// Create a new RingCT RPC handler.
    pub fn new(client: Arc<C>) -> Self {
        Self { client }
    }
}

fn rpc_err(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(1, msg.into(), None::<()>)
}

fn parse_ki(hex_str: &str) -> Result<[u8; 32], ErrorObjectOwned> {
    let bytes = hex::decode(hex_str.trim().trim_start_matches("0x"))
        .map_err(|e| rpc_err(format!("key_image hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(rpc_err(format!(
            "key_image must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn hex32(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

#[async_trait]
impl<C> RingCtRpcApiServer for RingCtRpc<C>
where
    C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
    C::Api: RuntimeRingCtApi<Block>,
{
    fn output_count(&self) -> Result<u64, ErrorObjectOwned> {
        let at = self.client.info().best_hash;
        self.client
            .runtime_api()
            .output_count(at)
            .map_err(|e| rpc_err(format!("runtime API: {e}")))
    }

    fn min_fee_per_byte(&self) -> Result<u64, ErrorObjectOwned> {
        let at = self.client.info().best_hash;
        self.client
            .runtime_api()
            .min_fee_per_byte(at)
            .map_err(|e| rpc_err(format!("runtime API: {e}")))
    }

    fn is_key_image_spent(&self, key_image_hex: String) -> Result<bool, ErrorObjectOwned> {
        let ki = parse_ki(&key_image_hex)?;
        let at = self.client.info().best_hash;
        self.client
            .runtime_api()
            .is_key_image_spent(at, ki)
            .map_err(|e| rpc_err(format!("runtime API: {e}")))
    }

    fn outputs_in_range(&self, from: u32, to: u32) -> Result<String, ErrorObjectOwned> {
        use codec::Encode;
        let at = self.client.info().best_hash;
        let outs: Vec<(u64, StoredOutput<u32>)> = self
            .client
            .runtime_api()
            .outputs_in_range(at, from, to)
            .map_err(|e| rpc_err(format!("runtime API: {e}")))?;
        Ok(format!("0x{}", hex::encode(outs.encode())))
    }

    fn membership_root(&self) -> Result<String, ErrorObjectOwned> {
        let at = self.client.info().best_hash;
        let root = self
            .client
            .runtime_api()
            .membership_root(at)
            .map_err(|e| rpc_err(format!("runtime API: {e}")))?;
        Ok(hex32(&root))
    }

    fn membership_root_at(&self, block: u32) -> Result<Option<String>, ErrorObjectOwned> {
        let at = self.client.info().best_hash;
        let root = self
            .client
            .runtime_api()
            .membership_root_at(at, block)
            .map_err(|e| rpc_err(format!("runtime API: {e}")))?;
        Ok(root.map(|r| hex32(&r)))
    }

    fn tree_slots(&self) -> Result<u64, ErrorObjectOwned> {
        let at = self.client.info().best_hash;
        self.client
            .runtime_api()
            .tree_slots(at)
            .map_err(|e| rpc_err(format!("runtime API: {e}")))
    }

    fn is_admitted(&self, index: u64) -> Result<bool, ErrorObjectOwned> {
        let at = self.client.info().best_hash;
        self.client
            .runtime_api()
            .is_admitted(at, index)
            .map_err(|e| rpc_err(format!("runtime API: {e}")))
    }

    fn membership_leaf_digest(&self, index: u64) -> Result<Option<String>, ErrorObjectOwned> {
        let at = self.client.info().best_hash;
        let d = self
            .client
            .runtime_api()
            .membership_leaf_digest(at, index)
            .map_err(|e| rpc_err(format!("runtime API: {e}")))?;
        Ok(d.map(|x| hex32(&x)))
    }

    fn membership_frontier(&self) -> Result<String, ErrorObjectOwned> {
        let at = self.client.info().best_hash;
        let raw = self
            .client
            .runtime_api()
            .membership_frontier(at)
            .map_err(|e| rpc_err(format!("runtime API: {e}")))?;
        Ok(format!("0x{}", hex::encode(raw)))
    }

    fn fcmp_mode(&self) -> Result<u8, ErrorObjectOwned> {
        let at = self.client.info().best_hash;
        self.client
            .runtime_api()
            .fcmp_mode(at)
            .map_err(|e| rpc_err(format!("runtime API: {e}")))
    }

    fn admit_scan_cursor(&self) -> Result<u64, ErrorObjectOwned> {
        let at = self.client.info().best_hash;
        self.client
            .runtime_api()
            .admit_scan_cursor(at)
            .map_err(|e| rpc_err(format!("runtime API: {e}")))
    }

    fn membership_backfill_status(&self) -> Result<MembershipBackfillRpc, ErrorObjectOwned> {
        let at = self.client.info().best_hash;
        let s = self
            .client
            .runtime_api()
            .membership_backfill_status(at)
            .map_err(|e| rpc_err(format!("runtime API: {e}")))?;
        Ok(MembershipBackfillRpc {
            tree_slots: s.tree_slots,
            next_output_index: s.next_output_index,
            lagging: s.lagging,
            admit_scan_cursor: s.admit_scan_cursor,
            membership_root: hex32(&s.membership_root),
        })
    }
}
