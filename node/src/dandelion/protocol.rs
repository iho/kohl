//! Wire format and protocol name for Dandelion++ stem messages.

use codec::{Decode, Encode};
use sc_network::{
    config::{NonReservedPeerMode, SetConfig},
    peer_store::PeerStoreProvider,
    service::traits::NotificationService,
    NetworkBackend, NotificationMetrics, ProtocolName,
};
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;

/// Fallback protocol name (no genesis prefix).
pub const DANDELION_PROTOCOL_PREFIX: &str = "/kohl/dandelion/1";

/// Maximum stem notification size (single extrinsic + small header).
pub const MAX_STEM_SIZE: u64 = 4 * 1024 * 1024;

/// Stem-phase message: a single extrinsic being relayed along the anonymity path.
#[derive(Debug, Clone, Encode, Decode, PartialEq, Eq)]
pub struct StemMessage<E> {
    /// Extrinsic payload.
    pub extrinsic: E,
}

/// Protocol name, optionally namespaced by genesis hash + fork id.
pub fn protocol_name(genesis_hash: &[u8], fork_id: Option<&str>) -> ProtocolName {
    let hex = array_bytes::bytes2hex("", genesis_hash);
    if let Some(fork_id) = fork_id {
        format!("/{hex}/{fork_id}/kohl/dandelion/1").into()
    } else {
        format!("/{hex}/kohl/dandelion/1").into()
    }
}

/// Register the stem notification protocol on a network backend.
pub fn notification_config<B, Net>(
    genesis_hash: &[u8],
    fork_id: Option<&str>,
    metrics: NotificationMetrics,
    peer_store: Arc<dyn PeerStoreProvider>,
) -> (Net::NotificationProtocolConfig, Box<dyn NotificationService>)
where
    B: BlockT,
    Net: NetworkBackend<B, <B as BlockT>::Hash>,
{
    let name = protocol_name(genesis_hash, fork_id);
    Net::notification_config(
        name,
        vec![DANDELION_PROTOCOL_PREFIX.into()],
        MAX_STEM_SIZE,
        None,
        SetConfig {
            in_peers: 0,
            out_peers: 0,
            reserved_nodes: Vec::new(),
            non_reserved_mode: NonReservedPeerMode::Deny,
        },
        metrics,
        peer_store,
    )
}
