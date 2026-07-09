//! Async Dandelion++ worker: stem protocol I/O, embargo fluffs, epoch peermap.
//!
//! Fluff is implemented by *clearing* the stem bit on a hash. Stock
//! `sc-network-transactions` then floods it on its next propagate tick
//! (≈ 3 s) because [`super::StemGate`] starts reporting `is_propagable`.

use crate::dandelion::{protocol::StemMessage, stem_gate::SharedEngine};
use codec::{Decode, Encode};
use futures::{FutureExt, StreamExt};
use log::{debug, trace, warn};
use sc_network::{
    multiaddr,
    service::traits::{NotificationEvent, NotificationService, ValidationResult},
    NetworkEventStream, NetworkPeers, ProtocolName,
};
use sc_network_sync::{SyncEvent, SyncEventStream};
use sc_network_types::PeerId;
use sc_transaction_pool_api::{InPoolTransaction, TransactionPool, TransactionSource};
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Block as BlockT;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

const LOG: &str = "kohl::dandelion";

/// Parameters to start the Dandelion worker.
pub struct DandelionParams<B, C, P, N, S>
where
    B: BlockT,
    P: TransactionPool<Block = B> + 'static,
{
    /// Shared engine state (also held by [`super::StemGate`]).
    pub engine: SharedEngine,
    /// Stem notification service.
    pub notifications: Box<dyn NotificationService>,
    /// Protocol name (for reserved-set membership).
    pub protocol_name: ProtocolName,
    /// Network handle (roles, reserved peers).
    pub network: N,
    /// Sync service (major-sync gate + peer connect events).
    pub sync: S,
    /// Client for best-hash at import time.
    pub client: Arc<C>,
    /// Transaction pool (stem imports + extrinsic lookup).
    pub pool: Arc<P>,
    /// How often to scan embargo timers.
    pub tick: Duration,
}

/// Spawn the Dandelion++ event loop. Runs until the notification service closes.
pub async fn start_dandelion<B, C, P, N, S>(params: DandelionParams<B, C, P, N, S>)
where
    B: BlockT + 'static,
    B::Extrinsic: Decode + Encode + Clone + Send + Sync + 'static,
    B::Hash: std::fmt::Debug + Clone,
    C: HeaderBackend<B> + Send + Sync + 'static,
    P: TransactionPool<Block = B, Hash = B::Hash> + 'static,
    N: NetworkPeers + NetworkEventStream + Send + 'static,
    S: SyncEventStream + sp_consensus::SyncOracle + Send + 'static,
{
    let DandelionParams {
        engine,
        mut notifications,
        protocol_name,
        network,
        sync,
        client,
        pool,
        tick,
    } = params;

    let mut sync_events = sync.event_stream("kohl-dandelion-sync").fuse();
    let mut import_notifications = pool.import_notification_stream().fuse();
    let mut peers: HashMap<PeerId, String> = HashMap::new();
    let mut delay = futures_timer::Delay::new(tick).fuse();

    log::info!(
        target: LOG,
        "Dandelion++ enabled (stem protocol + embargo fluff)"
    );

    loop {
        futures::select! {
            event = notifications.next_event().fuse() => {
                let Some(event) = event else {
                    debug!(target: LOG, "notification service closed");
                    return;
                };
                handle_notification(
                    event,
                    &mut notifications,
                    &engine,
                    &network,
                    &sync,
                    &client,
                    &pool,
                    &mut peers,
                ).await;
            },
            ev = sync_events.select_next_some() => {
                handle_sync_event(ev, &network, &protocol_name, &engine, &mut peers);
            },
            hash = import_notifications.select_next_some() => {
                on_pool_import(
                    hash,
                    &engine,
                    &pool,
                    &mut notifications,
                    &peers,
                    &sync,
                ).await;
            },
            _ = delay => {
                on_tick(&engine);
                delay = futures_timer::Delay::new(tick).fuse();
            },
        }
    }
}

async fn handle_notification<B, C, P, N, S>(
    event: NotificationEvent,
    notifications: &mut Box<dyn NotificationService>,
    engine: &SharedEngine,
    network: &N,
    sync: &S,
    client: &Arc<C>,
    pool: &Arc<P>,
    peers: &mut HashMap<PeerId, String>,
) where
    B: BlockT + 'static,
    B::Extrinsic: Decode + Encode + Clone + Send + Sync + 'static,
    B::Hash: std::fmt::Debug + Clone,
    C: HeaderBackend<B>,
    P: TransactionPool<Block = B, Hash = B::Hash> + 'static,
    N: NetworkPeers,
    S: sp_consensus::SyncOracle,
{
    match event {
        NotificationEvent::ValidateInboundSubstream {
            peer,
            handshake,
            result_tx,
            ..
        } => {
            let result = network
                .peer_role(peer, handshake)
                .map_or(ValidationResult::Reject, |_| ValidationResult::Accept);
            let _ = result_tx.send(result);
        }
        NotificationEvent::NotificationStreamOpened {
            peer, handshake, ..
        } => {
            if network.peer_role(peer, handshake).is_none() {
                return;
            }
            let id = peer.to_base58();
            peers.insert(peer, id.clone());
            engine.write().peer_connected(id, Instant::now());
            trace!(target: LOG, "stem substream open {peer}");
        }
        NotificationEvent::NotificationStreamClosed { peer } => {
            if let Some(id) = peers.remove(&peer) {
                engine.write().peer_disconnected(&id, Instant::now());
            }
        }
        NotificationEvent::NotificationReceived { peer, notification } => {
            if sync.is_major_syncing() {
                return;
            }
            let msg = match StemMessage::<B::Extrinsic>::decode(&mut notification.as_ref()) {
                Ok(m) => m,
                Err(e) => {
                    warn!(target: LOG, "bad stem message from {peer}: {e:?}");
                    return;
                }
            };
            on_stem_received(peer, msg, notifications, engine, client, pool, peers).await;
        }
    }
}

fn handle_sync_event<N>(
    event: SyncEvent,
    network: &N,
    protocol_name: &ProtocolName,
    engine: &SharedEngine,
    peers: &mut HashMap<PeerId, String>,
) where
    N: NetworkPeers,
{
    match event {
        SyncEvent::PeerConnected(remote) => {
            let addr = multiaddr::Multiaddr::empty().with(multiaddr::Protocol::P2p(remote.into()));
            if let Err(e) = network
                .add_peers_to_reserved_set(protocol_name.clone(), std::iter::once(addr).collect())
            {
                debug!(target: LOG, "add reserved peer: {e}");
            }
            let id = remote.to_base58();
            peers.insert(remote, id.clone());
            engine.write().peer_connected(id, Instant::now());
        }
        SyncEvent::PeerDisconnected(remote) => {
            let _ = network.remove_peers_from_reserved_set(
                protocol_name.clone(),
                std::iter::once(remote).collect(),
            );
            if let Some(id) = peers.remove(&remote) {
                engine.write().peer_disconnected(&id, Instant::now());
            }
        }
    }
}

async fn on_pool_import<B, P>(
    hash: B::Hash,
    engine: &SharedEngine,
    pool: &Arc<P>,
    notifications: &mut Box<dyn NotificationService>,
    peers: &HashMap<PeerId, String>,
    sync: &impl sp_consensus::SyncOracle,
) where
    B: BlockT + 'static,
    B::Extrinsic: Encode + Clone + Send + Sync + 'static,
    B::Hash: std::fmt::Debug + Clone,
    P: TransactionPool<Block = B, Hash = B::Hash> + 'static,
{
    if sync.is_major_syncing() {
        return;
    }
    let key = format!("{hash:?}");
    let now = Instant::now();

    // Only act on stem-phase hashes (local origin or prior stem receive).
    if !engine.read().is_stem(&key) {
        return;
    }

    let decision = engine.write().stem_decision(&key, now);
    match decision {
        Some(outbound_id) => {
            if let Some(peer) = peer_by_id(peers, &outbound_id) {
                if send_stem::<B, P>(notifications, &peer, &hash, pool) {
                    debug!(target: LOG, "stem → {outbound_id} hash={hash:?}");
                } else {
                    fluff_now(engine, &key, &hash);
                }
            } else {
                fluff_now(engine, &key, &hash);
            }
        }
        None => fluff_now(engine, &key, &hash),
    }
}

async fn on_stem_received<B, C, P>(
    from: PeerId,
    msg: StemMessage<B::Extrinsic>,
    notifications: &mut Box<dyn NotificationService>,
    engine: &SharedEngine,
    client: &Arc<C>,
    pool: &Arc<P>,
    peers: &HashMap<PeerId, String>,
) where
    B: BlockT + 'static,
    B::Extrinsic: Decode + Encode + Clone + Send + Sync + 'static,
    B::Hash: std::fmt::Debug + Clone,
    C: HeaderBackend<B>,
    P: TransactionPool<Block = B, Hash = B::Hash> + 'static,
{
    let from_id = from.to_base58();
    let at = client.info().best_hash;

    let hash = match pool
        .submit_one(at, TransactionSource::External, msg.extrinsic)
        .await
    {
        Ok(h) => h,
        Err(e) => {
            trace!(target: LOG, "stem import rejected from {from_id}: {e:?}");
            return;
        }
    };

    let key = format!("{hash:?}");
    let now = Instant::now();

    {
        let mut eng = engine.write();
        eng.enter_stem(key.clone(), Some(from_id.clone()), now);
        let decision = eng.stem_decision(&key, now);
        drop(eng);

        match decision {
            Some(outbound_id) => {
                if let Some(peer) = peer_by_id(peers, &outbound_id) {
                    if send_stem::<B, P>(notifications, &peer, &hash, pool) {
                        debug!(
                            target: LOG,
                            "stem relay {from_id} → {outbound_id} hash={hash:?}"
                        );
                    } else {
                        fluff_now(engine, &key, &hash);
                    }
                } else {
                    fluff_now(engine, &key, &hash);
                }
            }
            None => {
                debug!(target: LOG, "stem → fluff at this hop hash={hash:?}");
                fluff_now(engine, &key, &hash);
            }
        }
    }
}

fn send_stem<B, P>(
    notifications: &mut Box<dyn NotificationService>,
    peer: &PeerId,
    hash: &B::Hash,
    pool: &Arc<P>,
) -> bool
where
    B: BlockT,
    B::Extrinsic: Encode + Clone,
    P: TransactionPool<Block = B, Hash = B::Hash>,
{
    let Some(tx) = pool.ready_transaction(hash) else {
        return false;
    };
    // `InPoolTransaction::Transaction` is `Arc<Extrinsic>` for Substrate pools
    // (and for our `GatedTx` wrapper). Clone the inner extrinsic for the wire
    // format `StemMessage<B::Extrinsic>`.
    let extrinsic = tx.data().as_ref().clone();
    let payload = StemMessage::<B::Extrinsic> { extrinsic }.encode();
    notifications.send_sync_notification(peer, payload);
    true
}

fn fluff_now<H: std::fmt::Debug>(engine: &SharedEngine, key: &str, hash: &H) {
    engine.write().fluff(key);
    // Stock transactions handler will flood on its next propagate tick
    // because StemGate now reports is_propagable == true for this hash.
    debug!(target: LOG, "fluff (stem cleared) hash={hash:?}");
}

fn on_tick(engine: &SharedEngine) {
    let now = Instant::now();
    let expired = engine.read().embargo_expired(now);
    for key in expired {
        engine.write().fluff(&key);
        debug!(target: LOG, "embargo fluff key={key}");
    }
}

fn peer_by_id(peers: &HashMap<PeerId, String>, id: &str) -> Option<PeerId> {
    peers
        .iter()
        .find(|(_, v)| v.as_str() == id)
        .map(|(p, _)| *p)
}
