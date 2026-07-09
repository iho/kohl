//! Pure Dandelion++ state machine (no networking).
//!
//! Unit-tested in isolation so the privacy logic does not depend on libp2p.

use std::{
    collections::{HashMap, HashSet},
    hash::{DefaultHasher, Hash, Hasher},
    time::{Duration, Instant},
};

/// Tunables. Defaults track Monero’s production-ish ranges (epoch minutes,
/// fluff ≈ 10–20 %, embargo tens of seconds).
#[derive(Debug, Clone)]
pub struct DandelionConfig {
    /// Probability that a stem hop switches to fluff. `0.0..1.0`.
    pub fluff_probability: f64,
    /// How long a node waits to see a fluff before self-fluffing.
    pub embargo: Duration,
    /// Stem routing table lifetime.
    pub epoch: Duration,
    /// Soft cap on tracked stem hashes (drop oldest by embargo deadline).
    pub max_stem_entries: usize,
}

impl Default for DandelionConfig {
    fn default() -> Self {
        Self {
            fluff_probability: 0.1,
            embargo: Duration::from_secs(16),
            epoch: Duration::from_secs(10 * 60),
            max_stem_entries: 4096,
        }
    }
}

/// Stem routing decision for the current epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochRoute {
    /// Peer to which this node stems outbound traffic, if any.
    pub outbound: Option<String>,
    /// Whether *this* node is a fluff (diffuse) node for the epoch.
    ///
    /// Dandelion++ makes the fluff/relay role a property of the node+epoch,
    /// not of the transaction (see paper §4.2).
    pub is_fluff_node: bool,
    /// Epoch index (monotone).
    pub index: u64,
}

#[derive(Debug)]
struct StemEntry {
    embargo_deadline: Instant,
    /// Peer we received the stem from (if any); never stem back to it.
    from: Option<String>,
}

/// Shared Dandelion++ state.
///
/// `PeerId` is stored as its base58 string so the engine stays free of
/// `sc-network` types and is easy to unit-test.
#[derive(Debug)]
pub struct DandelionEngine {
    cfg: DandelionConfig,
    /// Local node identity (base58). Used to seed epoch fluff role.
    local_id: String,
    /// Hashes currently embargoed / on the stem.
    stem: HashMap<String, StemEntry>,
    /// Current epoch routing.
    epoch: EpochRoute,
    /// Known full-node peers (base58).
    peers: HashSet<String>,
    epoch_started: Instant,
    /// Monotone counter so tests can force epoch rolls without sleeping.
    epoch_index: u64,
}

impl DandelionEngine {
    /// Create an engine. `local_id` should be stable for the process lifetime.
    pub fn new(cfg: DandelionConfig, local_id: impl Into<String>) -> Self {
        let local_id = local_id.into();
        let mut eng = Self {
            cfg,
            local_id,
            stem: HashMap::new(),
            epoch: EpochRoute {
                outbound: None,
                is_fluff_node: false,
                index: 0,
            },
            peers: HashSet::new(),
            epoch_started: Instant::now(),
            epoch_index: 0,
        };
        eng.recompute_epoch(Instant::now());
        eng
    }

    /// Current epoch route (may refresh if the epoch timer elapsed).
    #[cfg(test)]
    pub fn epoch_route(&mut self, now: Instant) -> &EpochRoute {
        self.maybe_roll_epoch(now);
        &self.epoch
    }

    /// Notify that a full-node peer connected.
    pub fn peer_connected(&mut self, peer: impl Into<String>, now: Instant) {
        self.peers.insert(peer.into());
        // Rebuild outbound if we had none.
        if self.epoch.outbound.is_none() {
            self.recompute_epoch(now);
        }
    }

    /// Notify that a peer disconnected.
    pub fn peer_disconnected(&mut self, peer: &str, now: Instant) {
        self.peers.remove(peer);
        if self.epoch.outbound.as_deref() == Some(peer) {
            self.recompute_epoch(now);
        }
    }

    /// Whether `hash` is currently in the stem set (must not flood).
    pub fn is_stem(&self, hash: &str) -> bool {
        self.stem.contains_key(hash)
    }

    /// Enter stem phase for a newly originated or stem-received tx.
    ///
    /// Returns `false` if the hash was already known (stem or recently seen).
    pub fn enter_stem(
        &mut self,
        hash: impl Into<String>,
        from: Option<String>,
        now: Instant,
    ) -> bool {
        let hash = hash.into();
        if self.stem.contains_key(&hash) {
            return false;
        }
        self.evict_if_full(now);
        self.stem.insert(
            hash,
            StemEntry {
                embargo_deadline: now + self.cfg.embargo,
                from,
            },
        );
        true
    }

    /// Clear stem state — transaction may now be flooded.
    pub fn fluff(&mut self, hash: &str) -> bool {
        self.stem.remove(hash).is_some()
    }

    /// Decide what to do with a stem-phase transaction at this hop.
    ///
    /// Returns the outbound peer id for continued stemming, or `None` to fluff.
    pub fn stem_decision(&mut self, hash: &str, now: Instant) -> Option<String> {
        self.maybe_roll_epoch(now);
        if !self.stem.contains_key(hash) {
            return None;
        }
        // Node-level fluff role for this epoch.
        if self.epoch.is_fluff_node {
            return None;
        }
        // Also fluff with per-hop probability (Dandelion++ still samples).
        if self.sample_fluff(hash) {
            return None;
        }
        let from = self.stem.get(hash).and_then(|e| e.from.clone());
        let outbound = self.epoch.outbound.clone()?;
        // Never bounce back to the inbound stem peer.
        if from.as_deref() == Some(outbound.as_str()) {
            // Pick an alternate peer if possible.
            return self
                .peers
                .iter()
                .find(|p| Some(p.as_str()) != from.as_deref())
                .cloned()
                .or(None);
        }
        Some(outbound)
    }

    /// Hashes whose embargo expired and must be fluffed now.
    pub fn embargo_expired(&self, now: Instant) -> Vec<String> {
        self.stem
            .iter()
            .filter(|(_, e)| now >= e.embargo_deadline)
            .map(|(h, _)| h.clone())
            .collect()
    }

    /// Force an epoch roll (tests / peer set changes).
    #[cfg(test)]
    pub fn force_epoch(&mut self, now: Instant) {
        self.epoch_index = self.epoch_index.wrapping_add(1);
        self.recompute_epoch(now);
    }

    // --- internals -------------------------------------------------------

    fn maybe_roll_epoch(&mut self, now: Instant) {
        if now.duration_since(self.epoch_started) >= self.cfg.epoch {
            self.epoch_index = self.epoch_index.wrapping_add(1);
            self.recompute_epoch(now);
        }
    }

    fn recompute_epoch(&mut self, now: Instant) {
        self.epoch_started = now;
        // Deterministic fluff role from (local_id, epoch_index).
        let mut h = DefaultHasher::new();
        self.local_id.hash(&mut h);
        self.epoch_index.hash(&mut h);
        b"kohl/dandelion/fluff-role".hash(&mut h);
        let roll = (h.finish() % 10_000) as f64 / 10_000.0;
        let is_fluff_node = roll < self.cfg.fluff_probability;

        // Pick outbound stem peer: hash(local, epoch, peer) → min.
        let outbound = if self.peers.is_empty() {
            None
        } else {
            let mut best: Option<(u64, &String)> = None;
            for p in &self.peers {
                let mut ph = DefaultHasher::new();
                self.local_id.hash(&mut ph);
                self.epoch_index.hash(&mut ph);
                p.hash(&mut ph);
                b"kohl/dandelion/outbound".hash(&mut ph);
                let score = ph.finish();
                match best {
                    None => best = Some((score, p)),
                    Some((s, _)) if score < s => best = Some((score, p)),
                    _ => {}
                }
            }
            best.map(|(_, p)| p.clone())
        };

        self.epoch = EpochRoute {
            outbound,
            is_fluff_node,
            index: self.epoch_index,
        };
    }

    fn sample_fluff(&self, hash: &str) -> bool {
        let mut h = DefaultHasher::new();
        self.local_id.hash(&mut h);
        self.epoch_index.hash(&mut h);
        hash.hash(&mut h);
        b"kohl/dandelion/hop-fluff".hash(&mut h);
        let roll = (h.finish() % 10_000) as f64 / 10_000.0;
        roll < self.cfg.fluff_probability
    }

    fn evict_if_full(&mut self, now: Instant) {
        if self.stem.len() < self.cfg.max_stem_entries {
            return;
        }
        // Drop the entry closest to (or past) embargo first.
        if let Some(key) = self
            .stem
            .iter()
            .min_by_key(|(_, e)| e.embargo_deadline)
            .map(|(k, _)| k.clone())
        {
            let _ = now;
            self.stem.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eng(peers: &[&str]) -> DandelionEngine {
        let mut e = DandelionEngine::new(DandelionConfig::default(), "local-node");
        let now = Instant::now();
        for p in peers {
            e.peer_connected(*p, now);
        }
        e
    }

    #[test]
    fn local_origin_enters_stem() {
        let mut e = eng(&["peer-a", "peer-b"]);
        let now = Instant::now();
        assert!(e.enter_stem("tx1", None, now));
        assert!(e.is_stem("tx1"));
        assert!(!e.enter_stem("tx1", None, now));
    }

    #[test]
    fn fluff_clears_stem() {
        let mut e = eng(&["peer-a"]);
        let now = Instant::now();
        e.enter_stem("tx1", None, now);
        assert!(e.fluff("tx1"));
        assert!(!e.is_stem("tx1"));
        assert!(!e.fluff("tx1"));
    }

    #[test]
    fn embargo_expires() {
        let mut cfg = DandelionConfig::default();
        cfg.embargo = Duration::from_millis(50);
        let mut e = DandelionEngine::new(cfg, "local");
        let t0 = Instant::now();
        e.peer_connected("p1", t0);
        e.enter_stem("tx1", None, t0);
        assert!(e.embargo_expired(t0).is_empty());
        let t1 = t0 + Duration::from_millis(60);
        assert_eq!(e.embargo_expired(t1), vec!["tx1".to_string()]);
    }

    #[test]
    fn stem_decision_returns_outbound_or_fluff() {
        // Force fluff_probability = 0 and is_fluff_node = false by using 0.0.
        let mut cfg = DandelionConfig::default();
        cfg.fluff_probability = 0.0;
        let mut e = DandelionEngine::new(cfg, "local");
        let now = Instant::now();
        e.peer_connected("peer-a", now);
        e.peer_connected("peer-b", now);
        e.enter_stem("tx1", None, now);
        // With p=0, should stem to the epoch outbound.
        let d = e.stem_decision("tx1", now);
        assert!(d.is_some(), "expected stem outbound, got fluff");
        assert!(e.peers.contains(d.as_ref().unwrap()));
    }

    #[test]
    fn fluff_probability_one_always_fluffs() {
        let mut cfg = DandelionConfig::default();
        cfg.fluff_probability = 1.0;
        let mut e = DandelionEngine::new(cfg, "local");
        let now = Instant::now();
        e.peer_connected("peer-a", now);
        e.enter_stem("tx1", None, now);
        // is_fluff_node will be true with p=1, so decision is fluff.
        assert_eq!(e.stem_decision("tx1", now), None);
    }

    #[test]
    fn epoch_roll_changes_index() {
        let mut e = eng(&["peer-a"]);
        let now = Instant::now();
        let i0 = e.epoch_route(now).index;
        e.force_epoch(now);
        let i1 = e.epoch_route(now).index;
        assert_ne!(i0, i1);
    }

    #[test]
    fn no_peers_means_fluff() {
        let mut cfg = DandelionConfig::default();
        cfg.fluff_probability = 0.0;
        let mut e = DandelionEngine::new(cfg, "local");
        let now = Instant::now();
        e.enter_stem("tx1", None, now);
        assert_eq!(e.stem_decision("tx1", now), None);
    }

    #[test]
    fn does_not_stem_back_to_sender() {
        let mut cfg = DandelionConfig::default();
        cfg.fluff_probability = 0.0;
        let mut e = DandelionEngine::new(cfg, "local");
        let now = Instant::now();
        e.peer_connected("peer-a", now);
        e.peer_connected("peer-b", now);
        // Force outbound to peer-a by rolling until it matches (bounded).
        let mut outbound = e.epoch_route(now).outbound.clone().unwrap();
        for _ in 0..32 {
            if outbound == "peer-a" {
                break;
            }
            e.force_epoch(now);
            outbound = e.epoch_route(now).outbound.clone().unwrap();
        }
        e.enter_stem("tx1", Some(outbound.clone()), now);
        let d = e.stem_decision("tx1", now);
        // Should not return the same peer we received from.
        if let Some(ref p) = d {
            assert_ne!(p, &outbound);
        }
        // None (fluff) is also acceptable when no alternate exists.
    }
}
