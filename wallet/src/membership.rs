//! Membership witness cache for FCMP proving (PR-8).
//!
//! Holds a Path A leaf-digest vector + admitted `(P,C)` set under a root.
//! Call [`MembershipCache::refresh`] after scanning outputs, and
//! [`MembershipCache::resync_if_reorged`] when the best tip moves back
//! (or root/slots diverge from the cache).

use crate::{MembershipSnapshot, StoredOut, WalletError};
use ringct_crypto::fcmp::{
    empty_leaf_hash, leaf_hash, root_from_leaves, RingMember as FcmpTreeMember,
};
use ringct_primitives::MAX_FCMP_ANON_SET;

/// In-memory membership tree witness with tip tracking for reorg detection.
#[derive(Clone, Debug, Default)]
pub struct MembershipCache {
    /// Last known best block when this cache was built (wallet-side).
    pub tip_height: u32,
    pub snapshot: Option<MembershipSnapshot>,
}

impl MembershipCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {
        self.tip_height = 0;
        self.snapshot = None;
    }

    pub fn snapshot(&self) -> Option<&MembershipSnapshot> {
        self.snapshot.as_ref()
    }

    pub fn root(&self) -> Option<[u8; 32]> {
        self.snapshot.as_ref().map(|s| s.root)
    }

    /// Replace the cache from digests + output map.
    ///
    /// Digests must be the full `0..tree_slots` vector from the node.
    /// Non-EMPTY digests require a matching output in `by_index`.
    pub fn rebuild(
        &mut self,
        tip_height: u32,
        expected_root: [u8; 32],
        digests: Vec<[u8; 32]>,
        by_index: &std::collections::BTreeMap<u64, &StoredOut>,
    ) -> Result<&MembershipSnapshot, WalletError> {
        if digests.len() > MAX_FCMP_ANON_SET as usize {
            return Err(WalletError::TreeTooLarge);
        }
        let empty = empty_leaf_hash();
        let computed = root_from_leaves(&digests);
        if computed != expected_root {
            return Err(WalletError::MembershipStale);
        }

        let mut admitted = Vec::new();
        for (i, d) in digests.iter().enumerate() {
            if *d == empty {
                continue;
            }
            let out = by_index
                .get(&(i as u64))
                .ok_or(WalletError::MembershipIncomplete)?;
            let lh = leaf_hash(&out.one_time_key, &out.commitment);
            if lh != *d {
                return Err(WalletError::MembershipIncomplete);
            }
            admitted.push(FcmpTreeMember {
                one_time_key: out.one_time_key,
                commitment: out.commitment,
                tree_index: i as u64,
            });
        }

        self.tip_height = tip_height;
        self.snapshot = Some(MembershipSnapshot {
            root: expected_root,
            digests,
            admitted,
        });
        Ok(self.snapshot.as_ref().expect("just set"))
    }

    /// True if chain tip went backwards or root/slots no longer match.
    pub fn needs_resync(&self, chain_tip: u32, chain_root: &[u8; 32], chain_slots: u64) -> bool {
        let Some(snap) = &self.snapshot else {
            return true;
        };
        if chain_tip < self.tip_height {
            return true; // reorg / rewind
        }
        if snap.root != *chain_root {
            return true;
        }
        if snap.digests.len() as u64 != chain_slots {
            return true;
        }
        false
    }

    /// Clear cache when a reorg or tip divergence is detected.
    pub fn resync_if_reorged(
        &mut self,
        chain_tip: u32,
        chain_root: &[u8; 32],
        chain_slots: u64,
    ) -> bool {
        if self.needs_resync(chain_tip, chain_root, chain_slots) {
            self.clear();
            true
        } else {
            false
        }
    }

    /// Ensure every spend index is in the admitted set.
    pub fn ensure_spends_admitted(&self, indices: &[u64]) -> Result<(), WalletError> {
        let snap = self
            .snapshot
            .as_ref()
            .ok_or(WalletError::MembershipIncomplete)?;
        for idx in indices {
            if !snap.admitted.iter().any(|m| m.tree_index == *idx) {
                return Err(WalletError::MembershipIncomplete);
            }
        }
        Ok(())
    }
}

/// Build a [`MembershipSnapshot`] from a frontier digest vector + outputs.
pub fn snapshot_from_frontier(
    root: [u8; 32],
    digests: Vec<[u8; 32]>,
    outputs: &[(u64, StoredOut)],
) -> Result<MembershipSnapshot, WalletError> {
    let mut cache = MembershipCache::new();
    let by_index: std::collections::BTreeMap<u64, &StoredOut> =
        outputs.iter().map(|(i, o)| (*i, o)).collect();
    cache.rebuild(0, root, digests, &by_index)?;
    Ok(cache.snapshot.expect("rebuilt"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ringct_crypto::native as crypto;
    use ringct_crypto::stealth;

    fn mint(address: &stealth::StealthAddress, gi: u64, amount: u64) -> StoredOut {
        let (tx_secret, tx_pubkey) = stealth::tx_keypair();
        let shared = stealth::sender_shared_secret(&tx_secret, &address.view_public).unwrap();
        let (one_time_key, view_tag) =
            stealth::derive_one_time_key(&shared, &address.spend_public, 0).unwrap();
        StoredOut {
            one_time_key,
            commitment: crypto::value_commitment(amount),
            tx_pubkey,
            view_tag,
            payload: Default::default(),
            amount: Some(amount),
            height: gi as u32,
            coinbase: true,
        }
    }

    #[test]
    fn rebuild_and_ensure_spends() {
        let w = stealth::keypair_from_seed(&[1u8; 32]).1;
        let outs = vec![(0u64, mint(&w, 0, 100)), (1u64, mint(&w, 1, 200))];
        let digests: Vec<_> = outs
            .iter()
            .map(|(_, o)| leaf_hash(&o.one_time_key, &o.commitment))
            .collect();
        let root = root_from_leaves(&digests);
        let mut cache = MembershipCache::new();
        let by: std::collections::BTreeMap<_, _> = outs.iter().map(|(i, o)| (*i, o)).collect();
        cache.rebuild(10, root, digests, &by).unwrap();
        cache.ensure_spends_admitted(&[0, 1]).unwrap();
        assert!(cache.ensure_spends_admitted(&[2]).is_err());
    }

    #[test]
    fn reorg_detection() {
        let mut cache = MembershipCache {
            tip_height: 100,
            snapshot: Some(MembershipSnapshot {
                root: [1u8; 32],
                digests: vec![[2u8; 32]],
                admitted: vec![],
            }),
        };
        assert!(cache.needs_resync(90, &[1u8; 32], 1)); // rewind
        assert!(cache.needs_resync(100, &[9u8; 32], 1)); // root change
        assert!(cache.needs_resync(100, &[1u8; 32], 2)); // slots change
        assert!(!cache.needs_resync(105, &[1u8; 32], 1)); // forward tip ok
        assert!(cache.resync_if_reorged(90, &[1u8; 32], 1));
        assert!(cache.snapshot.is_none());
    }
}
