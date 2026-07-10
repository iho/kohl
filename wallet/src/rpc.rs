//! Minimal JSON-RPC client for talking to a kohl node: runtime-API calls via
//! `state_call`, and extrinsic submission via `author_submitExtrinsic`.

use crate::{MembershipSnapshot, StoredOut};
use codec::{Decode, Encode};
use ringct_crypto::fcmp::empty_leaf_hash;
use serde_json::json;
use std::error::Error;

pub struct RpcClient {
    url: String,
}

type R<T> = Result<T, Box<dyn Error>>;

impl RpcClient {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
        }
    }

    fn call(&self, method: &str, params: serde_json::Value) -> R<serde_json::Value> {
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let resp: serde_json::Value = ureq::post(&self.url).send_json(req)?.into_json()?;
        if let Some(err) = resp.get("error") {
            return Err(format!("rpc error: {err}").into());
        }
        Ok(resp
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null))
    }

    /// Call a runtime API method (`Trait_method`) with SCALE-encoded args and
    /// return the raw SCALE-encoded result bytes.
    fn runtime_call(&self, api_method: &str, args: &[u8]) -> R<Vec<u8>> {
        let hex_args = format!("0x{}", hex::encode(args));
        let result = self.call("state_call", json!([api_method, hex_args]))?;
        let s = result.as_str().ok_or("state_call: non-string result")?;
        Ok(hex::decode(s.trim_start_matches("0x"))?)
    }

    pub fn best_number(&self) -> R<u32> {
        let header = self.call("chain_getHeader", json!([]))?;
        let num = header
            .get("number")
            .and_then(|n| n.as_str())
            .ok_or("no header number")?;
        Ok(u32::from_str_radix(num.trim_start_matches("0x"), 16)?)
    }

    pub fn output_count(&self) -> R<u64> {
        // Prefer dedicated ringct_* RPC; fall back to state_call for older nodes.
        if let Ok(v) = self.call("ringct_outputCount", json!([])) {
            if let Some(n) = v.as_u64() {
                return Ok(n);
            }
        }
        let bytes = self.runtime_call("RingCtApi_output_count", &[])?;
        Ok(u64::decode(&mut &bytes[..])?)
    }

    pub fn min_fee_per_byte(&self) -> R<u64> {
        if let Ok(v) = self.call("ringct_minFeePerByte", json!([])) {
            if let Some(n) = v.as_u64() {
                return Ok(n);
            }
        }
        let bytes = self.runtime_call("RingCtApi_min_fee_per_byte", &[])?;
        Ok(u64::decode(&mut &bytes[..])?)
    }

    pub fn is_key_image_spent(&self, key_image: [u8; 32]) -> R<bool> {
        let hex_ki = format!("0x{}", hex::encode(key_image));
        if let Ok(v) = self.call("ringct_isKeyImageSpent", json!([hex_ki])) {
            if let Some(b) = v.as_bool() {
                return Ok(b);
            }
        }
        let bytes = self.runtime_call("RingCtApi_is_key_image_spent", &key_image.encode())?;
        Ok(bool::decode(&mut &bytes[..])?)
    }

    /// Fetch every output created in blocks `[from, to]`.
    pub fn outputs_in_range(&self, from: u32, to: u32) -> R<Vec<(u64, StoredOut)>> {
        if let Ok(v) = self.call("ringct_outputsInRange", json!([from, to])) {
            if let Some(s) = v.as_str() {
                let bytes = hex::decode(s.trim_start_matches("0x"))?;
                return Ok(Decode::decode(&mut &bytes[..])?);
            }
        }
        let bytes = self.runtime_call("RingCtApi_outputs_in_range", &(from, to).encode())?;
        Ok(Decode::decode(&mut &bytes[..])?)
    }

    /// Submit an already-encoded extrinsic; returns the tx hash on success.
    pub fn submit_extrinsic(&self, xt: &[u8]) -> R<String> {
        let hex_xt = format!("0x{}", hex::encode(xt));
        let result = self.call("author_submitExtrinsic", json!([hex_xt]))?;
        Ok(result.as_str().unwrap_or_default().to_string())
    }

    pub fn membership_root(&self) -> R<[u8; 32]> {
        if let Ok(v) = self.call("ringct_membershipRoot", json!([])) {
            if let Some(s) = v.as_str() {
                return parse_hex32(s);
            }
        }
        let bytes = self.runtime_call("RingCtApi_membership_root", &[])?;
        Ok(<[u8; 32]>::decode(&mut &bytes[..])?)
    }

    pub fn tree_slots(&self) -> R<u64> {
        if let Ok(v) = self.call("ringct_treeSlots", json!([])) {
            if let Some(n) = v.as_u64() {
                return Ok(n);
            }
        }
        let bytes = self.runtime_call("RingCtApi_tree_slots", &[])?;
        Ok(u64::decode(&mut &bytes[..])?)
    }

    pub fn is_admitted(&self, index: u64) -> R<bool> {
        if let Ok(v) = self.call("ringct_isAdmitted", json!([index])) {
            if let Some(b) = v.as_bool() {
                return Ok(b);
            }
        }
        let bytes = self.runtime_call("RingCtApi_is_admitted", &index.encode())?;
        Ok(bool::decode(&mut &bytes[..])?)
    }

    pub fn membership_leaf_digest(&self, index: u64) -> R<Option<[u8; 32]>> {
        if let Ok(v) = self.call("ringct_membershipLeafDigest", json!([index])) {
            if v.is_null() {
                return Ok(None);
            }
            if let Some(s) = v.as_str() {
                return Ok(Some(parse_hex32(s)?));
            }
        }
        let bytes = self.runtime_call("RingCtApi_membership_leaf_digest", &index.encode())?;
        Ok(Option::<[u8; 32]>::decode(&mut &bytes[..])?)
    }

    /// SCALE frontier: `Vec<[u8;32]>` digests for `0..tree_slots`.
    pub fn membership_frontier(&self) -> R<Vec<[u8; 32]>> {
        if let Ok(v) = self.call("ringct_membershipFrontier", json!([])) {
            if let Some(s) = v.as_str() {
                let bytes = hex::decode(s.trim_start_matches("0x"))?;
                return Ok(Decode::decode(&mut &bytes[..])?);
            }
        }
        let bytes = self.runtime_call("RingCtApi_membership_frontier", &[])?;
        Ok(Decode::decode(&mut &bytes[..])?)
    }

    /// Build a prove-time membership snapshot (prefers frontier RPC).
    pub fn membership_snapshot(&self, all_outputs: &[(u64, StoredOut)]) -> R<MembershipSnapshot> {
        let root = self.membership_root()?;
        let slots = self.tree_slots()?;
        let digests = match self.membership_frontier() {
            Ok(d) if d.len() as u64 == slots => d,
            _ => {
                // Fallback: one digest RPC per slot.
                let empty = empty_leaf_hash();
                let mut digests = Vec::with_capacity(slots as usize);
                for i in 0..slots {
                    digests.push(self.membership_leaf_digest(i)?.unwrap_or(empty));
                }
                digests
            }
        };
        crate::snapshot_from_frontier(root, digests, all_outputs).map_err(|e| e.to_string().into())
    }

    /// Refresh a cache against the live tip; clears and rebuilds on reorg/stale.
    pub fn refresh_membership_cache(
        &self,
        cache: &mut crate::MembershipCache,
        all_outputs: &[(u64, StoredOut)],
    ) -> R<MembershipSnapshot> {
        let tip = self.best_number()?;
        let root = self.membership_root()?;
        let slots = self.tree_slots()?;
        if cache.resync_if_reorged(tip, &root, slots) || cache.snapshot().is_none() {
            let snap = self.membership_snapshot(all_outputs)?;
            let by_index: std::collections::BTreeMap<u64, &StoredOut> =
                all_outputs.iter().map(|(i, o)| (*i, o)).collect();
            cache.rebuild(tip, snap.root, snap.digests, &by_index)?;
        }
        Ok(cache.snapshot().expect("populated").clone())
    }
}

fn parse_hex32(s: &str) -> R<[u8; 32]> {
    let bytes = hex::decode(s.trim().trim_start_matches("0x"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()).into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
