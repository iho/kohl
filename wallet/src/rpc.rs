//! Minimal JSON-RPC client for talking to a kohl node: runtime-API calls via
//! `state_call`, and extrinsic submission via `author_submitExtrinsic`.

use crate::StoredOut;
use codec::{Decode, Encode};
use serde_json::json;
use std::error::Error;

pub struct RpcClient {
    url: String,
}

type R<T> = Result<T, Box<dyn Error>>;

impl RpcClient {
    pub fn new(url: &str) -> Self {
        Self { url: url.to_string() }
    }

    fn call(&self, method: &str, params: serde_json::Value) -> R<serde_json::Value> {
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let resp: serde_json::Value = ureq::post(&self.url).send_json(req)?.into_json()?;
        if let Some(err) = resp.get("error") {
            return Err(format!("rpc error: {err}").into());
        }
        Ok(resp.get("result").cloned().unwrap_or(serde_json::Value::Null))
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
        let num = header.get("number").and_then(|n| n.as_str()).ok_or("no header number")?;
        Ok(u32::from_str_radix(num.trim_start_matches("0x"), 16)?)
    }

    pub fn output_count(&self) -> R<u64> {
        let bytes = self.runtime_call("RingCtApi_output_count", &[])?;
        Ok(u64::decode(&mut &bytes[..])?)
    }

    pub fn min_fee_per_byte(&self) -> R<u64> {
        let bytes = self.runtime_call("RingCtApi_min_fee_per_byte", &[])?;
        Ok(u64::decode(&mut &bytes[..])?)
    }

    pub fn is_key_image_spent(&self, key_image: [u8; 32]) -> R<bool> {
        let bytes = self.runtime_call("RingCtApi_is_key_image_spent", &key_image.encode())?;
        Ok(bool::decode(&mut &bytes[..])?)
    }

    /// Fetch every output created in blocks `[from, to]`.
    pub fn outputs_in_range(&self, from: u32, to: u32) -> R<Vec<(u64, StoredOut)>> {
        let bytes = self.runtime_call("RingCtApi_outputs_in_range", &(from, to).encode())?;
        Ok(Decode::decode(&mut &bytes[..])?)
    }

    /// Submit an already-encoded extrinsic; returns the tx hash on success.
    pub fn submit_extrinsic(&self, xt: &[u8]) -> R<String> {
        let hex_xt = format!("0x{}", hex::encode(xt));
        let result = self.call("author_submitExtrinsic", json!([hex_xt]))?;
        Ok(result.as_str().unwrap_or_default().to_string())
    }
}
