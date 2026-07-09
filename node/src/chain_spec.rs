//! Chain specifications. Genesis carries no balances — a fair launch with
//! zero supply; only the initial PoW difficulty is set (see the runtime's
//! genesis presets).

use kohl_runtime::WASM_BINARY;
use sc_service::ChainType;

pub type ChainSpec = sc_service::GenericChainSpec;

fn wasm() -> Result<&'static [u8], String> {
    WASM_BINARY
        .ok_or_else(|| "kohl runtime WASM not available (build without SKIP_WASM_BUILD)".into())
}

pub fn development_chain_spec() -> Result<ChainSpec, String> {
    Ok(ChainSpec::builder(wasm()?, None)
        .with_name("kohl Development")
        .with_id("dev")
        .with_chain_type(ChainType::Development)
        .with_genesis_config_preset_name("development")
        .build())
}

/// Local multi-node testnet ("kohl-ash") — fair-launch genesis, moderate
/// initial difficulty for multi-miner smoke tests (BLUEPRINT.md Phase 4).
pub fn local_testnet_chain_spec() -> Result<ChainSpec, String> {
    Ok(ChainSpec::builder(wasm()?, None)
        .with_name("kohl-ash Local Testnet")
        .with_id("kohl-ash")
        .with_chain_type(ChainType::Local)
        .with_genesis_config_preset_name("kohl-ash")
        .build())
}

pub fn mainnet_chain_spec() -> Result<ChainSpec, String> {
    Ok(ChainSpec::builder(wasm()?, None)
        .with_name("kohl")
        .with_id("kohl")
        .with_chain_type(ChainType::Live)
        .with_genesis_config_preset_name("mainnet")
        .build())
}
