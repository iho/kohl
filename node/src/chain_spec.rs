//! Chain specifications. Genesis carries no balances — a fair launch with
//! zero supply; only the initial PoW difficulty is set (see the runtime's
//! genesis presets).
//!
//! **FCMP-only (PR-9 / design rev 6):** every preset starts an economic history
//! where spends are full-chain membership (`fcmp_mode = 2`). There is no Dual
//! schedule, no CLSAG activation height, and no genesis flag to re-enable rings.
//! Operators: `docs/fcmp-runbook.md`, `chainspecs/README.md`.

use kohl_runtime::WASM_BINARY;
use sc_service::ChainType;

pub type ChainSpec = sc_service::GenericChainSpec;

fn wasm() -> Result<&'static [u8], String> {
    WASM_BINARY
        .ok_or_else(|| "kohl runtime WASM not available (build without SKIP_WASM_BUILD)".into())
}

/// Single-machine dev chain. Fair launch + FCMP-only spends; wipe freely.
pub fn development_chain_spec() -> Result<ChainSpec, String> {
    Ok(ChainSpec::builder(wasm()?, None)
        .with_name("kohl Development")
        .with_id("dev")
        .with_chain_type(ChainType::Development)
        .with_genesis_config_preset_name("development")
        .build())
}

/// Local multi-node testnet ("kohl-ash") — fair-launch FCMP-only genesis,
/// moderate initial difficulty for multi-miner smoke / soak (BLUEPRINT Phase 4).
/// Throwaway: re-genesis over Dual migration (`docs/fcmp-soak-report.md`).
pub fn local_testnet_chain_spec() -> Result<ChainSpec, String> {
    Ok(ChainSpec::builder(wasm()?, None)
        .with_name("kohl-ash Local Testnet")
        .with_id("kohl-ash")
        .with_chain_type(ChainType::Local)
        .with_genesis_config_preset_name("kohl-ash")
        .build())
}

/// Mainnet: fair launch, FCMP-only, high initial difficulty.
/// Encoding freeze: `docs/fcmp-mainnet-freeze.md` (PR-10). External audit: PR-11.
pub fn mainnet_chain_spec() -> Result<ChainSpec, String> {
    Ok(ChainSpec::builder(wasm()?, None)
        .with_name("kohl")
        .with_id("kohl")
        .with_chain_type(ChainType::Live)
        .with_genesis_config_preset_name("mainnet")
        .build())
}
