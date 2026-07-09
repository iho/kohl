//! CLI command dispatch.

use crate::{
    chain_spec,
    cli::{Cli, Subcommand},
    service,
};
use kohl_runtime::opaque::Block;
use sc_cli::SubstrateCli;
use sc_service::PartialComponents;
use sp_runtime::traits::Block as BlockT;

impl SubstrateCli for Cli {
    fn impl_name() -> String {
        "kohl node".into()
    }
    fn impl_version() -> String {
        env!("CARGO_PKG_VERSION").into()
    }
    fn description() -> String {
        env!("CARGO_PKG_DESCRIPTION").into()
    }
    fn author() -> String {
        env!("CARGO_PKG_AUTHORS").into()
    }
    fn support_url() -> String {
        "https://github.com/kohl-chain/kohl".into()
    }
    fn copyright_start_year() -> i32 {
        2026
    }

    fn load_spec(&self, id: &str) -> Result<Box<dyn sc_service::ChainSpec>, String> {
        Ok(match id {
            "dev" | "" => Box::new(chain_spec::development_chain_spec()?),
            "kohl-ash" | "local" => Box::new(chain_spec::local_testnet_chain_spec()?),
            "kohl" | "mainnet" => Box::new(chain_spec::mainnet_chain_spec()?),
            path => Box::new(chain_spec::ChainSpec::from_json_file(std::path::PathBuf::from(path))?),
        })
    }
}

/// Parse and run command-line arguments.
pub fn run() -> sc_cli::Result<()> {
    let cli = Cli::from_args();

    match &cli.subcommand {
        Some(Subcommand::Key(cmd)) => cmd.run(&cli),
        Some(Subcommand::ExportChainSpec(cmd)) => {
            let spec = cli.load_spec(&cmd.chain)?;
            cmd.run(spec)
        }
        Some(Subcommand::CheckBlock(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.async_run(|config| {
                let PartialComponents { client, task_manager, import_queue, .. } =
                    service::new_partial(&config)?;
                Ok((cmd.run(client, import_queue), task_manager))
            })
        }
        Some(Subcommand::ExportBlocks(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.async_run(|config| {
                let PartialComponents { client, task_manager, .. } =
                    service::new_partial(&config)?;
                Ok((cmd.run(client, config.database), task_manager))
            })
        }
        Some(Subcommand::ExportState(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.async_run(|config| {
                let PartialComponents { client, task_manager, .. } =
                    service::new_partial(&config)?;
                Ok((cmd.run(client, config.chain_spec), task_manager))
            })
        }
        Some(Subcommand::ImportBlocks(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.async_run(|config| {
                let PartialComponents { client, task_manager, import_queue, .. } =
                    service::new_partial(&config)?;
                Ok((cmd.run(client, import_queue), task_manager))
            })
        }
        Some(Subcommand::PurgeChain(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.sync_run(|config| cmd.run(config.database))
        }
        Some(Subcommand::Revert(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.async_run(|config| {
                let PartialComponents { client, task_manager, backend, .. } =
                    service::new_partial(&config)?;
                // No justification/aux revert hook: PoW has no GRANDPA.
                let aux_revert = Box::new(|_, _, _| Ok(()));
                Ok((cmd.run(client, backend, Some(aux_revert)), task_manager))
            })
        }
        None => {
            let mining_seed = parse_mining_seed(cli.mining_seed.as_deref())?;
            let runner = cli.create_runner(&cli.run)?;
            runner.run_node_until_exit(|config| async move {
                let mining = service::MiningConfig { mining_seed };
                match config.network.network_backend {
                    sc_network::config::NetworkBackendType::Libp2p => service::new_full::<
                        sc_network::NetworkWorker<Block, <Block as BlockT>::Hash>,
                    >(config, mining)
                    .map_err(sc_cli::Error::Service),
                    sc_network::config::NetworkBackendType::Litep2p => {
                        service::new_full::<sc_network::Litep2pNetworkBackend>(config, mining)
                            .map_err(sc_cli::Error::Service)
                    }
                }
            })
        }
    }
}

/// Parse `--mining-seed` as 32 raw bytes (64 hex chars, optional 0x).
fn parse_mining_seed(raw: Option<&str>) -> sc_cli::Result<Option<[u8; 32]>> {
    let Some(s) = raw else {
        return Ok(None);
    };
    let hex = s.trim().trim_start_matches("0x");
    let bytes = hex::decode(hex).map_err(|e| sc_cli::Error::Input(format!("mining-seed: {e}")))?;
    if bytes.len() != 32 {
        return Err(sc_cli::Error::Input(format!(
            "mining-seed must be 32 bytes (64 hex chars), got {}",
            bytes.len()
        )));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(Some(seed))
}
