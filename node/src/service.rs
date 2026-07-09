//! Full-node service assembly for the kohl PoW chain.
//!
//! Differs from a stock Aura/GRANDPA node in four ways:
//! * the executor is extended with the RingCT verification host functions
//!   ([`HostFunctions`]) so the WASM runtime can call them natively;
//! * block import + import queue are `sc-consensus-pow` with our [`KohlPow`]
//!   algorithm (epoch-rotating seed from lagged block hashes);
//! * a CPU mining loop drives `start_mining_worker` (BLAKE2b fallback by
//!   default; RandomX under the `randomx` feature);
//! * Dandelion++ stem-phase gossip hides the origin IP of transfers before
//!   ordinary transaction flood (see [`crate::dandelion`]).

use std::{sync::Arc, time::Duration};

use futures::FutureExt;
use kohl_pow::{algorithm::seed_for_parent, mining::BlakeHasher, Hasher, KohlPow};
use kohl_runtime::{opaque::Block, RuntimeApi};
use parking_lot::RwLock;
use sc_service::{error::Error as ServiceError, Configuration, TaskManager};
use sc_telemetry::{Telemetry, TelemetryWorker};
use sp_runtime::traits::Block as BlockT;

use crate::dandelion::{self, DandelionConfig, DandelionEngine, SharedEngine, StemGate};
use sp_blockchain::HeaderBackend;

#[cfg(feature = "randomx")]
use kohl_pow::RandomXHasher;

/// Build the PoW hasher: RandomX when the node is compiled with `--features
/// randomx`, otherwise the BLAKE2b dev fallback (still uses epoch seeds).
fn pow_hasher() -> Arc<dyn Hasher + Send + Sync> {
    #[cfg(feature = "randomx")]
    {
        // Initial seed is the genesis domain; the hasher rebuilds its VM when
        // `hash()` is called with a different epoch seed.
        match RandomXHasher::new(kohl_pow::DEFAULT_SEED) {
            Ok(h) => {
                log::info!(target: "kohl", "PoW hasher: RandomX (epoch-rotating seed)");
                return Arc::new(h);
            }
            Err(e) => {
                log::error!(
                    target: "kohl",
                    "RandomX init failed ({e}); falling back to BLAKE2b dev hasher"
                );
            }
        }
    }
    #[cfg(not(feature = "randomx"))]
    log::info!(target: "kohl", "PoW hasher: BLAKE2b dev fallback (build with --features randomx for RandomX)");
    Arc::new(BlakeHasher)
}

/// Host functions available to the runtime: the standard Substrate set plus
/// the RingCT verifiers (CLSAG / balance / range proof / value commitment).
pub type HostFunctions = (
    sp_io::SubstrateHostFunctions,
    ringct_crypto::RingCtHostFunctions,
);

pub(crate) type FullClient =
    sc_service::TFullClient<Block, RuntimeApi, sc_executor::WasmExecutor<HostFunctions>>;
type FullBackend = sc_service::TFullBackend<Block>;
type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;
type BoxBlockImport = sc_consensus::BoxBlockImport<Block>;

/// Pool type used by the node: stock Substrate pool gated by Dandelion++ stem state.
pub type FullPool = StemGate<sc_transaction_pool::TransactionPoolHandle<Block, FullClient>>;

pub type Service = sc_service::PartialComponents<
    FullClient,
    FullBackend,
    FullSelectChain,
    sc_consensus::DefaultImportQueue<Block>,
    FullPool,
    (BoxBlockImport, Option<Telemetry>, SharedEngine),
>;

/// Optional 32-byte mining seed: when set, coinbase rewards go to the
/// deterministic stealth address derived from it (wallet-scannable).
pub struct MiningConfig {
    pub mining_seed: Option<[u8; 32]>,
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Verification-side inherent data providers: just the timestamp. The
/// coinbase inherent found in a block is validated by dispatch (its amount
/// must equal reward + fees), so the importer needs no coinbase data.
fn create_inherent_data_providers(
) -> impl sp_inherents::CreateInherentDataProviders<Block, ()> + Clone {
    |_parent, ()| async move { Ok(sp_timestamp::InherentDataProvider::from_system_time()) }
}

/// Supplies the coinbase inherent: the miner's payout destination. A fresh
/// one-time stealth key + tx pubkey per block, derived to `miner_address`
/// (so the reward is scannable with the miner's view key and spendable with
/// its spend key). The reward *amount* is computed by the runtime.
struct CoinbaseProvider {
    one_time_key: [u8; 32],
    tx_pubkey: [u8; 32],
    view_tag: u8,
}

#[async_trait::async_trait]
impl sp_inherents::InherentDataProvider for CoinbaseProvider {
    async fn provide_inherent_data(
        &self,
        inherent_data: &mut sp_inherents::InherentData,
    ) -> Result<(), sp_inherents::Error> {
        inherent_data.put_data(
            pallet_ringct::INHERENT_IDENTIFIER,
            &(self.one_time_key, self.tx_pubkey, self.view_tag),
        )
    }

    async fn try_handle_error(
        &self,
        _identifier: &sp_inherents::InherentIdentifier,
        _error: &[u8],
    ) -> Option<Result<(), sp_inherents::Error>> {
        None
    }
}

/// Production-side inherent data providers for a miner: timestamp + a fresh
/// coinbase payout to `miner_address`.
fn mining_inherent_data_providers(
    miner_address: ringct_crypto::stealth::StealthAddress,
) -> impl sp_inherents::CreateInherentDataProviders<Block, ()> + Clone {
    move |_parent, ()| async move {
        use ringct_crypto::stealth;
        let (tx_secret, tx_pubkey) = stealth::tx_keypair();
        // Derive a one-time key for output index 0 of this coinbase tx.
        let coinbase = stealth::sender_shared_secret(&tx_secret, &miner_address.view_public)
            .and_then(|shared| {
                stealth::derive_one_time_key(&shared, &miner_address.spend_public, 0)
            })
            .map(|(one_time_key, view_tag)| CoinbaseProvider {
                one_time_key,
                tx_pubkey,
                view_tag,
            })
            .ok_or_else(|| sp_inherents::Error::Application(Box::from("invalid miner address")))?;
        Ok((
            sp_timestamp::InherentDataProvider::from_system_time(),
            coinbase,
        ))
    }
}

pub fn new_partial(config: &Configuration) -> Result<Service, ServiceError> {
    let telemetry = config
        .telemetry_endpoints
        .clone()
        .filter(|x| !x.is_empty())
        .map(|endpoints| -> Result<_, sc_telemetry::Error> {
            let worker = TelemetryWorker::new(16)?;
            let telemetry = worker.handle().new_telemetry(endpoints);
            Ok((worker, telemetry))
        })
        .transpose()?;

    let executor = sc_service::new_wasm_executor::<HostFunctions>(&config.executor);

    let (client, backend, keystore_container, task_manager) =
        sc_service::new_full_parts::<Block, RuntimeApi, _>(
            config,
            telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
            executor,
            Vec::new(),
        )?;
    let client = Arc::new(client);

    let telemetry = telemetry.map(|(worker, telemetry)| {
        task_manager
            .spawn_handle()
            .spawn("telemetry", None, worker.run());
        telemetry
    });

    let select_chain = sc_consensus::LongestChain::new(backend.clone());

    let inner_pool = Arc::from(
        sc_transaction_pool::Builder::new(
            task_manager.spawn_essential_handle(),
            client.clone(),
            config.role.is_authority().into(),
        )
        .with_options(config.transaction_pool.clone())
        .with_prometheus(config.prometheus_registry())
        .build(),
    );

    // Dandelion++ engine: local node id is a process-local random label used
    // only to seed epoch fluff/outbound choices (not a network identity).
    let local_label = format!("kohl-{}", hex(&rand_label()));
    let dandelion_engine = Arc::new(RwLock::new(DandelionEngine::new(
        DandelionConfig::default(),
        local_label,
    )));
    let transaction_pool = Arc::new(StemGate::new(inner_pool, dandelion_engine.clone()));

    let algorithm = KohlPow::new(client.clone(), pow_hasher());

    let pow_block_import = sc_consensus_pow::PowBlockImport::new(
        client.clone(),
        client.clone(),
        algorithm.clone(),
        0,
        select_chain.clone(),
        create_inherent_data_providers(),
    );

    let import_queue = sc_consensus_pow::import_queue(
        Box::new(pow_block_import.clone()),
        None,
        algorithm,
        &task_manager.spawn_essential_handle(),
        config.prometheus_registry(),
    )?;

    Ok(sc_service::PartialComponents {
        client,
        backend,
        task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        other: (Box::new(pow_block_import), telemetry, dandelion_engine),
    })
}

fn rand_label() -> [u8; 32] {
    // Cheap process-local entropy without a new RNG dependency.
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&t.to_le_bytes());
    // Mix in the stack address so two nodes started in the same nanosecond differ.
    let addr = &bytes as *const _ as usize;
    bytes[16..24].copy_from_slice(&(addr as u64).to_le_bytes());
    bytes
}

pub fn new_full<N: sc_network::NetworkBackend<Block, <Block as BlockT>::Hash>>(
    config: Configuration,
    mining: MiningConfig,
) -> Result<TaskManager, ServiceError> {
    let sc_service::PartialComponents {
        client,
        backend,
        mut task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        other: (block_import, mut telemetry, dandelion_engine),
    } = new_partial(&config)?;

    let mut net_config = sc_network::config::FullNetworkConfiguration::<
        Block,
        <Block as BlockT>::Hash,
        N,
    >::new(&config.network, config.prometheus_registry().cloned());
    let metrics = N::register_notification_metrics(config.prometheus_registry());

    // Register Dandelion++ stem protocol before the network is built so peers
    // negotiate the substream alongside the stock transactions protocol.
    let genesis_hash = client.info().genesis_hash;
    let (dandelion_cfg, dandelion_notifications) = dandelion::notification_config::<Block, N>(
        genesis_hash.as_ref(),
        config.chain_spec.fork_id(),
        metrics.clone(),
        net_config.peer_store_handle(),
    );
    net_config.add_notification_protocol(dandelion_cfg);
    let dandelion_protocol_name =
        dandelion::protocol_name(genesis_hash.as_ref(), config.chain_spec.fork_id());

    let (network, system_rpc_tx, tx_handler_controller, sync_service) =
        sc_service::build_network(sc_service::BuildNetworkParams {
            config: &config,
            net_config,
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            spawn_handle: task_manager.spawn_handle(),
            spawn_essential_handle: task_manager.spawn_essential_handle(),
            import_queue,
            block_announce_validator_builder: None,
            warp_sync_config: None,
            block_relay: None,
            metrics,
        })?;

    // Dandelion++ worker: stem relay + embargo-driven fluff (stem bit clear).
    {
        let params = dandelion::DandelionParams {
            engine: dandelion_engine,
            notifications: dandelion_notifications,
            protocol_name: dandelion_protocol_name,
            network: network.clone(),
            sync: sync_service.clone(),
            client: client.clone(),
            pool: transaction_pool.clone(),
            tick: Duration::from_secs(1),
        };
        task_manager.spawn_handle().spawn(
            "kohl-dandelion",
            Some("networking"),
            dandelion::start_dandelion(params),
        );
    }

    let role = config.role;
    let prometheus_registry = config.prometheus_registry().cloned();

    let rpc_extensions_builder = {
        let client = client.clone();
        let pool = transaction_pool.clone();
        Box::new(move |_| {
            let deps = crate::rpc::FullDeps {
                client: client.clone(),
                pool: pool.clone(),
            };
            crate::rpc::create_full(deps).map_err(Into::into)
        })
    };

    let _rpc_handlers = sc_service::spawn_tasks(sc_service::SpawnTasksParams {
        network: Arc::new(network.clone()),
        client: client.clone(),
        keystore: keystore_container.keystore(),
        task_manager: &mut task_manager,
        transaction_pool: transaction_pool.clone(),
        rpc_builder: rpc_extensions_builder,
        backend,
        system_rpc_tx,
        tx_handler_controller,
        sync_service: sync_service.clone(),
        config,
        telemetry: telemetry.as_mut(),
        tracing_execute_block: None,
    })?;

    if role.is_authority() {
        let proposer_factory = sc_basic_authorship::ProposerFactory::new(
            task_manager.spawn_handle(),
            client.clone(),
            transaction_pool.clone(),
            prometheus_registry.as_ref(),
            telemetry.as_ref().map(|x| x.handle()),
        );

        let hasher = pow_hasher();
        let algorithm = KohlPow::new(client.clone(), hasher.clone());

        // Miner payout address: deterministic from --mining-seed when set,
        // otherwise a throwaway keypair for this process.
        let (miner_keys, miner_address) = match mining.mining_seed {
            Some(seed) => {
                let pair = ringct_crypto::stealth::keypair_from_seed(&seed);
                log::info!(
                    target: "kohl",
                    "⛏  Mining rewards → seed-derived address (kohl:{}{})",
                    hex(&pair.1.view_public),
                    hex(&pair.1.spend_public),
                );
                pair
            }
            None => {
                let pair = ringct_crypto::stealth::keypair();
                log::warn!(
                    target: "kohl",
                    "⛏  No --mining-seed: throwaway payout keys this run \
                     (view_secret={}, spend_secret={}). Pass --mining-seed \
                     <64-hex> for a persistent address the wallet can scan.",
                    hex(&pair.0.view_secret),
                    hex(&pair.0.spend_secret),
                );
                pair
            }
        };
        // Silence unused when seed-derived (secrets stay offline in the wallet).
        let _ = miner_keys;

        let (mining_handle, mining_task) = sc_consensus_pow::start_mining_worker(
            block_import,
            client.clone(),
            select_chain,
            algorithm,
            proposer_factory,
            sync_service.clone(),
            sync_service.clone(),
            None,
            mining_inherent_data_providers(miner_address),
            Duration::from_secs(10),
            Duration::from_secs(10),
        );

        task_manager.spawn_essential_handle().spawn_blocking(
            "pow-mining-worker",
            Some("pow"),
            mining_task.boxed(),
        );

        // The CPU miner runs on a dedicated OS thread: `MiningHandle::submit`
        // holds a non-`Send` lock across an await, so it cannot run on the
        // shared async pool — we drive it with `block_on` here instead. Poll
        // the current build, resolve the epoch seed from the parent header,
        // search nonces, and submit the first seal that meets difficulty.
        std::thread::Builder::new()
            .name("kohl-cpu-miner".into())
            .spawn(move || {
                let mut nonce_start = 0u64;
                const ROUNDS: u64 = 100_000;
                loop {
                    let Some(metadata) = mining_handle.metadata() else {
                        std::thread::sleep(Duration::from_millis(500));
                        continue;
                    };
                    // Same seed the importer will recompute in KohlPow::verify.
                    let seed = match seed_for_parent::<Block, _>(&*client, metadata.best_hash) {
                        Ok(s) => s,
                        Err(e) => {
                            log::warn!(target: "kohl", "epoch seed resolve failed: {e}");
                            std::thread::sleep(Duration::from_millis(500));
                            continue;
                        }
                    };
                    match kohl_pow::mine(
                        &*hasher,
                        metadata.pre_hash.as_ref(),
                        &seed,
                        metadata.difficulty,
                        nonce_start,
                        ROUNDS,
                    ) {
                        Some(seal) => {
                            futures::executor::block_on(mining_handle.submit(seal.encode_seal()));
                            nonce_start = 0;
                        }
                        None => nonce_start = nonce_start.wrapping_add(ROUNDS),
                    }
                }
            })
            .expect("spawn kohl-cpu-miner thread");
    }

    Ok(task_manager)
}
