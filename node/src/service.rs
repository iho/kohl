//! Full-node service assembly for the kohl PoW chain.
//!
//! Differs from a stock Aura/GRANDPA node in three ways:
//! * the executor is extended with the RingCT verification host functions
//!   ([`HostFunctions`]) so the WASM runtime can call them natively;
//! * block import + import queue are `sc-consensus-pow` with our [`KohlPow`]
//!   algorithm;
//! * a CPU mining loop drives `start_mining_worker` (BLAKE2b fallback by
//!   default; RandomX under the `randomx` feature).

use std::{sync::Arc, time::Duration};

use futures::FutureExt;
use kohl_pow::{
    algorithm::{KohlPow, DEFAULT_SEED},
    mining::BlakeHasher,
};
use kohl_runtime::{opaque::Block, RuntimeApi};
use sc_service::{error::Error as ServiceError, Configuration, TaskManager};
use sc_telemetry::{Telemetry, TelemetryWorker};
use sp_runtime::traits::Block as BlockT;

/// Host functions available to the runtime: the standard Substrate set plus
/// the RingCT verifiers (CLSAG / balance / range proof / value commitment).
pub type HostFunctions = (sp_io::SubstrateHostFunctions, ringct_crypto::RingCtHostFunctions);

pub(crate) type FullClient =
    sc_service::TFullClient<Block, RuntimeApi, sc_executor::WasmExecutor<HostFunctions>>;
type FullBackend = sc_service::TFullBackend<Block>;
type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;
type BoxBlockImport = sc_consensus::BoxBlockImport<Block>;

pub type Service = sc_service::PartialComponents<
    FullClient,
    FullBackend,
    FullSelectChain,
    sc_consensus::DefaultImportQueue<Block>,
    sc_transaction_pool::TransactionPoolHandle<Block, FullClient>,
    (BoxBlockImport, Option<Telemetry>),
>;

/// Inherent data providers for block production/verification: just the
/// timestamp. The coinbase inherent is supplied by a mining node that wants
/// to claim rewards (not wired in this minimal dev service).
fn create_inherent_data_providers(
) -> impl sp_inherents::CreateInherentDataProviders<Block, ()> + Clone {
    |_parent, ()| async move {
        Ok(sp_timestamp::InherentDataProvider::from_system_time())
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
        task_manager.spawn_handle().spawn("telemetry", None, worker.run());
        telemetry
    });

    let select_chain = sc_consensus::LongestChain::new(backend.clone());

    let transaction_pool = Arc::from(
        sc_transaction_pool::Builder::new(
            task_manager.spawn_essential_handle(),
            client.clone(),
            config.role.is_authority().into(),
        )
        .with_options(config.transaction_pool.clone())
        .with_prometheus(config.prometheus_registry())
        .build(),
    );

    let algorithm = KohlPow::new(client.clone(), Arc::new(BlakeHasher));

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
        other: (Box::new(pow_block_import), telemetry),
    })
}

pub fn new_full<N: sc_network::NetworkBackend<Block, <Block as BlockT>::Hash>>(
    config: Configuration,
) -> Result<TaskManager, ServiceError> {
    let sc_service::PartialComponents {
        client,
        backend,
        mut task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        other: (block_import, mut telemetry),
    } = new_partial(&config)?;

    let net_config = sc_network::config::FullNetworkConfiguration::<
        Block,
        <Block as BlockT>::Hash,
        N,
    >::new(&config.network, config.prometheus_registry().cloned());
    let metrics = N::register_notification_metrics(config.prometheus_registry());

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

    let role = config.role;
    let prometheus_registry = config.prometheus_registry().cloned();

    let rpc_extensions_builder = {
        let client = client.clone();
        let pool = transaction_pool.clone();
        Box::new(move |_| {
            let deps = crate::rpc::FullDeps { client: client.clone(), pool: pool.clone() };
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

        let algorithm = KohlPow::new(client.clone(), Arc::new(BlakeHasher));

        let (mining_handle, mining_task) = sc_consensus_pow::start_mining_worker(
            block_import,
            client,
            select_chain,
            algorithm,
            proposer_factory,
            sync_service.clone(),
            sync_service.clone(),
            None,
            create_inherent_data_providers(),
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
        // the current build, search nonces with the configured hasher, and
        // submit the first seal that meets difficulty.
        std::thread::Builder::new()
            .name("kohl-cpu-miner".into())
            .spawn(move || {
                let hasher = BlakeHasher;
                let mut nonce_start = 0u64;
                const ROUNDS: u64 = 100_000;
                loop {
                    let Some(metadata) = mining_handle.metadata() else {
                        std::thread::sleep(Duration::from_millis(500));
                        continue;
                    };
                    match kohl_pow::mine(
                        &hasher,
                        metadata.pre_hash.as_ref(),
                        DEFAULT_SEED,
                        metadata.difficulty,
                        nonce_start,
                        ROUNDS,
                    ) {
                        Some(seal) => {
                            futures::executor::block_on(
                                mining_handle.submit(seal.encode_seal()),
                            );
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
