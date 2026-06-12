//! Node assembly: shared state, block production loop, RPC server lifecycle.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result};
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;

use crate::chain::Chain;
use crate::config::NodeConfig;
use crate::executor;
use crate::genesis;
use crate::hook::SecurityHook;
use crate::mempool::Mempool;

pub struct NodeHandle {
    pub rpc_addr: SocketAddr,
    pub chain: Arc<Mutex<Chain>>,
    pub mempool: Arc<Mutex<Mempool>>,
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl NodeHandle {
    /// Signal both the RPC server and the block producer to stop, then join them.
    pub async fn shutdown(mut self) {
        let _ = self.shutdown.send(true);
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Boot the devnet: genesis state, mempool with the given hook, RPC server,
/// and the interval block producer.
pub async fn start(config: NodeConfig, hook: Arc<dyn SecurityHook>) -> Result<NodeHandle> {
    let chain = Arc::new(Mutex::new(Chain::new(
        config.chain_id,
        genesis::genesis_alloc(),
    )));
    let mempool = Arc::new(Mutex::new(Mempool::new()));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // --- JSON-RPC server -------------------------------------------------
    let router = crate::rpc::router(chain.clone(), mempool.clone(), hook, config.chain_id);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", config.rpc_port))
        .await
        .context("binding RPC listener")?;
    let rpc_addr = listener.local_addr()?;

    let mut rpc_shutdown = shutdown_rx.clone();
    let rpc_task = tokio::spawn(async move {
        let serve = axum::serve(listener, router).with_graceful_shutdown(async move {
            // `changed()` (unlike `wait_for`) returns a Send future.
            while rpc_shutdown.changed().await.is_ok() {
                if *rpc_shutdown.borrow() {
                    break;
                }
            }
        });
        if let Err(err) = serve.await {
            tracing::error!(%err, "rpc server terminated abnormally");
        }
    });

    // --- Block producer ---------------------------------------------------
    let producer_chain = chain.clone();
    let producer_pool = mempool.clone();
    let mut producer_shutdown = shutdown_rx;
    let block_time = Duration::from_secs(config.block_time_secs);
    let producer_task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(block_time);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let txs = producer_pool.lock().await.drain();
                    let tx_count = txs.len();
                    let mut chain = producer_chain.lock().await;
                    match executor::execute_block(&mut chain, txs, unix_now()) {
                        Ok(block) => tracing::info!(
                            number = block.number,
                            hash = %block.hash,
                            txs = tx_count,
                            "block produced"
                        ),
                        Err(err) => tracing::error!(%err, "block production failed"),
                    }
                }
                changed = producer_shutdown.changed() => {
                    if changed.is_err() || *producer_shutdown.borrow() {
                        break;
                    }
                }
            }
        }
        tracing::info!("block producer stopped");
    });

    tracing::info!(
        chain_id = config.chain_id,
        rpc = %rpc_addr,
        block_time_secs = config.block_time_secs,
        "helix-node devnet started"
    );

    Ok(NodeHandle {
        rpc_addr,
        chain,
        mempool,
        shutdown: shutdown_tx,
        tasks: vec![rpc_task, producer_task],
    })
}
