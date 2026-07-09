//! Transaction-pool wrapper that hides stem-phase extrinsics from gossip.
//!
//! Stock `sc-network-transactions` only floods transactions for which
//! [`InPoolTransaction::is_propagable`] is true. While a hash is in the
//! Dandelion stem set we report `false`, so the stock handler cannot fluff
//! early. Block production still sees the extrinsic via [`TransactionPool::ready`].

use crate::dandelion::engine::DandelionEngine;
use async_trait::async_trait;
use parking_lot::RwLock;
use sc_transaction_pool_api::{
    ChainEvent, ImportNotificationStream, InPoolTransaction, LocalTransactionFor,
    LocalTransactionPool, MaintainedTransactionPool, PoolStatus, ReadyTransactions, TransactionFor,
    TransactionPool, TransactionSource, TransactionStatusStreamFor, TxHash, TxInvalidityReportMap,
};
use sp_runtime::traits::Block as BlockT;
use std::{collections::HashMap, pin::Pin, sync::Arc, time::Instant};

/// Shared engine handle.
pub type SharedEngine = Arc<RwLock<DandelionEngine>>;

/// Wraps an inner pool and forces `is_propagable == false` for stem hashes.
pub struct StemGate<P> {
    inner: Arc<P>,
    engine: SharedEngine,
}

impl<P> Clone for StemGate<P> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            engine: self.engine.clone(),
        }
    }
}

impl<P> StemGate<P> {
    /// Wrap `inner` with Dandelion stem gating.
    pub fn new(inner: Arc<P>, engine: SharedEngine) -> Self {
        Self { inner, engine }
    }

    fn mark_stem_hash<H: std::fmt::Debug>(&self, hash: &H) {
        let key = format!("{hash:?}");
        self.engine.write().enter_stem(key, None, Instant::now());
    }
}

/// Ready transaction whose propagable bit is ANDed with “not in stem set”.
pub struct GatedTx<T> {
    inner: Arc<T>,
    propagable: bool,
}

impl<T> sc_transaction_pool_api::InPoolTransaction for GatedTx<T>
where
    T: sc_transaction_pool_api::InPoolTransaction,
{
    type Transaction = T::Transaction;
    type Hash = T::Hash;

    fn data(&self) -> &Self::Transaction {
        self.inner.data()
    }
    fn hash(&self) -> &Self::Hash {
        self.inner.hash()
    }
    fn priority(&self) -> &sp_runtime::transaction_validity::TransactionPriority {
        self.inner.priority()
    }
    fn longevity(&self) -> &sp_runtime::transaction_validity::TransactionLongevity {
        self.inner.longevity()
    }
    fn requires(&self) -> &[sp_runtime::transaction_validity::TransactionTag] {
        self.inner.requires()
    }
    fn provides(&self) -> &[sp_runtime::transaction_validity::TransactionTag] {
        self.inner.provides()
    }
    fn is_propagable(&self) -> bool {
        self.propagable && self.inner.is_propagable()
    }
}

struct GatedIter<I> {
    inner: I,
    engine: SharedEngine,
}

impl<I, T> Iterator for GatedIter<I>
where
    I: Iterator<Item = Arc<T>>,
    T: sc_transaction_pool_api::InPoolTransaction,
    T::Hash: std::fmt::Debug,
{
    type Item = Arc<GatedTx<T>>;

    fn next(&mut self) -> Option<Self::Item> {
        let tx = self.inner.next()?;
        let key = format!("{:?}", tx.hash());
        let in_stem = self.engine.read().is_stem(&key);
        Some(Arc::new(GatedTx {
            inner: tx,
            propagable: !in_stem,
        }))
    }
}

impl<I, T> ReadyTransactions for GatedIter<I>
where
    I: Iterator<Item = Arc<T>>,
    T: sc_transaction_pool_api::InPoolTransaction,
    T::Hash: std::fmt::Debug,
{
    fn report_invalid(&mut self, _tx: &Self::Item) {}
}

fn gate_ready<P>(
    engine: SharedEngine,
    iter: Box<dyn ReadyTransactions<Item = Arc<P::InPoolTransaction>> + Send>,
) -> Box<dyn ReadyTransactions<Item = Arc<GatedTx<P::InPoolTransaction>>> + Send>
where
    P: TransactionPool,
    P::InPoolTransaction: 'static,
    <P::InPoolTransaction as sc_transaction_pool_api::InPoolTransaction>::Hash: std::fmt::Debug,
{
    Box::new(GatedIter {
        inner: iter,
        engine,
    })
}

#[async_trait]
impl<P> TransactionPool for StemGate<P>
where
    P: TransactionPool + 'static,
    P::InPoolTransaction: 'static,
    <P::InPoolTransaction as sc_transaction_pool_api::InPoolTransaction>::Hash: std::fmt::Debug,
    P::Hash: std::fmt::Debug,
{
    type Block = P::Block;
    type Hash = P::Hash;
    type InPoolTransaction = GatedTx<P::InPoolTransaction>;
    type Error = P::Error;

    async fn submit_at(
        &self,
        at: <Self::Block as BlockT>::Hash,
        source: TransactionSource,
        xts: Vec<TransactionFor<Self>>,
    ) -> Result<Vec<Result<TxHash<Self>, Self::Error>>, Self::Error> {
        if matches!(source, TransactionSource::Local) {
            for xt in &xts {
                let h = self.inner.hash_of(xt);
                self.mark_stem_hash(&h);
            }
        }
        self.inner.submit_at(at, source, xts).await
    }

    async fn submit_one(
        &self,
        at: <Self::Block as BlockT>::Hash,
        source: TransactionSource,
        xt: TransactionFor<Self>,
    ) -> Result<TxHash<Self>, Self::Error> {
        if matches!(source, TransactionSource::Local) {
            let h = self.inner.hash_of(&xt);
            self.mark_stem_hash(&h);
        }
        self.inner.submit_one(at, source, xt).await
    }

    async fn submit_and_watch(
        &self,
        at: <Self::Block as BlockT>::Hash,
        source: TransactionSource,
        xt: TransactionFor<Self>,
    ) -> Result<Pin<Box<TransactionStatusStreamFor<Self>>>, Self::Error> {
        if matches!(source, TransactionSource::Local) {
            let h = self.inner.hash_of(&xt);
            self.mark_stem_hash(&h);
        }
        self.inner.submit_and_watch(at, source, xt).await
    }

    async fn ready_at(
        &self,
        at: <Self::Block as BlockT>::Hash,
    ) -> Box<dyn ReadyTransactions<Item = Arc<Self::InPoolTransaction>> + Send> {
        gate_ready::<P>(self.engine.clone(), self.inner.ready_at(at).await)
    }

    fn ready(&self) -> Box<dyn ReadyTransactions<Item = Arc<Self::InPoolTransaction>> + Send> {
        gate_ready::<P>(self.engine.clone(), self.inner.ready())
    }

    async fn report_invalid(
        &self,
        at: Option<<Self::Block as BlockT>::Hash>,
        invalid_tx_errors: TxInvalidityReportMap<TxHash<Self>>,
    ) -> Vec<Arc<Self::InPoolTransaction>> {
        let removed = self.inner.report_invalid(at, invalid_tx_errors).await;
        let eng = self.engine.read();
        removed
            .into_iter()
            .map(|tx| {
                let key = format!("{:?}", tx.hash());
                let in_stem = eng.is_stem(&key);
                Arc::new(GatedTx {
                    inner: tx,
                    propagable: !in_stem,
                })
            })
            .collect()
    }

    fn futures(&self) -> Vec<Self::InPoolTransaction> {
        let eng = self.engine.read();
        self.inner
            .futures()
            .into_iter()
            .map(|tx| {
                let key = format!("{:?}", tx.hash());
                let in_stem = eng.is_stem(&key);
                GatedTx {
                    inner: Arc::new(tx),
                    propagable: !in_stem,
                }
            })
            .collect()
    }

    fn status(&self) -> PoolStatus {
        self.inner.status()
    }

    fn import_notification_stream(&self) -> ImportNotificationStream<TxHash<Self>> {
        self.inner.import_notification_stream()
    }

    fn on_broadcasted(&self, propagations: HashMap<TxHash<Self>, Vec<String>>) {
        self.inner.on_broadcasted(propagations)
    }

    fn hash_of(&self, xt: &TransactionFor<Self>) -> TxHash<Self> {
        self.inner.hash_of(xt)
    }

    fn ready_transaction(&self, hash: &TxHash<Self>) -> Option<Arc<Self::InPoolTransaction>> {
        let tx = self.inner.ready_transaction(hash)?;
        let key = format!("{hash:?}");
        let in_stem = self.engine.read().is_stem(&key);
        Some(Arc::new(GatedTx {
            inner: tx,
            propagable: !in_stem,
        }))
    }

    async fn ready_at_with_timeout(
        &self,
        at: <Self::Block as BlockT>::Hash,
        timeout: std::time::Duration,
    ) -> Box<dyn ReadyTransactions<Item = Arc<Self::InPoolTransaction>> + Send> {
        gate_ready::<P>(
            self.engine.clone(),
            self.inner.ready_at_with_timeout(at, timeout).await,
        )
    }
}

#[async_trait]
impl<P> MaintainedTransactionPool for StemGate<P>
where
    P: MaintainedTransactionPool + 'static,
    P::InPoolTransaction: 'static,
    <P::InPoolTransaction as sc_transaction_pool_api::InPoolTransaction>::Hash: std::fmt::Debug,
    P::Hash: std::fmt::Debug,
{
    async fn maintain(&self, event: ChainEvent<Self::Block>) {
        self.inner.maintain(event).await
    }
}

impl<P> LocalTransactionPool for StemGate<P>
where
    P: LocalTransactionPool + 'static,
    <P as LocalTransactionPool>::Hash: std::fmt::Debug,
{
    type Block = <P as LocalTransactionPool>::Block;
    type Hash = <P as LocalTransactionPool>::Hash;
    type Error = <P as LocalTransactionPool>::Error;

    fn submit_local(
        &self,
        at: <Self::Block as BlockT>::Hash,
        xt: LocalTransactionFor<Self>,
    ) -> Result<Self::Hash, Self::Error> {
        let hash = self.inner.submit_local(at, xt)?;
        self.mark_stem_hash(&hash);
        Ok(hash)
    }
}
