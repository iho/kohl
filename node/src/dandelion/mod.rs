//! Dandelion++ transaction diffusion for network-layer origin privacy.
//!
//! ## Why
//!
//! Stock Substrate floods every ready extrinsic to all peers as soon as it
//! lands in the pool. An observer that sits next to many peers can then guess
//! which IP originated a transfer. Dandelion++ (Fanti et al., 2018) breaks
//! that first-hop correlation:
//!
//! 1. **Stem phase** — the transaction is forwarded along a single random path
//!    (one outbound peer per hop). Intermediate nodes look like the origin.
//! 2. **Fluff phase** — with probability `p` a hop switches to ordinary
//!    diffusion (broadcast to every peer). Embargo timers guarantee eventual
//!    fluff if the stem dies.
//!
//! Epochs re-roll the stem routing table so long-lived adversary edges cannot
//! reconstruct the path.
//!
//! ## Integration with Substrate
//!
//! Local submissions enter a **stem set** before the stock gossip loop can
//! see them. While a hash is in that set, [`StemGate`] reports
//! `is_propagable() == false`, so `sc-network-transactions` will not flood it.
//! Stem forwarding uses a dedicated notification protocol
//! (`/kohl/dandelion/1`). Fluff clears the stem bit and lets the ordinary
//! transaction protocol take over.
//!
//! References:
//! - G. Fanti et al., “Dandelion++: Lightweight Cryptocurrency Networking with
//!   Formal Anonymity Guarantees”, ACM SIGMETRICS 2018 / arXiv:1805.11060
//! - Monero’s production Dandelion++ parameters (embargo, epoch, fluff prob.)

mod engine;
mod handler;
mod protocol;
mod stem_gate;

pub use engine::{DandelionConfig, DandelionEngine};
pub use handler::{start_dandelion, DandelionParams};
pub use protocol::{notification_config, protocol_name};
pub use stem_gate::{SharedEngine, StemGate};
