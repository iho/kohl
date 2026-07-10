//! FCMP / RingCT host capability for operators (PR-9).
//!
//! The runtime calls expensive RingCT crypto through native host functions
//! (`ringct_crypto::RingCtHostFunctions`). Shipping a runtime that imports a
//! host fn the node binary does not provide causes import failure or panics
//! at verification — not a soft degrade.
//!
//! **Policy (pre-launch, design rev 6):**
//! - Spend path is **FCMP-only** (`fcmp_mode = 2`). There is **no Dual**
//!   height matrix and no mainnet CLSAG coexistence.
//! - Ship **node binary first**, then runtime that depends on new host ABIs.
//! - Keep the matrix in this module and [`docs/fcmp-runbook.md`] in sync.
//!
//! See BLUEPRINT.md §1.6 and `docs/fcmp-design.md` D10 / operator runbook.

/// One row of the host/runtime compatibility matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostCapabilityRow {
    /// Runtime `spec_version` this row describes.
    pub spec_version: u32,
    /// Minimum `kohl-node` package version that registers the required hosts.
    pub min_node_version: &'static str,
    /// Human label for operators (e.g. interim FCMP0001).
    pub note: &'static str,
}

/// Current matrix. Append rows when bumping `spec_version` or host ABIs;
/// never rewrite historical rows after a public network freezes on them.
pub const HOST_CAPABILITY_MATRIX: &[HostCapabilityRow] = &[HostCapabilityRow {
    spec_version: 1,
    min_node_version: "0.1.0",
    note: "FCMP-only spends (FCMP0001); Path A tree; no Dual",
}];

/// Logical host entrypoints the **block-import / authorize** path needs for
/// `spec_version` 1 (names match `RingctCrypto` trait methods).
///
/// Benchmark-only hosts (`prove_range_v1`, `fcmp_prove_v1`, RNG helpers) are
/// listed separately so a pure validator build still knows the consensus set.
pub const REQUIRED_CONSENSUS_HOST_FNS: &[&str] = &[
    "verify_balance_v1",
    "verify_range_proof_v1",
    "value_commitment_v1",
    "verify_fcmp_v1",
    "is_valid_point_v1",
];

/// Host entrypoints used by runtime benchmarks / weight generation, not by
/// ordinary block import. Still registered on the stock `kohl` binary.
pub const BENCHMARK_HOST_FNS: &[&str] = &[
    "random_secret_key_v1",
    "random_blinding_v1",
    "commit_v1",
    "key_image_v1",
    "prove_range_v1",
    "fcmp_prove_v1",
];

/// Legacy CLSAG host still registered (FCMP0001 SA+L is verified inside
/// `verify_fcmp_v1` natively). Runtime **transfer** does not call this after
/// PR-7; listed so operators know the binary still exports it.
pub const LEGACY_REGISTERED_HOST_FNS: &[&str] = &["verify_clsag_v1"];

/// Spend-path mode constant exposed by the runtime API (`fcmp_mode`).
pub const FCMP_MODE_FCMP_ONLY: u8 = 2;

/// Look up the matrix row for a runtime `spec_version`.
pub fn row_for_spec(spec_version: u32) -> Option<&'static HostCapabilityRow> {
    HOST_CAPABILITY_MATRIX
        .iter()
        .rev()
        .find(|r| r.spec_version == spec_version)
}

/// Log host capability once at service construction so journald / node logs
/// show whether this binary is intended for the connected runtime.
pub fn log_startup_capability() {
    let node_ver = env!("CARGO_PKG_VERSION");
    let row = HOST_CAPABILITY_MATRIX
        .last()
        .expect("HOST_CAPABILITY_MATRIX is non-empty");

    log::info!(
        target: "kohl",
        "RingCT/FCMP host capability: node_version={node_ver} \
         matrix_spec_version={} min_node={} ({})",
        row.spec_version,
        row.min_node_version,
        row.note,
    );
    log::info!(
        target: "kohl",
        "FCMP spend path: FcmpOnly (mode={FCMP_MODE_FCMP_ONLY}); Dual HF matrix: none (out of scope)",
    );
    log::info!(
        target: "kohl",
        "Required consensus host fns (RingctCrypto): {}",
        REQUIRED_CONSENSUS_HOST_FNS.join(", "),
    );
    log::debug!(
        target: "kohl",
        "Also registered: legacy={} benchmark={}",
        LEGACY_REGISTERED_HOST_FNS.join(", "),
        BENCHMARK_HOST_FNS.join(", "),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_covers_spec_version_1() {
        let row = row_for_spec(1).expect("spec_version 1 row");
        assert_eq!(row.min_node_version, "0.1.0");
        assert!(row.note.contains("FCMP-only") || row.note.contains("FCMP"));
    }

    #[test]
    fn consensus_hosts_include_fcmp() {
        assert!(REQUIRED_CONSENSUS_HOST_FNS.contains(&"verify_fcmp_v1"));
        assert!(REQUIRED_CONSENSUS_HOST_FNS.contains(&"verify_balance_v1"));
        assert!(REQUIRED_CONSENSUS_HOST_FNS.contains(&"verify_range_proof_v1"));
        // Production transfer path must not depend on CLSAG host after PR-7.
        assert!(!REQUIRED_CONSENSUS_HOST_FNS.contains(&"verify_clsag_v1"));
    }

    #[test]
    fn no_empty_capability_lists() {
        assert!(!HOST_CAPABILITY_MATRIX.is_empty());
        assert!(!REQUIRED_CONSENSUS_HOST_FNS.is_empty());
    }
}
