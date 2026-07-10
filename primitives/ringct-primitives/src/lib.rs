//! Consensus constants and the emission schedule for the kohl chain.
//!
//! Everything in this crate is consensus-critical: changing any value is a
//! hard fork. See BLUEPRINT.md §8 for the economic rationale.

#![cfg_attr(not(feature = "std"), no_std)]

/// Atomic units per 1 KOHL.
pub const ATOMIC_UNITS: u64 = 100_000_000;

/// Supply targeted by the decaying emission curve (the tail emission then
/// continues forever, so total supply keeps growing slowly past this point).
pub const MAX_CURVE_SUPPLY: u64 = 92_000_000 * ATOMIC_UNITS;

/// Perpetual tail reward per block: 0.3 KOHL.
pub const TAIL_REWARD: u64 = 3 * ATOMIC_UNITS / 10;

/// Right-shift applied to the remaining curve supply per block.
pub const EMISSION_SHIFT: u32 = 19;

/// Target block time in milliseconds (RandomX PoW target, Phase 4).
pub const TARGET_BLOCK_TIME_MS: u64 = 60_000;

/// Maximum inputs per transfer (legacy alias ceiling; production uses
/// [`MAX_FCMP_INPUTS`]).
pub const MAX_INPUTS: u32 = 8;

/// Maximum outputs per transfer (and per coinbase).
pub const MAX_OUTPUTS: u32 = 8;

/// Historical CLSAG ring-size ceiling. Production spends are FCMP-only
/// (PR-7/PR-10); FCMP0001 SA+L may still use CLSAG over up to
/// [`MAX_FCMP_ANON_SET`] members inside the host. Not a wallet ring parameter.
pub const MAX_RING_SIZE: u32 = 16;

/// Maximum encoded size of a CLSAG signature at [`MAX_RING_SIZE`]:
/// c0 (32) + one scalar per ring member (32·n) + auxiliary key image D (32).
/// FCMP0001 uses a larger host-side ring bound (`MAX_FCMP_ANON_SET`).
pub const CLSAG_MAX_BYTES: u32 = 32 * (MAX_RING_SIZE + 2);

/// Maximum encoded size of an aggregated range proof.
/// An n=64-bit proof aggregating m parties is (9 + 2·log2(64·m))·32 bytes;
/// for m = 8 that is 864 bytes.
pub const MAX_RANGE_PROOF_BYTES: u32 = 1024;

/// Maximum opaque per-output wallet payload (encrypted amount + blinding;
/// format finalized with stealth-address ECDH in Phase 3).
pub const MAX_PAYLOAD_BYTES: u32 = 80;

// ---- FCMP Path A membership tree (PR-1 scaffolding; consensus-critical) ----

/// Max `EMPTY → L(P,C)` fills per block (finalize; never shared with live grow).
pub const FCMP_ADMIT_MAX_LEAVES_PER_BLOCK: u32 = 64;

/// Max sequential catch-up `grow EMPTY` ops per block while lagging.
pub const FCMP_GROW_CATCHUP_MAX_PER_BLOCK: u32 = 64;

/// How long historical membership roots are retained for wallet anchoring.
pub const FCMP_ROOT_MAX_AGE_BLOCKS: u32 = 64;

/// Occupied-leaf preimage domain: `LEAF_DOM || P || C`.
pub const FCMP_LEAF_DOM: &[u8] = b"kohl/fcmp/leaf/v1";

/// Immature / not-yet-admitted leaf placeholder domain.
pub const FCMP_EMPTY_LEAF_DOM: &[u8] = b"kohl/fcmp/leaf/empty/v1";

/// Internal Merkle node domain: `MERKLE_DOM || left || right`.
pub const FCMP_MERKLE_DOM: &[u8] = b"kohl/fcmp/merkle/v1";

/// Missing child beyond `TreeSlots` (depth padding).
pub const FCMP_MERKLE_EMPTY_DOM: &[u8] = b"kohl/fcmp/merkle/v1/empty";

// ---- Mainnet encoding freeze (PR-10) ------------------------------------
// Values below are frozen for the FCMP0001 mainnet-candidate. Changing them
// is a hard fork — update docs/fcmp-mainnet-freeze.md and bump runtime
// versions in the same change. See `tests::mainnet_encoding_freeze_snapshot`.

/// Max FCMP inputs per tx (design D15 / PR-10 freeze).
pub const MAX_FCMP_INPUTS: u32 = 4;

/// Max FCMP proof size per input (12 KiB; design D15 / PR-10 freeze).
/// Hard D2 gate is 16 KiB; keep headroom under 300 KiB blocks.
pub const MAX_FCMP_PROOF_BYTES: u32 = 12_288;

/// Max mature-set size for FCMP0001 full-set membership under the Merkle root.
/// Proof packs digests + ring + CLSAG; 64 fits in [`MAX_FCMP_PROOF_BYTES`].
/// Larger trees need Curve Trees / Path B (or a later IPA composition).
pub const MAX_FCMP_ANON_SET: u32 = 64;

/// Block reward as a function of coins emitted so far:
/// `max(TAIL_REWARD, (MAX_CURVE_SUPPLY - emitted) >> EMISSION_SHIFT)`.
///
/// Monero-style smooth curve — front-loaded, decade-scale distribution,
/// perpetual tail for the security budget.
pub const fn block_reward(emitted: u64) -> u64 {
    let curve = MAX_CURVE_SUPPLY.saturating_sub(emitted) >> EMISSION_SHIFT;
    if curve > TAIL_REWARD {
        curve
    } else {
        TAIL_REWARD
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PR-10 freeze snapshot — fail loudly if consensus caps drift unsigned.
    #[test]
    fn mainnet_encoding_freeze_snapshot() {
        assert_eq!(MAX_FCMP_INPUTS, 4);
        assert_eq!(MAX_FCMP_PROOF_BYTES, 12_288);
        assert_eq!(MAX_FCMP_ANON_SET, 64);
        assert_eq!(MAX_OUTPUTS, 8);
        assert_eq!(MAX_RANGE_PROOF_BYTES, 1024);
        assert_eq!(MAX_PAYLOAD_BYTES, 80);
        assert_eq!(FCMP_ADMIT_MAX_LEAVES_PER_BLOCK, 64);
        assert_eq!(FCMP_GROW_CATCHUP_MAX_PER_BLOCK, 64);
        assert_eq!(FCMP_ROOT_MAX_AGE_BLOCKS, 64);
        assert_eq!(FCMP_LEAF_DOM, b"kohl/fcmp/leaf/v1");
        assert_eq!(FCMP_EMPTY_LEAF_DOM, b"kohl/fcmp/leaf/empty/v1");
        assert_eq!(FCMP_MERKLE_DOM, b"kohl/fcmp/merkle/v1");
        assert_eq!(FCMP_MERKLE_EMPTY_DOM, b"kohl/fcmp/merkle/v1/empty");
        assert_eq!(ATOMIC_UNITS, 100_000_000);
        assert_eq!(TARGET_BLOCK_TIME_MS, 60_000);
    }

    #[test]
    fn first_reward_is_sane() {
        // (9.2e15) >> 19 ≈ 175.48 KOHL
        let r = block_reward(0);
        assert_eq!(r, MAX_CURVE_SUPPLY >> EMISSION_SHIFT);
        assert!(r / ATOMIC_UNITS == 175);
    }

    #[test]
    fn reward_decreases_monotonically_to_tail() {
        let mut last = block_reward(0);
        let mut emitted = 0u64;
        // Sample the curve coarsely across the whole range.
        while emitted < MAX_CURVE_SUPPLY {
            let r = block_reward(emitted);
            assert!(r <= last);
            assert!(r >= TAIL_REWARD);
            last = r;
            emitted = emitted.saturating_add(MAX_CURVE_SUPPLY / 1000);
        }
        assert_eq!(block_reward(MAX_CURVE_SUPPLY), TAIL_REWARD);
        assert_eq!(block_reward(u64::MAX), TAIL_REWARD);
    }

    #[test]
    fn emission_never_overflows() {
        // Even at u64::MAX "emitted", reward stays at tail.
        assert_eq!(block_reward(u64::MAX), TAIL_REWARD);
    }
}
