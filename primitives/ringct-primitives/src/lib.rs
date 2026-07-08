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

/// Maximum inputs per transfer.
pub const MAX_INPUTS: u32 = 8;

/// Maximum outputs per transfer (and per coinbase).
pub const MAX_OUTPUTS: u32 = 8;

/// Maximum ring size the type system admits. The *required* ring size is a
/// runtime `Config` constant (16 on the production chain) and must be ≤ this.
pub const MAX_RING_SIZE: u32 = 16;

/// Maximum encoded size of a CLSAG signature:
/// c0 (32) + one scalar per ring member (32·n) + auxiliary key image D (32).
pub const CLSAG_MAX_BYTES: u32 = 32 * (MAX_RING_SIZE + 2);

/// Maximum encoded size of an aggregated range proof.
/// An n=64-bit proof aggregating m parties is (9 + 2·log2(64·m))·32 bytes;
/// for m = 8 that is 864 bytes.
pub const MAX_RANGE_PROOF_BYTES: u32 = 1024;

/// Maximum opaque per-output wallet payload (encrypted amount + blinding;
/// format finalized with stealth-address ECDH in Phase 3).
pub const MAX_PAYLOAD_BYTES: u32 = 80;

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
