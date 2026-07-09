use crate as pallet_difficulty;
use frame_support::{
    derive_impl,
    traits::{ConstU32, ConstU64, Hooks},
};
use sp_core::U256;
use sp_runtime::BuildStorage;

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        Timestamp: pallet_timestamp,
        Difficulty: pallet_difficulty,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
}

#[derive_impl(pallet_timestamp::config_preludes::TestDefaultConfig)]
impl pallet_timestamp::Config for Test {
    type Moment = u64;
    type MinimumPeriod = ConstU64<0>;
}

const TARGET: u64 = 60_000; // 60s
const MIN_DIFFICULTY: u128 = 1_000;

impl pallet_difficulty::Config for Test {
    type TargetBlockTime = ConstU64<TARGET>;
    type BlockWindow = ConstU32<30>;
    type MinDifficulty = ConstU64Min;
}

// `MinDifficulty` needs a `Get<u128>`; ConstU64 gives u64, so a tiny adapter.
pub struct ConstU64Min;
impl frame_support::traits::Get<u128> for ConstU64Min {
    fn get() -> u128 {
        MIN_DIFFICULTY
    }
}

fn new_test_ext(initial: u128) -> sp_io::TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    pallet_difficulty::GenesisConfig::<Test> {
        initial_difficulty: initial,
        _marker: Default::default(),
    }
    .assimilate_storage(&mut storage)
    .unwrap();
    storage.into()
}

/// Feed `count` blocks whose solve time is exactly `solvetime` ms, starting
/// from t = 0, and return the resulting difficulty.
fn run_with_solvetime(initial: u128, count: u64, solvetime: u64) -> U256 {
    let mut ext = new_test_ext(initial);
    ext.execute_with(|| {
        for i in 1..=count {
            Timestamp::set_timestamp(i * solvetime);
            Difficulty::on_finalize(i);
        }
        Difficulty::difficulty()
    })
}

#[test]
fn genesis_sets_initial_difficulty() {
    new_test_ext(500_000).execute_with(|| {
        assert_eq!(Difficulty::difficulty(), U256::from(500_000u64));
    });
}

#[test]
fn genesis_respects_minimum() {
    new_test_ext(1).execute_with(|| {
        assert_eq!(Difficulty::difficulty(), U256::from(MIN_DIFFICULTY));
    });
}

#[test]
fn on_target_holds_difficulty_roughly_steady() {
    let start = 1_000_000u128;
    let d = run_with_solvetime(start, 60, TARGET);
    // Within ~1% of the starting difficulty when blocks land exactly on time.
    let lo = U256::from(start) * 99u32 / 100u32;
    let hi = U256::from(start) * 101u32 / 100u32;
    assert!(d >= lo && d <= hi, "difficulty {d} drifted from {start}");
}

#[test]
fn fast_blocks_raise_difficulty() {
    let start = 1_000_000u128;
    // Half the target solve time → difficulty should climb well above start.
    let d = run_with_solvetime(start, 60, TARGET / 2);
    assert!(
        d > U256::from(start) * 3u32 / 2u32,
        "expected big rise, got {d}"
    );
}

#[test]
fn slow_blocks_lower_difficulty() {
    let start = 1_000_000u128;
    // Double the target solve time → difficulty should fall toward half.
    let d = run_with_solvetime(start, 60, TARGET * 2);
    assert!(
        d < U256::from(start) * 3u32 / 4u32,
        "expected big drop, got {d}"
    );
    assert!(d >= U256::from(MIN_DIFFICULTY));
}

#[test]
fn difficulty_never_drops_below_minimum() {
    let start = MIN_DIFFICULTY + 10;
    // Extremely slow blocks: solve time clamped to 6T, difficulty floors.
    let d = run_with_solvetime(start, 60, TARGET * 100);
    assert_eq!(d, U256::from(MIN_DIFFICULTY));
}

#[test]
fn window_is_bounded() {
    let mut ext = new_test_ext(1_000_000);
    ext.execute_with(|| {
        for i in 1..=500u64 {
            Timestamp::set_timestamp(i * TARGET);
            Difficulty::on_finalize(i);
        }
        // Window capped at BlockWindow + 1 = 31.
        assert_eq!(crate::PastSamples::<Test>::get().len(), 31);
    });
}

#[test]
fn non_monotonic_timestamps_do_not_panic_or_explode() {
    let mut ext = new_test_ext(1_000_000);
    ext.execute_with(|| {
        // Alternating stalled/backwards timestamps (clamped to 1ms solvetime).
        for i in 1..=40u64 {
            let t = if i % 2 == 0 { i * TARGET } else { 1 };
            Timestamp::set_timestamp(t);
            Difficulty::on_finalize(i);
        }
        let d = Difficulty::difficulty();
        assert!(d >= U256::from(MIN_DIFFICULTY));
    });
}
