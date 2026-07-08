use crate as pallet_ringct;
use frame_support::{
    derive_impl,
    traits::{ConstU32, ConstU64},
};
use sp_runtime::BuildStorage;

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        RingCt: pallet_ringct,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
}

impl pallet_ringct::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type RingSize = ConstU32<4>;
    type SpendableAge = ConstU64<10>;
    type CoinbaseMaturity = ConstU64<60>;
    type MinFeePerByte = ConstU64<1>;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
    let mut ext = sp_io::TestExternalities::new(t);
    ext.execute_with(|| System::set_block_number(1));
    ext
}

/// Advance to `n`, running this pallet's `on_initialize` (resets the
/// per-block coinbase flag) — enough for these tests, no full block cycle.
pub fn run_to_block(n: u64) {
    use frame_support::traits::Hooks;
    System::set_block_number(n);
    RingCt::on_initialize(n);
}
