use crate as pallet_ringct;
use frame_support::{derive_impl, traits::ConstU64};
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
    type SpendableAge = ConstU64<10>;
    type CoinbaseMaturity = ConstU64<60>;
    type MinFeePerByte = ConstU64<1>;
    type WeightInfo = ();
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    let mut ext = sp_io::TestExternalities::new(t);
    ext.execute_with(|| System::set_block_number(1));
    ext
}

/// Advance to `n`, running `on_finalize` / `on_initialize` so membership
/// tree maintenance executes between blocks.
pub fn run_to_block(n: u64) {
    use frame_support::traits::Hooks;
    while System::block_number() < n {
        let b = System::block_number();
        RingCt::on_finalize(b);
        System::set_block_number(b + 1);
        RingCt::on_initialize(b + 1);
    }
}
