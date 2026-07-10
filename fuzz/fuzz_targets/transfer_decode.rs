//! Fuzz SCALE decoding of FCMP `TransferTx` — unsigned extrinsics mean anyone
//! can feed the runtime arbitrary bytes (BLUEPRINT.md §9.1 / PR-11).
#![no_main]

use codec::Decode;
use libfuzzer_sys::fuzz_target;
use pallet_ringct::TransferTx;

fuzz_target!(|data: &[u8]| {
    let _ = TransferTx::decode(&mut &data[..]);
});
