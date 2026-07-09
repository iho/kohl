//! Pallet list for the `frame_benchmarking::Benchmark` runtime API.
//! Consumed by `list_benchmarks!` / `add_benchmarks!` when
//! `--features runtime-benchmarks` is enabled.

#![cfg(feature = "runtime-benchmarks")]

frame_benchmarking::define_benchmarks!(
    [pallet_ringct, RingCt]
    [pallet_timestamp, Timestamp]
);
