fn main() {
    // WASM runtime build. Skipped when the `std` feature omits wasm-builder
    // or when SKIP_WASM_BUILD=1 (e.g. building/testing natively without the
    // wasm32 target installed).
    #[cfg(feature = "std")]
    {
        substrate_wasm_builder::WasmBuilder::build_using_defaults();
    }
}
