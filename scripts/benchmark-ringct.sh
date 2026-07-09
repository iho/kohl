#!/usr/bin/env bash
# Benchmark pallet-ringct against the production WASM runtime.
#
# Why not stock `frame-omni-bencher`?
#   Kohl's transfer path calls custom `ringct_crypto` host functions. Omni-bencher
#   only registers the Polkadot host set, so CLSAG/BP verification would trap.
#   The node binary registers the same host functions as a full validator.
#
# Usage:
#   ./scripts/benchmark-ringct.sh
#   STEPS=20 REPEAT=5 ./scripts/benchmark-ringct.sh   # faster smoke run

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

STEPS="${STEPS:-50}"
REPEAT="${REPEAT:-20}"
# Machine results land next to the engineered weights for review/merge.
OUT="${OUT:-pallets/ringct/src/weights_machine.rs}"
PROFILE="${PROFILE:-release}"

echo "==> Building runtime + node with runtime-benchmarks ($PROFILE)"
# `release` is the cargo profile name; binary ends up in target/release.
cargo build -p kohl-runtime --release --features runtime-benchmarks
cargo build -p kohl-node --release --features runtime-benchmarks

BIN="target/release/kohl"
WASM=$(ls -1 target/release/wbuild/kohl-runtime/kohl_runtime.compact.compressed.wasm \
  target/release/wbuild/kohl-runtime/kohl_runtime.compact.wasm \
  target/release/wbuild/kohl-runtime/kohl_runtime.wasm 2>/dev/null | head -1 || true)

echo "==> Binary: $BIN"
echo "==> WASM:   ${WASM:-'(none — will use --chain dev)'}"
echo "==> Running: kohl benchmark pallet --pallet pallet_ringct"
echo "    (node CLI registers ringct_crypto host functions; stock omni-bencher does not)"
echo "    Note: --chain and --runtime are mutually exclusive."

# Prefer an explicit production WASM blob + runtime genesis builder. Fall back
# to the chain-spec path if the wasm artifact is missing.
# No --header: the CLI requires a real file if the flag is set (/dev/null fails).
# The Handlebars template already embeds a license banner.
COMMON_ARGS=(
  --wasm-execution=compiled
  --pallet pallet_ringct
  --extrinsic '*'
  --steps "$STEPS"
  --repeat "$REPEAT"
  --heap-pages=4096
  --template=./scripts/frame-weight-template.hbs
  --output "$OUT"
)

if [[ -n "${WASM}" && -f "${WASM}" ]]; then
  "$BIN" benchmark pallet \
    --runtime "$WASM" \
    --genesis-builder=runtime \
    "${COMMON_ARGS[@]}"
else
  echo "    warning: no WASM found under target/release/wbuild; using --chain dev"
  "$BIN" benchmark pallet \
    --chain dev \
    "${COMMON_ARGS[@]}"
fi

echo "==> Machine weights written to $OUT"
echo "    Compare with pallets/ringct/src/weights.rs and merge if desired."
echo "    Engineered WeightInfo stays parametric (inputs/outputs/ring_size);"
echo "    machine file is the omni-style fixed worst-case measurement."
