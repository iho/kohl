# Chain specifications

Exported JSON specs that miners can pass as `--chain path/to/file.json`.

## FCMP-only (all networks)

Every built-in preset (`dev`, `kohl-ash`, `kohl` / `mainnet`) starts **FCMP-only** history:

- Spends use full-chain membership (`verify_fcmp_v1`, signing domain `kohl/transfer/v4`)
- **No Dual** schedule, no CLSAG activation height, no genesis flag for rings
- Fair launch: genesis supply is zero; only initial PoW difficulty differs by preset

Operators: full host-skew matrix and genesis checklist in **[docs/fcmp-runbook.md](../docs/fcmp-runbook.md)**. Design: [docs/fcmp-design.md](../docs/fcmp-design.md) (PR-9).

| Built-in id | CLI | Initial difficulty | Typical use |
|-------------|-----|--------------------|-------------|
| `dev` | `--dev` | low (`MinDifficulty`) | Single machine; wipe freely |
| `kohl-ash` | `--chain kohl-ash` | `100_000` | Multi-node smoke / throwaway soak |
| `kohl` | `--chain kohl` or `mainnet` | `50_000_000` | Mainnet (encoding freeze PR-10; see `docs/fcmp-mainnet-freeze.md`) |

Treat any pre-freeze public testnet as **throwaway**: re-genesis rather than migrating CLSAG-era state.

### Node version skew

Miners and seeds must run a node binary that registers the host functions required by the runtime `spec_version` (see runbook matrix). Example for current tree:

| Runtime `spec_version` | Min node package | Required (consensus) |
|------------------------|------------------|----------------------|
| 1 | 0.1.0 | `verify_fcmp_v1`, balance, range, value commitment, point hygiene |

On start, the node logs the capability line under target `kohl`.

## Generate with bootnodes

```bash
cargo build -p kohl-node --release

# After your seed is up and you know PeerId + public multiaddr:
./scripts/make-chainspec.sh \
  --chain kohl \
  --bootnode /ip4/YOUR.IP/tcp/30333/p2p/12D3KooW... \
  --output chainspecs/kohl.json
```

Miners:

```bash
./target/release/kohl \
  --chain ./chainspecs/kohl.json \
  --validator \
  --mining-seed <64-hex>
```

Bootnodes embedded in the file are used automatically; extra `--bootnodes` still work.

## Chains (suggested files)

| File (suggested) | Built-in id | Notes |
|------------------|-------------|--------|
| `kohl.json` | `kohl` | Mainnet fair launch, FCMP-only |
| `kohl-ash.json` | `kohl-ash` | Public / multi-node testnet, FCMP-only |

Do **not** commit real production node keys. Committing a public `bootNodes` multiaddr is fine and recommended once the seed is stable.
