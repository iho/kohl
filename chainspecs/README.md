# Chain specifications

Exported JSON specs that miners can pass as `--chain path/to/file.json`.

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

## Chains

| File (suggested) | Built-in id | Notes |
|------------------|-------------|--------|
| `kohl.json` | `kohl` | Mainnet fair launch |
| `kohl-ash.json` | `kohl-ash` | Public / multi-node testnet |

Do **not** commit real production node keys. Committing a public `bootNodes` multiaddr is fine and recommended once the seed is stable.
