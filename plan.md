You are an expert blockchain architect and Rust developer specializing in the Polkadot SDK (Substrate/FRAME) and privacy-preserving cryptocurrencies. Your task is to design and provide a complete starter blueprint (architecture + detailed code structure + implementation plan) for a **pure cash-only Layer 1 blockchain** built with the Polkadot SDK in Rust. The chain must emulate the core privacy structure of Monero while being practical to implement on Substrate.

### Project Requirements
- **Pure cash-only L1**: No smart contracts, no EVM/Wasm contracts pallet, no programmability beyond basic private transfers. The only functionality is private, fungible value transfers (sender, receiver, and amount hidden by default). Focus exclusively on untraceable digital cash.
- **Monero-like privacy structure** (the three pillars):
  1. **Sender anonymity** via ring signatures (or practical equivalent using linkable ring signatures or zk-SNARKs).
  2. **Receiver privacy** via stealth / one-time addresses.
  3. **Amount confidentiality** via RingCT-style mechanisms (Pedersen commitments + range proofs, e.g., Bulletproofs, or modern zk-SNARKs for amounts).
- Use a **UTXO / record / commitment model** (not the default Substrate account model) for private outputs. Outputs are commitments; spending uses nullifiers or key images to prevent double-spends.
- Standalone L1 (not a parachain). Users run their own nodes. Support for light clients is desirable.
- Native token used only for transaction fees and (optionally) minimal staking or security incentives. No heavy pre-mine or complex tokenomics — keep it simple like early Monero.
- Consensus: Choose and justify one suitable for a cash chain (e.g., custom PoW inspired by RandomX for ASIC resistance, or hybrid Aura + GRANDPA with modifications). Prioritize decentralization and resistance to 51% attacks.
- Runtime must be efficient: proofs/verification should be practical (consider off-chain proving with on-chain verification where beneficial).
- WASM-compatible runtime (standard for Substrate). All crypto must work in `no_std` + WASM where possible.

### Research You Must Incorporate
Before designing, deeply research and reference:
- Cryptonote whitepaper and Monero protocol (ring signatures / MLSAG → CLSAG, stealth addresses, key images).
- RingCT paper by Shen Noether (Pedersen commitments + range proofs).
- Bulletproofs (for efficient range proofs; Rust implementations exist).
- Polkadot SDK / Substrate documentation (FRAME pallets, custom runtime, custom storage, extrinsics, runtime APIs).
- Existing privacy work on Substrate: ZeroPool pallet (zk-SNARK anonymous/confidential transactions), any confidential balances or mixer pallets, Manta Network or similar zk privacy approaches.
- Rust crypto crates suitable for Substrate: `curve25519-dalek` / `dalek` ecosystem, `bulletproofs`, ring signature implementations (e.g., Ristretto-based ring signatures), `arkworks` or Halo2 for zk if preferred over classic ring sigs.
- Challenges: Implementing full MLSAG + Bulletproofs in WASM/runtime performance, storage of commitments/nullifiers, key management in wallets.

### Output Structure (Provide in This Exact Order)
1. **High-Level Architecture Overview**
   - Overall design (L1 node structure, runtime composition).
   - Data model (private UTXO / commitment model with nullifiers).
   - How the three Monero pillars are implemented or approximated using available Substrate primitives and Rust crypto.
   - Consensus choice and justification.
   - How privacy is enforced at protocol level (mandatory, no opt-out).

2. **Recommended Tech Stack & Dependencies**
   - Polkadot SDK version / template to start from (e.g., `substrate-node-template` or latest Polkadot SDK templates).
   - Key Rust crates (with versions or latest recommendations) for crypto (ring sigs, commitments, Bulletproofs/zk).
   - Any existing pallets or examples to fork/adapt (e.g., ZeroPool concepts, custom balances).

3. **Custom Pallet Design (Core of the Chain)**
   - Name and purpose of the main privacy pallet (e.g., `pallet-private-cash` or `pallet-ringct`).
   - Storage items (commitments, nullifiers/key images, ring members or proof data).
   - Extrinsics (e.g., `private_transfer`, `create_stealth_address` if needed).
   - Verification logic for ring signatures / commitments / range proofs.
   - Double-spend prevention.
   - Fee handling (native token burned or to validators).

4. **Runtime Configuration**
   - Which standard pallets to include (System, Timestamp, etc.) and which to customize or replace.
   - How to wire the custom privacy pallet.
   - Genesis config for initial supply/distribution (fair launch style).
   - Custom runtime APIs if needed (e.g., for light clients or wallet scanning).

5. **Node & Client Side**
   - How to build the node binary.
   - Wallet considerations (key derivation for stealth addresses, ring member selection, proof generation — possibly off-chain for heavy zk).
   - Light client support ideas.

6. **Implementation Plan & Phased Approach**
   - Step-by-step plan (Phase 1: Basic transparent UTXO-like, Phase 2: Add commitments, Phase 3: Ring signatures / zk, Phase 4: Full integration + testing).
   - Potential challenges (performance in WASM, proving time, storage bloat, security audits) and mitigation strategies.
   - Testing strategy (unit tests for crypto primitives, integration tests for private transfers, privacy analysis).

7. **Code Skeletons & Examples**
   - `Cargo.toml` with key dependencies.
   - Basic structure of the custom pallet (`lib.rs`, storage, calls, errors, events).
   - Example of a private transfer extrinsic skeleton (high-level pseudocode + key Rust snippets for commitment creation/verification or ring sig).
   - Runtime `lib.rs` snippet showing pallet integration.
   - Genesis / chain spec notes.

8. **Tokenomics & Economics (Light)**
   - Simple native token design (supply, emission if any, fee model) optimized for a cash chain.
   - Security incentives (how miners/validators are rewarded without compromising privacy).

9. **Risks, Limitations & Recommendations**
   - Cryptographic security (recommend professional audits for any custom ring sig / zk implementation).
   - Regulatory considerations for privacy coins.
   - Alternatives or simplifications (e.g., using modern zk-SNARKs / Bulletproofs instead of classic MLSAG if full ring sig implementation proves too heavy).
   - Scalability notes and future extensions (while keeping pure cash focus).

### Constraints & Style
- Prioritize **practicality and security** over theoretical perfection. If full classic Monero MLSAG + Bulletproofs is too complex for an initial implementation, propose a strong modern equivalent (e.g., linkable ring signatures + Bulletproofs or zk-SNARK confidential transactions) that achieves similar privacy properties (sender/receiver/amount hiding + fungibility).
- All code must be in **Rust** and compatible with the Polkadot SDK runtime (WASM + native).
- Be detailed and production-minded — include error handling, events, and security considerations.
- Cite sources (papers, crates, Substrate docs) where relevant.
- If something is extremely complex or not recommended in Substrate, explain why and suggest the best feasible alternative while staying as close as possible to Monero structure.

Start by confirming your understanding of the requirements and outlining the high-level architecture before diving into code. Use the latest stable Polkadot SDK practices.