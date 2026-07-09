//! `kohl-wallet` — scan the chain for owned outputs and build/submit RingCT
//! transfers. A thin CLI over the [`kohl_wallet`] library.

use clap::{Parser, Subcommand};
use codec::Encode;
use kohl_wallet::{rpc::RpcClient, Wallet};
use ringct_crypto::stealth::StealthAddress;
use std::error::Error;

#[derive(Parser)]
#[command(name = "kohl-wallet", about = "Wallet for the kohl private-cash chain")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the wallet address for a seed.
    Address {
        #[arg(long)]
        seed: String,
    },
    /// Scan the chain and list owned outputs and total balance.
    Scan {
        #[arg(long)]
        seed: String,
        #[arg(long, default_value = "http://127.0.0.1:9944")]
        rpc: String,
    },
    /// Build and submit a transfer to `--to`.
    Send {
        #[arg(long)]
        seed: String,
        #[arg(long, default_value = "http://127.0.0.1:9944")]
        rpc: String,
        /// Recipient address (`kohl:<64hex view><64hex spend>`).
        #[arg(long)]
        to: String,
        /// Amount in atomic units.
        #[arg(long)]
        amount: u64,
        /// Ring size (must match the chain's, 16).
        #[arg(long, default_value_t = 16)]
        ring: usize,
    },
}

fn parse_seed(s: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let bytes = hex::decode(s.trim_start_matches("0x"))?;
    if bytes.len() != 32 {
        return Err("seed must be 32 bytes (64 hex chars)".into());
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

fn parse_address(s: &str) -> Result<StealthAddress, Box<dyn Error>> {
    let hexpart = s.strip_prefix("kohl:").ok_or("address must start with 'kohl:'")?;
    let bytes = hex::decode(hexpart)?;
    if bytes.len() != 64 {
        return Err("address must encode 64 bytes (view||spend)".into());
    }
    let mut view_public = [0u8; 32];
    let mut spend_public = [0u8; 32];
    view_public.copy_from_slice(&bytes[..32]);
    spend_public.copy_from_slice(&bytes[32..]);
    Ok(StealthAddress { view_public, spend_public })
}

fn fetch_all_outputs(
    rpc: &RpcClient,
) -> Result<Vec<(u64, kohl_wallet::StoredOut)>, Box<dyn Error>> {
    let best = rpc.best_number()?;
    rpc.outputs_in_range(0, best)
}

fn main() -> Result<(), Box<dyn Error>> {
    match Cli::parse().command {
        Command::Address { seed } => {
            let wallet = Wallet::from_seed(&parse_seed(&seed)?);
            println!("{}", wallet.address_string());
        }

        Command::Scan { seed, rpc } => {
            let wallet = Wallet::from_seed(&parse_seed(&seed)?);
            let client = RpcClient::new(&rpc);
            let outputs = fetch_all_outputs(&client)?;
            let owned = wallet.scan(&outputs);
            let total: u64 = owned.iter().map(|o| o.amount).sum();
            println!("address: {}", wallet.address_string());
            println!("scanned {} outputs, own {}", outputs.len(), owned.len());
            for o in &owned {
                println!(
                    "  #{:<6} amount={:<14} {}",
                    o.global_index,
                    o.amount,
                    if o.coinbase { "coinbase" } else { "" }
                );
            }
            println!("balance: {} atomic units", total);
        }

        Command::Send { seed, rpc, to, amount, ring } => {
            let wallet = Wallet::from_seed(&parse_seed(&seed)?);
            let dest = parse_address(&to)?;
            let client = RpcClient::new(&rpc);

            let best = client.best_number()?;
            let fee_per_byte = client.min_fee_per_byte()?;
            let all = client.outputs_in_range(0, best)?;
            let owned = wallet.scan(&all);

            // Fee estimate scales with input count; start with 1-in/2-out size.
            let est_fee = fee_per_byte.saturating_mul(3_000);
            let needed = amount.saturating_add(est_fee);
            let mut mature: Vec<_> =
                owned.into_iter().filter(|o| is_mature(o, best)).collect();
            // Prefer larger outputs first (fewer inputs).
            mature.sort_by(|a, b| b.amount.cmp(&a.amount));
            let mut selected = Vec::new();
            let mut total = 0u64;
            for o in mature {
                selected.push(o);
                total = total.saturating_add(selected.last().unwrap().amount);
                if total >= needed {
                    break;
                }
            }
            if total < needed {
                return Err(format!(
                    "not enough mature funds: need {needed}, have {total}"
                )
                .into());
            }
            // Re-estimate fee for multi-input size (~1.5 KiB per extra input).
            let est_fee = fee_per_byte
                .saturating_mul(3_000u64.saturating_add(1_500 * (selected.len() as u64 - 1)));
            if total < amount.saturating_add(est_fee) {
                return Err("selected inputs cover amount but not re-estimated fee; try again"
                    .into());
            }

            let spend_set: std::collections::BTreeSet<u64> =
                selected.iter().map(|o| o.global_index).collect();
            let candidates: Vec<kohl_wallet::DecoyCandidate> = all
                .iter()
                .filter(|(gi, o)| !spend_set.contains(gi) && output_mature(o, best))
                .map(|(gi, o)| kohl_wallet::DecoyCandidate {
                    global_index: *gi,
                    one_time_key: o.one_time_key,
                    commitment: o.commitment,
                    height: o.height,
                })
                .collect();
            let need = ring - 1;
            let mut rng_seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(1);
            let mut rings = Vec::with_capacity(selected.len());
            for _ in &selected {
                let decoys = kohl_wallet::sample_decoys(&candidates, need, best, rng_seed)
                    .map_err(|e| e.to_string())?;
                rings.push(decoys);
                rng_seed = rng_seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
            }

            let tx =
                wallet.build_transfer_multi(&selected, &rings, &dest, amount, est_fee)?;
            let spent: Vec<u64> = selected.iter().map(|o| o.global_index).collect();
            let call = kohl_runtime::RuntimeCall::RingCt(pallet_ringct::Call::transfer { tx });
            // General transaction with AuthorizeCall so `#[pallet::authorize]`
            // can set origin to Authorized (bare extrinsics skip tx extensions).
            let xt = kohl_runtime::UncheckedExtrinsic::new_transaction(
                call,
                (
                    frame_system::AuthorizeCall::<kohl_runtime::Runtime>::new(),
                    frame_system::CheckNonZeroSender::<kohl_runtime::Runtime>::new(),
                    frame_system::CheckSpecVersion::<kohl_runtime::Runtime>::new(),
                    frame_system::CheckTxVersion::<kohl_runtime::Runtime>::new(),
                    frame_system::CheckGenesis::<kohl_runtime::Runtime>::new(),
                    frame_system::CheckEra::<kohl_runtime::Runtime>::from(
                        sp_runtime::generic::Era::Immortal,
                    ),
                    frame_system::CheckNonce::<kohl_runtime::Runtime>::from(0),
                    frame_system::CheckWeight::<kohl_runtime::Runtime>::new(),
                ),
            );
            let hash = client.submit_extrinsic(&xt.encode())?;
            println!("submitted transfer spending {:?}: {}", spent, hash);
        }
    }
    Ok(())
}

/// A coinbase output matures after 60 blocks, a regular one after 10 — mirror
/// the runtime constants for input/decoy selection.
fn is_mature(o: &kohl_wallet::OwnedOutput, best: u32) -> bool {
    mature(o.coinbase, o.height, best)
}
fn output_mature(o: &kohl_wallet::StoredOut, best: u32) -> bool {
    mature(o.coinbase, o.height, best)
}
fn mature(coinbase: bool, height: u32, best: u32) -> bool {
    let age = best.saturating_sub(height);
    if coinbase {
        age >= 60
    } else {
        age >= 10
    }
}
