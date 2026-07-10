//! `kohl-wallet` — scan the chain for owned outputs and build/submit **FCMP**
//! transfers. A thin CLI over the [`kohl_wallet`] library.

use clap::{Parser, Subcommand};
use codec::Encode;
use kohl_wallet::{rpc::RpcClient, MembershipCache, Wallet};
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
    /// Build and submit an FCMP transfer to `--to`.
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
    let hexpart = s
        .strip_prefix("kohl:")
        .ok_or("address must start with 'kohl:'")?;
    let bytes = hex::decode(hexpart)?;
    if bytes.len() != 64 {
        return Err("address must encode 64 bytes (view||spend)".into());
    }
    let mut view_public = [0u8; 32];
    let mut spend_public = [0u8; 32];
    view_public.copy_from_slice(&bytes[..32]);
    spend_public.copy_from_slice(&bytes[32..]);
    Ok(StealthAddress {
        view_public,
        spend_public,
    })
}

fn fetch_all_outputs(
    rpc: &RpcClient,
) -> Result<Vec<(u64, kohl_wallet::StoredOut)>, Box<dyn Error>> {
    let best = rpc.best_number()?;
    rpc.outputs_in_range(0, best)
}

/// Split owned outputs into (unspent, spent) by querying the chain's key
/// image set — scanning alone cannot tell whether we already spent an output.
fn split_by_spent(
    rpc: &RpcClient,
    owned: Vec<kohl_wallet::OwnedOutput>,
) -> Result<(Vec<kohl_wallet::OwnedOutput>, Vec<kohl_wallet::OwnedOutput>), Box<dyn Error>> {
    let mut unspent = Vec::new();
    let mut spent = Vec::new();
    for o in owned {
        if rpc.is_key_image_spent(o.key_image)? {
            spent.push(o);
        } else {
            unspent.push(o);
        }
    }
    Ok((unspent, spent))
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
            let (unspent, spent) = split_by_spent(&client, owned)?;
            let total: u64 = unspent.iter().map(|o| o.amount).sum();
            println!("address: {}", wallet.address_string());
            println!(
                "scanned {} outputs, own {} ({} unspent, {} spent)",
                outputs.len(),
                unspent.len() + spent.len(),
                unspent.len(),
                spent.len()
            );
            for o in &unspent {
                println!(
                    "  #{:<6} amount={:<14} {}",
                    o.global_index,
                    o.amount,
                    if o.coinbase { "coinbase" } else { "" }
                );
            }
            for o in &spent {
                println!("  #{:<6} amount={:<14} spent", o.global_index, o.amount);
            }
            println!("balance: {} atomic units", total);
        }

        Command::Send {
            seed,
            rpc,
            to,
            amount,
        } => {
            let wallet = Wallet::from_seed(&parse_seed(&seed)?);
            let dest = parse_address(&to)?;
            let client = RpcClient::new(&rpc);

            let best = client.best_number()?;
            let fee_per_byte = client.min_fee_per_byte()?;
            let all = client.outputs_in_range(0, best)?;
            let owned = wallet.scan(&all);
            let (owned, _spent) = split_by_spent(&client, owned)?;

            let mut cache = MembershipCache::new();
            let membership = client.refresh_membership_cache(&mut cache, &all)?;
            let slots = membership.digests.len() as u64;

            let est_fee = fee_per_byte.saturating_mul(Wallet::estimate_tx_bytes(slots, 1));
            let needed = amount.saturating_add(est_fee);
            let mut mature: Vec<_> = owned.into_iter().filter(|o| is_mature(o, best)).collect();
            mature.sort_by_key(|o| std::cmp::Reverse(o.amount));
            let mut selected = Vec::new();
            let mut total = 0u64;
            for o in mature {
                if !membership
                    .admitted
                    .iter()
                    .any(|m| m.tree_index == o.global_index)
                {
                    continue;
                }
                selected.push(o);
                total = total.saturating_add(selected.last().unwrap().amount);
                if total >= needed {
                    break;
                }
            }
            if total < needed {
                return Err(format!(
                    "not enough admitted mature funds: need {needed}, have {total} (tree slots={slots})"
                )
                .into());
            }
            let est_fee =
                fee_per_byte.saturating_mul(Wallet::estimate_tx_bytes(slots, selected.len()));
            if total < amount.saturating_add(est_fee) {
                return Err(
                    "selected inputs cover amount but not re-estimated fee; try again".into(),
                );
            }

            // Re-check tip before prove (cheap reorg guard).
            let tip2 = client.best_number()?;
            let root2 = client.membership_root()?;
            let slots2 = client.tree_slots()?;
            let membership = if cache.needs_resync(tip2, &root2, slots2) {
                client.refresh_membership_cache(&mut cache, &all)?
            } else {
                membership
            };

            let tx = wallet.build_transfer_multi(&selected, &membership, &dest, amount, est_fee)?;
            submit_transfer(&client, tx, &selected)?;
        }
    }
    Ok(())
}

/// A coinbase output matures after 60 blocks, a regular one after 10 — mirror
/// the runtime constants for admission into the membership tree.
fn is_mature(o: &kohl_wallet::OwnedOutput, best: u32) -> bool {
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

fn submit_transfer(
    client: &RpcClient,
    tx: pallet_ringct::TransferTx,
    selected: &[kohl_wallet::OwnedOutput],
) -> Result<(), Box<dyn Error>> {
    let spent: Vec<u64> = selected.iter().map(|o| o.global_index).collect();
    let call = kohl_runtime::RuntimeCall::RingCt(pallet_ringct::Call::transfer { tx });
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
    println!("submitted FCMP transfer spending {:?}: {}", spent, hash);
    Ok(())
}
