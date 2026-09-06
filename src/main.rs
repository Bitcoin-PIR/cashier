//! `bpir-cashier` — operator CLI.
//!
//! ```text
//! bpir-cashier serve --config /etc/bitcoinpir/cashier/config.toml
//! bpir-cashier keygen --out grant.key            # grant signing seed (prints the pubkey to pin)
//! bpir-cashier wallet-seed --out wallet.seed     # Cashu wallet seed
//! bpir-cashier pubkey --key grant.key            # print the public key for --session-grant-pubkey
//! bpir-cashier balance --config config.toml      # ecash held per (mint, unit)
//! bpir-cashier mnemonic --out mint.seed          # BIP39 phrase for cdk-mintd --seed-file
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use tokio::sync::Mutex;

use bpir_cashier::api::{build_router, AppState};
use bpir_cashier::cashu::CdkSwapper;
use bpir_cashier::config::{read_seed_file, Config};
use bpir_cashier::grant::Issuer;
use bpir_cashier::store::Store;

#[derive(Parser)]
#[command(
    name = "bpir-cashier",
    about = "BitcoinPIR cashier: session grants for Cashu ecash",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the HTTP service.
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    /// Generate the 32-byte Ed25519 grant signing seed (mode 0600) and print
    /// its public key, which every PIR server pins with --session-grant-pubkey.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Generate the 64-byte Cashu wallet seed (mode 0600).
    WalletSeed {
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the public key of a grant signing seed.
    Pubkey {
        #[arg(long)]
        key: PathBuf,
    },
    /// Print the ecash balance the cashier holds per (mint, unit).
    Balance {
        #[arg(long)]
        config: PathBuf,
    },
    /// Generate a BIP39 mnemonic (24 words, 256-bit entropy) into a mode-0400
    /// file, for a mint's `--seed-file`. The phrase is never printed.
    Mnemonic {
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 24)]
        words: usize,
    },
}

fn write_secret(path: &PathBuf, bytes: &[u8]) -> anyhow::Result<()> {
    write_secret_mode(path, bytes, 0o600)
}

fn write_secret_mode(path: &PathBuf, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn load_grant_seed(path: &std::path::Path) -> anyhow::Result<[u8; 32]> {
    let seed = read_seed_file(path, 32).map_err(anyhow::Error::msg)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&seed);
    Ok(out)
}

fn load_wallet_seed(path: &std::path::Path) -> anyhow::Result<[u8; 64]> {
    let seed = read_seed_file(path, 64).map_err(anyhow::Error::msg)?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&seed);
    Ok(out)
}

fn units(config: &Config) -> Vec<String> {
    let mut units: Vec<String> = config.offers.iter().map(|o| o.unit.clone()).collect();
    units.sort();
    units.dedup();
    units
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse()?),
        )
        .init();
    match Cli::parse().command {
        Command::Keygen { out } => {
            let mut seed = zeroize::Zeroizing::new([0u8; 32]);
            getrandom::getrandom(seed.as_mut()).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
            write_secret(&out, seed.as_ref())?;
            let issuer = Issuer::new(&seed, 1);
            eprintln!(
                "wrote grant signing seed (32 bytes, mode 0600) to {}",
                out.display()
            );
            eprintln!("public key (pin on every PIR server with --session-grant-pubkey):");
            println!("{}", issuer.public_key_hex());
        }
        Command::WalletSeed { out } => {
            let mut seed = zeroize::Zeroizing::new([0u8; 64]);
            getrandom::getrandom(seed.as_mut()).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
            write_secret(&out, seed.as_ref())?;
            eprintln!(
                "wrote wallet seed (64 bytes, mode 0600) to {}",
                out.display()
            );
        }
        Command::Pubkey { key } => {
            let seed = zeroize::Zeroizing::new(load_grant_seed(&key)?);
            println!("{}", Issuer::new(&seed, 1).public_key_hex());
        }
        Command::Mnemonic { out, words } => {
            anyhow::ensure!(
                matches!(words, 12 | 15 | 18 | 21 | 24),
                "--words must be 12, 15, 18, 21, or 24"
            );
            let phrase = zeroize::Zeroizing::new(
                bip39::Mnemonic::generate_in(bip39::Language::English, words)
                    .map_err(|e| anyhow::anyhow!("bip39: {e}"))?
                    .to_string(),
            );
            write_secret_mode(&out, format!("{}\n", phrase.as_str()).as_bytes(), 0o400)?;
            eprintln!(
                "wrote {words}-word BIP39 mnemonic (mode 0400) to {}",
                out.display()
            );
        }
        Command::Balance { config } => {
            let config = Config::load(&config)?;
            let seed = zeroize::Zeroizing::new(load_wallet_seed(&config.wallet_seed_path)?);
            let swapper = CdkSwapper::open(
                &config.wallet_db_path,
                *seed,
                &config.mints,
                &units(&config),
                std::time::Duration::from_secs(30),
            )
            .await?;
            for ((mint, unit), balance) in swapper.balances().await {
                match balance {
                    Ok(b) => println!("{mint} {unit} {b}"),
                    Err(e) => println!("{mint} {unit} error: {e}"),
                }
            }
        }
        Command::Serve { config } => {
            let config = Config::load(&config)?;
            let grant_seed = zeroize::Zeroizing::new(load_grant_seed(&config.grant_key_path)?);
            let issuer = Issuer::new(&grant_seed, config.grant_ttl_secs);
            let wallet_seed = zeroize::Zeroizing::new(load_wallet_seed(&config.wallet_seed_path)?);
            let swapper = CdkSwapper::open(
                &config.wallet_db_path,
                *wallet_seed,
                &config.mints,
                &units(&config),
                std::time::Duration::from_secs(45),
            )
            .await?;
            let store = Store::open(&config.store_path)?;
            let pending = store.pending_keys();
            if !pending.is_empty() {
                tracing::warn!(count = pending.len(), "tokens with unknown swap outcome in the store; reconcile against the wallet balance");
            }
            tracing::info!(
                listen = %config.listen,
                cashier_pubkey_hex = %issuer.public_key_hex(),
                mints = ?config.mints,
                offers = config.offers.len(),
                grant_ttl_secs = config.grant_ttl_secs,
                issued_grants = store.issued_count(),
                store = %store.path().display(),
                "bpir-cashier starting"
            );
            let listen = config.listen;
            let state = Arc::new(AppState {
                config,
                issuer,
                swapper: Box::new(swapper),
                store: Mutex::new(store),
                clock: Box::new(bpir_cashier::unix_now),
            });
            let listener = tokio::net::TcpListener::bind(listen)
                .await
                .with_context(|| format!("bind {listen}"))?;
            axum::serve(listener, build_router(state))
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                    tracing::info!("shutting down");
                })
                .await?;
        }
    }
    Ok(())
}
