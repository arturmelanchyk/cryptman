use clap::{Args, Parser, Subcommand};
use std::{process, time::Instant};

mod cli;
mod crypto;
mod error;
mod file;
mod kdf;
mod memory;
mod password;
mod progress;

use error::CryptError;

#[derive(Parser)]
#[command(name = "cryptman")]
#[command(about = "A minimalistic CLI encryption/decryption tool")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Enc(EncArgs),
    Dec(DecArgs),
}

#[derive(Args)]
struct EncArgs {
    #[arg(value_name = "INPUT_FILE")]
    input_file: String,

    #[arg(value_name = "OUTPUT_FILE")]
    output_file: String,

    #[arg(long, default_value = "aes-256-gcm")]
    cipher: String,

    #[arg(long, default_value = "stdin")]
    passin: String,

    #[arg(long)]
    force: bool,

    #[arg(long)]
    insecure: bool,

    // Argon2id parameters
    #[arg(long, default_value = "3")]
    argon2id_time_cost: u32,

    #[arg(long, default_value = "65536")]
    argon2id_memory_cost: u32,

    #[arg(long, default_value = "1")]
    argon2id_parallelism: u32,

    #[arg(long, default_value = "16")]
    argon2id_salt_length: usize,

    #[arg(long, default_value = "32")]
    argon2id_hash_length: usize,
}

#[derive(Args)]
struct DecArgs {
    #[arg(value_name = "INPUT_FILE")]
    input_file: String,

    #[arg(value_name = "OUTPUT_FILE")]
    output_file: String,

    #[arg(long, default_value = "stdin")]
    passin: String,

    #[arg(long)]
    force: bool,

    #[arg(long)]
    insecure: bool,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Enc(args) => handle_encrypt(args),
        Commands::Dec(args) => handle_decrypt(args),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(e.exit_code());
    }
}

fn handle_encrypt(args: EncArgs) -> Result<(), CryptError> {
    // Validate CLI arguments
    cli::validate_enc_args(
        &args.cipher,
        args.argon2id_time_cost,
        args.argon2id_memory_cost,
        args.argon2id_parallelism,
        args.argon2id_salt_length,
        args.argon2id_hash_length,
    )?;

    // Get password with confirmation for stdin
    let password = password::get_password(&args.passin, args.passin == "stdin")?;

    // Create KDF configuration (Argon2id only)
    let kdf_config = kdf::KdfConfig::new_argon2id(
        args.argon2id_time_cost,
        args.argon2id_memory_cost,
        args.argon2id_parallelism,
        args.argon2id_salt_length,
        args.argon2id_hash_length,
    )?;

    // Derive encryption key with progress reporting
    let key_pb = progress::create_bar("Key derivation", 1);
    let key_start = Instant::now();
    let key = kdf_config.derive_key(password.as_bytes())?;
    progress::complete_with_duration(&key_pb, key_start);

    // Get cipher type
    let cipher_type = crypto::CipherType::from_string(&args.cipher)?;

    // Encrypt file
    file::encrypt_file(
        &args.input_file,
        &args.output_file,
        &kdf_config,
        &cipher_type,
        &key,
        args.force,
    )
}

fn handle_decrypt(args: DecArgs) -> Result<(), CryptError> {
    // Check that no KDF/cipher flags are provided in decryption mode
    let cli_args: Vec<String> = std::env::args().collect();
    let cli_args_str: Vec<&str> = cli_args.iter().map(|s| s.as_str()).collect();
    cli::validate_dec_args_no_kdf_params(&cli_args_str)?;

    // Get password (no confirmation needed for decryption)
    let password = password::get_password(&args.passin, false)?;

    // Decrypt file (streams header and payload without loading entire file)
    file::decrypt_file(&args.input_file, &args.output_file, &password, args.force)
}
