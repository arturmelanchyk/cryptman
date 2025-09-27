use crate::error::CryptError;

pub fn validate_enc_args(
    cipher: &str,
    argon2id_time_cost: u32,
    argon2id_memory_cost: u32,
    argon2id_parallelism: u32,
    argon2id_salt_length: usize,
    argon2id_hash_length: usize,
) -> Result<(), CryptError> {
    // Validate cipher
    if !matches!(cipher, "aes-256-gcm" | "xchacha20poly1305") {
        return Err(CryptError::InvalidCipher(format!(
            "Unsupported cipher: {}",
            cipher
        )));
    }

    // Validate Argon2id parameters
    validate_argon2id_params(
        argon2id_time_cost,
        argon2id_memory_cost,
        argon2id_parallelism,
        argon2id_salt_length,
        argon2id_hash_length,
    )?;

    Ok(())
}

pub fn validate_dec_args_no_kdf_params(args: &[&str]) -> Result<(), CryptError> {
    let forbidden_flags = [
        "--cipher",
        "--argon2id-time-cost",
        "--argon2id-memory-cost",
        "--argon2id-parallelism",
        "--argon2id-salt-length",
        "--argon2id-hash-length",
    ];

    for flag in forbidden_flags {
        if args.iter().any(|&arg| arg == flag) {
            return Err(CryptError::CliArgument(format!(
                "Flag {} must not be specified in decryption mode",
                flag
            )));
        }
    }

    Ok(())
}

fn validate_argon2id_params(
    time_cost: u32,
    memory_cost: u32,
    parallelism: u32,
    salt_length: usize,
    hash_length: usize,
) -> Result<(), CryptError> {
    if time_cost < 3 {
        return Err(CryptError::InvalidKdfParameters(
            "Argon2id time cost must be at least 3".to_string(),
        ));
    }

    if memory_cost < 65536 {
        return Err(CryptError::InvalidKdfParameters(
            "Argon2id memory cost must be at least 65536 KB (64 MiB)".to_string(),
        ));
    }

    if parallelism < 1 {
        return Err(CryptError::InvalidKdfParameters(
            "Argon2id parallelism must be at least 1".to_string(),
        ));
    }

    if salt_length < 16 {
        return Err(CryptError::InvalidKdfParameters(
            "Argon2id salt length must be at least 16 bytes".to_string(),
        ));
    }

    if hash_length < 32 {
        return Err(CryptError::InvalidKdfParameters(
            "Argon2id hash length must be at least 32 bytes".to_string(),
        ));
    }

    Ok(())
}
