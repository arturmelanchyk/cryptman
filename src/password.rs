use crate::error::CryptError;
use crate::memory::SecureString;
use rpassword;
use std::env;
use std::fs;
use std::io::{self, Write};
use zeroize::Zeroize;

pub fn get_password(passin: &str, require_confirmation: bool) -> Result<SecureString, CryptError> {
    let password = if passin == "stdin" {
        get_password_from_stdin(require_confirmation)?
    } else if passin.starts_with("env:") {
        let var_name = &passin[4..];
        get_password_from_env(var_name)?
    } else if passin.starts_with("file:") {
        let file_path = &passin[5..];
        get_password_from_file(file_path)?
    } else {
        return Err(CryptError::CliArgument(format!(
            "Invalid passin format: {}. Must be 'stdin', 'env:VAR', or 'file:PATH'",
            passin
        )));
    };

    Ok(password)
}

fn get_password_from_stdin(require_confirmation: bool) -> Result<SecureString, CryptError> {
    print!("Enter password: ");
    io::stdout().flush().map_err(CryptError::FileAccess)?;

    let password = rpassword::read_password()
        .map_err(|e| CryptError::FileAccess(io::Error::new(io::ErrorKind::Other, e)))?;

    if require_confirmation {
        print!("Confirm password: ");
        io::stdout().flush().map_err(CryptError::FileAccess)?;

        let mut confirmation = rpassword::read_password()
            .map_err(|e| CryptError::FileAccess(io::Error::new(io::ErrorKind::Other, e)))?;

        if password != confirmation {
            confirmation.zeroize();
            return Err(CryptError::CliArgument(
                "Passwords do not match".to_string(),
            ));
        }

        confirmation.zeroize();
    }

    if password.is_empty() {
        return Err(CryptError::CliArgument(
            "Password cannot be empty".to_string(),
        ));
    }

    Ok(SecureString::new(password))
}

fn get_password_from_env(var_name: &str) -> Result<SecureString, CryptError> {
    let password = env::var(var_name).map_err(|_| {
        CryptError::CliArgument(format!("Environment variable {} not found", var_name))
    })?;

    if password.is_empty() {
        return Err(CryptError::CliArgument(
            "Password from environment cannot be empty".to_string(),
        ));
    }

    Ok(SecureString::new(password))
}

fn get_password_from_file(file_path: &str) -> Result<SecureString, CryptError> {
    let mut password = fs::read_to_string(file_path).map_err(CryptError::FileAccess)?;

    // Remove trailing newline if present
    if password.ends_with('\n') {
        password.pop();
        if password.ends_with('\r') {
            password.pop();
        }
    }

    if password.is_empty() {
        return Err(CryptError::CliArgument(
            "Password from file cannot be empty".to_string(),
        ));
    }

    Ok(SecureString::new(password))
}
