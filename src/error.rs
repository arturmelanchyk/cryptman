use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptError {
    #[error("Wrong password during decryption")]
    WrongPassword,

    #[error("Corrupted or invalid file format: {0}")]
    CorruptedFile(String),

    #[error("Invalid KDF parameters: {0}")]
    InvalidKdfParameters(String),

    #[error("File access error: {0}")]
    FileAccess(#[from] std::io::Error),

    #[error("CLI argument error: {0}")]
    CliArgument(String),

    #[error("Memory locking failed: {0}")]
    MemoryLock(String),

    #[error("Cryptographic operation failed: {0}")]
    Crypto(String),

    #[error("Invalid cipher: {0}")]
    InvalidCipher(String),

    #[error("Unsupported file version: {0}")]
    UnsupportedVersion(u32),
}

impl CryptError {
    pub fn exit_code(&self) -> i32 {
        match self {
            CryptError::WrongPassword => 1,
            CryptError::CorruptedFile(_) => 2,
            CryptError::InvalidKdfParameters(_) => 3,
            CryptError::FileAccess(_) => 4,
            CryptError::CliArgument(_) => 5,
            CryptError::MemoryLock(_) => 5,
            CryptError::Crypto(_) => 2,
            CryptError::InvalidCipher(_) => 5,
            CryptError::UnsupportedVersion(_) => 2,
        }
    }
}
