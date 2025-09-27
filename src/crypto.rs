use crate::error::CryptError;
use crate::memory::SecureVec;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use chacha20poly1305::{XChaCha20Poly1305, aead::OsRng as ChaChaOsRng};

pub const CHUNK_SIZE: usize = 512 * 1024; // 512KiB chunks balance CPU parallelism and bounded memory use

#[derive(Debug, Clone)]
pub struct EncryptedChunk {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum CipherType {
    Aes256Gcm,
    XChaCha20Poly1305,
}

impl CipherType {
    pub fn from_string(s: &str) -> Result<Self, CryptError> {
        match s {
            "aes-256-gcm" => Ok(CipherType::Aes256Gcm),
            "xchacha20poly1305" => Ok(CipherType::XChaCha20Poly1305),
            _ => Err(CryptError::InvalidCipher(format!(
                "Unsupported cipher: {}",
                s
            ))),
        }
    }

    pub fn to_string(&self) -> &'static str {
        match self {
            CipherType::Aes256Gcm => "aes-256-gcm",
            CipherType::XChaCha20Poly1305 => "xchacha20poly1305",
        }
    }

    pub fn to_id(&self) -> u16 {
        match self {
            CipherType::Aes256Gcm => 1,
            CipherType::XChaCha20Poly1305 => 2,
        }
    }

    pub fn from_id(id: u16) -> Result<Self, CryptError> {
        match id {
            1 => Ok(CipherType::Aes256Gcm),
            2 => Ok(CipherType::XChaCha20Poly1305),
            _ => Err(CryptError::InvalidCipher(format!(
                "Unsupported cipher id: {}",
                id
            ))),
        }
    }

    pub fn key_size(&self) -> usize {
        match self {
            CipherType::Aes256Gcm => 32,         // 256 bits
            CipherType::XChaCha20Poly1305 => 32, // 256 bits
        }
    }

    pub fn nonce_size(&self) -> usize {
        match self {
            CipherType::Aes256Gcm => 12,         // 96 bits
            CipherType::XChaCha20Poly1305 => 24, // 192 bits
        }
    }
}

#[derive(Clone)]
pub struct Cipher {
    cipher_type: CipherType,
    key: SecureVec<u8>,
}

impl Cipher {
    pub fn new(cipher_type: CipherType, key: SecureVec<u8>) -> Result<Self, CryptError> {
        if key.len() != cipher_type.key_size() {
            return Err(CryptError::Crypto(format!(
                "Invalid key size for {}: expected {}, got {}",
                cipher_type.to_string(),
                cipher_type.key_size(),
                key.len()
            )));
        }

        Ok(Cipher { cipher_type, key })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedChunk, CryptError> {
        match self.cipher_type {
            CipherType::Aes256Gcm => self.encrypt_aes_gcm(plaintext),
            CipherType::XChaCha20Poly1305 => self.encrypt_xchacha20poly1305(plaintext),
        }
    }

    pub fn decrypt(&self, chunk: &EncryptedChunk) -> Result<SecureVec<u8>, CryptError> {
        match self.cipher_type {
            CipherType::Aes256Gcm => self.decrypt_aes_gcm(&chunk.nonce, &chunk.ciphertext),
            CipherType::XChaCha20Poly1305 => {
                self.decrypt_xchacha20poly1305(&chunk.nonce, &chunk.ciphertext)
            }
        }
    }

    fn encrypt_aes_gcm(&self, plaintext: &[u8]) -> Result<EncryptedChunk, CryptError> {
        let cipher = Aes256Gcm::new_from_slice(self.key.as_slice())
            .map_err(|e| CryptError::Crypto(format!("Failed to create AES-GCM cipher: {}", e)))?;

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| CryptError::Crypto(format!("AES-GCM encryption failed: {}", e)))?;

        Ok(EncryptedChunk {
            nonce: nonce.to_vec(),
            ciphertext,
        })
    }

    fn decrypt_aes_gcm(
        &self,
        nonce_bytes: &[u8],
        ciphertext: &[u8],
    ) -> Result<SecureVec<u8>, CryptError> {
        if nonce_bytes.len() != self.cipher_type.nonce_size() {
            return Err(CryptError::CorruptedFile(
                "Invalid nonce length for AES-GCM".to_string(),
            ));
        }

        let nonce = Nonce::from_slice(nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(self.key.as_slice())
            .map_err(|e| CryptError::Crypto(format!("Failed to create AES-GCM cipher: {}", e)))?;

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptError::WrongPassword)?;

        Ok(SecureVec::new(plaintext))
    }

    fn encrypt_xchacha20poly1305(&self, plaintext: &[u8]) -> Result<EncryptedChunk, CryptError> {
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_slice()).map_err(|e| {
            CryptError::Crypto(format!("Failed to create XChaCha20Poly1305 cipher: {}", e))
        })?;

        let nonce = XChaCha20Poly1305::generate_nonce(&mut ChaChaOsRng);

        let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|e| {
            CryptError::Crypto(format!("XChaCha20Poly1305 encryption failed: {}", e))
        })?;

        Ok(EncryptedChunk {
            nonce: nonce.to_vec(),
            ciphertext,
        })
    }

    fn decrypt_xchacha20poly1305(
        &self,
        nonce_bytes: &[u8],
        ciphertext: &[u8],
    ) -> Result<SecureVec<u8>, CryptError> {
        if nonce_bytes.len() != self.cipher_type.nonce_size() {
            return Err(CryptError::CorruptedFile(
                "Invalid nonce length for XChaCha20Poly1305".to_string(),
            ));
        }

        let nonce = chacha20poly1305::XNonce::from_slice(nonce_bytes);

        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_slice()).map_err(|e| {
            CryptError::Crypto(format!("Failed to create XChaCha20Poly1305 cipher: {}", e))
        })?;

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptError::WrongPassword)?;

        Ok(SecureVec::new(plaintext))
    }
}
