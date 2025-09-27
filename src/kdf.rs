use crate::error::CryptError;
use crate::memory::{SecureVec, secure_random_bytes};
use argon2::{Argon2, ParamsBuilder};

#[derive(Debug, Clone)]
pub struct KdfConfig {
    pub kdf_type: KdfType,
    pub salt: Vec<u8>,
    pub hash_length: usize,
}

#[derive(Debug, Clone)]
pub enum KdfType {
    Argon2id {
        time_cost: u32,
        memory_cost: u32,
        parallelism: u32,
    },
}

impl KdfConfig {
    pub fn new_argon2id(
        time_cost: u32,
        memory_cost: u32,
        parallelism: u32,
        salt_length: usize,
        hash_length: usize,
    ) -> Result<Self, CryptError> {
        let salt = secure_random_bytes(salt_length)?;

        Ok(KdfConfig {
            kdf_type: KdfType::Argon2id {
                time_cost,
                memory_cost,
                parallelism,
            },
            salt,
            hash_length,
        })
    }

    pub fn from_argon2id_params(
        time_cost: u32,
        memory_cost: u32,
        parallelism: u32,
        salt: Vec<u8>,
        hash_length: usize,
    ) -> Result<Self, CryptError> {
        if salt.is_empty() {
            return Err(CryptError::CorruptedFile(
                "Argon2id salt must not be empty".to_string(),
            ));
        }

        Ok(KdfConfig {
            kdf_type: KdfType::Argon2id {
                time_cost,
                memory_cost,
                parallelism,
            },
            salt,
            hash_length,
        })
    }

    pub fn argon2id_params(&self) -> (u32, u32, u32) {
        match &self.kdf_type {
            KdfType::Argon2id {
                time_cost,
                memory_cost,
                parallelism,
            } => (*time_cost, *memory_cost, *parallelism),
        }
    }

    pub fn derive_key(&self, password: &[u8]) -> Result<SecureVec<u8>, CryptError> {
        match &self.kdf_type {
            KdfType::Argon2id {
                time_cost,
                memory_cost,
                parallelism,
            } => {
                let params = ParamsBuilder::new()
                    .m_cost(*memory_cost)
                    .t_cost(*time_cost)
                    .p_cost(*parallelism)
                    .output_len(self.hash_length)
                    .build()
                    .map_err(|e| {
                        CryptError::InvalidKdfParameters(format!(
                            "Failed to build Argon2id params: {}",
                            e
                        ))
                    })?;

                let argon2 =
                    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

                let mut key = vec![0u8; self.hash_length];
                argon2
                    .hash_password_into(password, &self.salt, &mut key)
                    .map_err(|e| {
                        CryptError::Crypto(format!("Argon2id key derivation failed: {}", e))
                    })?;

                Ok(SecureVec::new(key))
            }
        }
    }
}
