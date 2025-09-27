use crate::error::CryptError;
use getrandom::fill;
use std::mem;
use zeroize::Zeroize;

const MAX_LOCKED_BYTES: usize = 64 * 1024; // 64KiB cap keeps key material locked but skips large streaming buffers.

#[cfg(unix)]
use libc::{mlock, munlock};

#[cfg(windows)]
use winapi::um::memoryapi::{VirtualLock, VirtualUnlock};

pub struct SecureString {
    data: Vec<u8>,
    locked: bool,
}

impl Drop for SecureString {
    fn drop(&mut self) {
        self.unlock_memory();
        self.data.zeroize();
    }
}

impl SecureString {
    pub fn new(mut s: String) -> Self {
        let data = s.as_bytes().to_vec();
        s.zeroize();

        let mut secure = SecureString {
            data,
            locked: false,
        };

        // Try to lock memory, but don't fail if it's not available
        let _ = secure.lock_memory();
        secure
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    fn lock_memory(&mut self) -> Result<(), CryptError> {
        if self.data.is_empty() {
            return Ok(());
        }

        #[cfg(unix)]
        {
            let result =
                unsafe { mlock(self.data.as_ptr() as *const libc::c_void, self.data.len()) };
            if result != 0 {
                return Err(CryptError::MemoryLock(
                    "Failed to lock memory on Unix".to_string(),
                ));
            }
        }

        #[cfg(windows)]
        {
            let result = unsafe {
                VirtualLock(
                    self.data.as_ptr() as *mut winapi::ctypes::c_void,
                    self.data.len(),
                )
            };
            if result == 0 {
                return Err(CryptError::MemoryLock(
                    "Failed to lock memory on Windows".to_string(),
                ));
            }
        }

        self.locked = true;
        Ok(())
    }

    fn unlock_memory(&mut self) {
        if !self.locked || self.data.is_empty() {
            return;
        }

        #[cfg(unix)]
        {
            unsafe {
                munlock(self.data.as_ptr() as *const libc::c_void, self.data.len());
            }
        }

        #[cfg(windows)]
        {
            unsafe {
                VirtualUnlock(
                    self.data.as_ptr() as *mut winapi::ctypes::c_void,
                    self.data.len(),
                );
            }
        }

        self.locked = false;
    }
}

pub struct SecureVec<T: Zeroize> {
    data: Vec<T>,
    locked: bool,
}

impl<T: Clone + Zeroize> Clone for SecureVec<T> {
    fn clone(&self) -> Self {
        SecureVec::new(self.data.clone())
    }
}

impl<T: Zeroize> Drop for SecureVec<T> {
    fn drop(&mut self) {
        self.unlock_memory();
        self.data.zeroize();
    }
}

impl<T: Zeroize> SecureVec<T> {
    pub fn new(data: Vec<T>) -> Self {
        let mut secure = SecureVec {
            data,
            locked: false,
        };

        // Only attempt to lock relatively small buffers to avoid expensive OS calls for large chunks.
        if secure.should_lock() {
            let _ = secure.lock_memory();
        }
        secure
    }

    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn into_vec(mut self) -> Vec<T> {
        self.unlock_memory();
        let data = mem::take(&mut self.data);
        self.locked = false;
        data
    }

    fn should_lock(&self) -> bool {
        let byte_len = self.data.len().saturating_mul(mem::size_of::<T>());
        byte_len <= MAX_LOCKED_BYTES
    }

    fn lock_memory(&mut self) -> Result<(), CryptError> {
        if self.data.is_empty() {
            return Ok(());
        }

        let size = self.data.len() * std::mem::size_of::<T>();

        #[cfg(unix)]
        {
            let result = unsafe { mlock(self.data.as_ptr() as *const libc::c_void, size) };
            if result != 0 {
                return Err(CryptError::MemoryLock(
                    "Failed to lock memory on Unix".to_string(),
                ));
            }
        }

        #[cfg(windows)]
        {
            let result =
                unsafe { VirtualLock(self.data.as_ptr() as *mut winapi::ctypes::c_void, size) };
            if result == 0 {
                return Err(CryptError::MemoryLock(
                    "Failed to lock memory on Windows".to_string(),
                ));
            }
        }

        self.locked = true;
        Ok(())
    }

    fn unlock_memory(&mut self) {
        if !self.locked || self.data.is_empty() {
            return;
        }

        let size = self.data.len() * std::mem::size_of::<T>();

        #[cfg(unix)]
        {
            unsafe {
                munlock(self.data.as_ptr() as *const libc::c_void, size);
            }
        }

        #[cfg(windows)]
        {
            unsafe {
                VirtualUnlock(self.data.as_ptr() as *mut winapi::ctypes::c_void, size);
            }
        }

        self.locked = false;
    }
}

pub fn secure_random_bytes(len: usize) -> Result<Vec<u8>, CryptError> {
    let mut bytes = vec![0u8; len];
    fill(&mut bytes)
        .map_err(|e| CryptError::Crypto(format!("Failed to generate random bytes: {}", e)))?;
    Ok(bytes)
}
