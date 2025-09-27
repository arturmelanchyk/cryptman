use crate::crypto::{CHUNK_SIZE, Cipher, CipherType, EncryptedChunk};
use crate::error::CryptError;
use crate::kdf::KdfConfig;
use crate::memory::{SecureString, SecureVec};
use crate::progress;
use crossbeam_channel::{Receiver, Sender, TryRecvError, bounded};
use indicatif::ProgressBar;
use std::cmp;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::Path;
use std::thread;
use std::time::Instant;
use zeroize::Zeroize;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const MAGIC: [u8; 4] = [0xF0, 0x9F, 0x94, 0x90]; // U+1F510 "🔐"
const FILE_VERSION: u32 = 1;
const FLAG_CHUNKED: u32 = 0x0000_0001;
const MAX_PIPELINE_INFLIGHT: usize = 16; // Cap in-flight chunks to keep memory usage bounded.

#[derive(Clone)]
struct FileHeader {
    version: u32,
    cipher: CipherType,
    kdf_config: KdfConfig,
    payload: PayloadKind,
}

#[derive(Clone)]
enum PayloadKind {
    Single,
    Chunked { chunk_count: u32 },
}

struct IndexedChunk<T> {
    index: u32,
    data: T,
}

impl PayloadKind {
    fn is_chunked(&self) -> bool {
        matches!(self, PayloadKind::Chunked { .. })
    }

    fn chunk_count(&self) -> u32 {
        match self {
            PayloadKind::Single => 1,
            PayloadKind::Chunked { chunk_count } => *chunk_count,
        }
    }
}

pub fn encrypt_file(
    input_path: &str,
    output_path: &str,
    kdf_config: &KdfConfig,
    cipher_type: &CipherType,
    key: &SecureVec<u8>,
    force: bool,
) -> Result<(), CryptError> {
    let input_file = File::open(input_path)?;
    let file_size = input_file.metadata()?.len();
    let mut reader = BufReader::new(input_file);

    let total_chunks = calculate_chunk_count(file_size)?;
    let payload = if total_chunks > 1 {
        PayloadKind::Chunked {
            chunk_count: total_chunks as u32,
        }
    } else {
        PayloadKind::Single
    };

    let header = FileHeader {
        version: FILE_VERSION,
        cipher: cipher_type.clone(),
        kdf_config: kdf_config.clone(),
        payload: payload.clone(),
    };

    let cipher = Cipher::new(cipher_type.clone(), SecureVec::new(key.as_slice().to_vec()))?;

    if output_path == "-" {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        write_header(&mut handle, &header)?;
        encrypt_payload(&mut reader, &mut handle, &cipher, &payload, file_size)?;
        handle.flush()?;
    } else {
        if Path::new(output_path).exists() && !force {
            return Err(CryptError::FileAccess(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "Output file '{}' already exists. Use --force to overwrite.",
                    output_path
                ),
            )));
        }

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(output_path)?;

        #[cfg(unix)]
        {
            let mut permissions = file.metadata()?.permissions();
            permissions.set_mode(0o600);
            file.set_permissions(permissions)?;
        }

        write_header(&mut file, &header)?;
        encrypt_payload(&mut reader, &mut file, &cipher, &payload, file_size)?;
        file.sync_all()?;
    }

    Ok(())
}

pub fn decrypt_file(
    input_path: &str,
    output_path: &str,
    password: &SecureString,
    force: bool,
) -> Result<(), CryptError> {
    if output_path != "-" && Path::new(output_path).exists() && !force {
        return Err(CryptError::FileAccess(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "Output file '{}' already exists. Use --force to overwrite.",
                output_path
            ),
        )));
    }

    if input_path == "-" {
        let stdin = io::stdin();
        let mut reader = stdin.lock();
        decrypt_from_reader(&mut reader, output_path, password)
    } else {
        let file = File::open(input_path)?;
        let mut reader = BufReader::new(file);
        decrypt_from_reader(&mut reader, output_path, password)
    }
}

fn decrypt_from_reader<R: Read>(
    reader: &mut R,
    output_path: &str,
    password: &SecureString,
) -> Result<(), CryptError> {
    let header = read_header(reader)?;

    let key_pb = progress::create_bar("Key derivation", 1);
    let key_start = Instant::now();
    let key = header.kdf_config.derive_key(password.as_bytes())?;
    progress::complete_with_duration(&key_pb, key_start);

    let cipher = Cipher::new(
        header.cipher.clone(),
        SecureVec::new(key.as_slice().to_vec()),
    )?;

    if output_path == "-" {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        decrypt_payload(reader, &mut handle, &cipher, &header.payload)?;
        handle.flush()?;
    } else {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(output_path)?;

        #[cfg(unix)]
        {
            let mut permissions = file.metadata()?.permissions();
            permissions.set_mode(0o600);
            file.set_permissions(permissions)?;
        }

        decrypt_payload(reader, &mut file, &cipher, &header.payload)?;
        file.sync_all()?;
    }

    Ok(())
}

fn write_header<W: Write>(writer: &mut W, header: &FileHeader) -> Result<(), CryptError> {
    writer.write_all(&MAGIC)?;
    writer.write_all(&header.version.to_le_bytes())?;

    let mut flags = 0u32;
    if header.payload.is_chunked() {
        flags |= FLAG_CHUNKED;
    }
    writer.write_all(&flags.to_le_bytes())?;
    writer.write_all(&header.cipher.to_id().to_le_bytes())?;

    let (time_cost, memory_cost, parallelism) = header.kdf_config.argon2id_params();
    writer.write_all(&time_cost.to_le_bytes())?;
    writer.write_all(&memory_cost.to_le_bytes())?;
    writer.write_all(&parallelism.to_le_bytes())?;

    let salt_len = u16::try_from(header.kdf_config.salt.len())
        .map_err(|_| CryptError::Crypto("Salt too large to encode".to_string()))?;
    writer.write_all(&salt_len.to_le_bytes())?;
    writer.write_all(&header.kdf_config.salt)?;

    let hash_length = u16::try_from(header.kdf_config.hash_length)
        .map_err(|_| CryptError::Crypto("Hash length too large to encode".to_string()))?;
    writer.write_all(&hash_length.to_le_bytes())?;

    if let PayloadKind::Chunked { chunk_count } = header.payload {
        writer.write_all(&chunk_count.to_le_bytes())?;
    }

    Ok(())
}

fn read_header<R: Read>(reader: &mut R) -> Result<FileHeader, CryptError> {
    let mut magic = [0u8; 4];
    read_exact_checked(reader, &mut magic)?;
    if magic != MAGIC {
        return Err(CryptError::CorruptedFile(
            "Invalid magic prefix".to_string(),
        ));
    }

    let version = read_u32(reader)?;
    if version > FILE_VERSION {
        return Err(CryptError::UnsupportedVersion(version));
    }

    let flags = read_u32(reader)?;
    let cipher_id = read_u16(reader)?;
    let cipher = CipherType::from_id(cipher_id)?;

    let time_cost = read_u32(reader)?;
    let memory_cost = read_u32(reader)?;
    let parallelism = read_u32(reader)?;

    let salt_len = read_u16(reader)? as usize;
    if salt_len == 0 {
        return Err(CryptError::CorruptedFile("Salt length is zero".to_string()));
    }
    let mut salt = vec![0u8; salt_len];
    read_exact_checked(reader, &mut salt)?;

    let hash_length = read_u16(reader)? as usize;
    if hash_length == 0 {
        return Err(CryptError::CorruptedFile("Hash length is zero".to_string()));
    }

    let kdf_config =
        KdfConfig::from_argon2id_params(time_cost, memory_cost, parallelism, salt, hash_length)?;

    let payload = if flags & FLAG_CHUNKED != 0 {
        let chunk_count = read_u32(reader)?;
        if chunk_count == 0 {
            return Err(CryptError::CorruptedFile(
                "Chunked payload with zero chunks".to_string(),
            ));
        }
        PayloadKind::Chunked { chunk_count }
    } else {
        PayloadKind::Single
    };

    Ok(FileHeader {
        version,
        cipher,
        kdf_config,
        payload,
    })
}

fn encrypt_payload<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    cipher: &Cipher,
    payload: &PayloadKind,
    file_size: u64,
) -> Result<(), CryptError> {
    let total_chunks = payload.chunk_count() as u64;
    let progress_bar = progress::create_bar("Encryption", total_chunks);
    let start = Instant::now();

    match payload {
        PayloadKind::Single => {
            let capacity = usize::try_from(file_size).unwrap_or(0);
            let mut buffer = Vec::with_capacity(capacity);
            reader.read_to_end(&mut buffer)?;
            let chunk = cipher.encrypt(&buffer)?;
            write_chunk(writer, &chunk)?;
            progress_bar.set_position(total_chunks);
        }
        PayloadKind::Chunked { chunk_count } => {
            progress_bar.set_length(*chunk_count as u64);
            let worker_count = cmp::max(
                1,
                cmp::min(
                    num_cpus::get(),
                    cmp::min(*chunk_count as usize, MAX_PIPELINE_INFLIGHT),
                ),
            );
            let queue_bound = cmp::max(1, cmp::min(worker_count * 2, MAX_PIPELINE_INFLIGHT));
            let (task_tx, task_rx): (
                Sender<IndexedChunk<Vec<u8>>>,
                Receiver<IndexedChunk<Vec<u8>>>,
            ) = bounded(queue_bound);
            let (result_tx, result_rx) =
                bounded::<Result<IndexedChunk<EncryptedChunk>, CryptError>>(queue_bound);

            let scope_result = thread::scope(|scope| -> Result<(), CryptError> {
                for _ in 0..worker_count {
                    let worker_cipher = cipher.clone();
                    let worker_rx = task_rx.clone();
                    let worker_tx = result_tx.clone();
                    scope.spawn(move || {
                        while let Ok(task) = worker_rx.recv() {
                            let result =
                                worker_cipher.encrypt(&task.data).map(|chunk| IndexedChunk {
                                    index: task.index,
                                    data: chunk,
                                });
                            if worker_tx.send(result).is_err() {
                                break;
                            }
                        }
                    });
                }

                drop(result_tx);

                let mut remaining = file_size;
                let mut pending: BTreeMap<u32, EncryptedChunk> = BTreeMap::new();
                let mut next_index: u32 = 0;
                let mut received: u32 = 0;

                for index in 0..*chunk_count {
                    let expected = if index + 1 < *chunk_count {
                        CHUNK_SIZE
                    } else {
                        remaining as usize
                    };

                    let mut chunk_data = vec![0u8; expected];
                    reader.read_exact(&mut chunk_data)?;
                    remaining = remaining.saturating_sub(expected as u64);

                    task_tx
                        .send(IndexedChunk {
                            index,
                            data: chunk_data,
                        })
                        .map_err(|_| {
                            CryptError::Crypto("Failed to dispatch encryption work".to_string())
                        })?;

                    drain_encrypted_results(
                        &result_rx,
                        writer,
                        &progress_bar,
                        &mut pending,
                        &mut next_index,
                        &mut received,
                    )?;
                }

                drop(task_tx);

                while received < *chunk_count {
                    let indexed_chunk = result_rx.recv().map_err(|_| {
                        CryptError::Crypto("Encryption worker terminated unexpectedly".to_string())
                    })??;
                    received += 1;
                    handle_encrypted_chunk(
                        writer,
                        &progress_bar,
                        &mut pending,
                        &mut next_index,
                        indexed_chunk,
                    )?;
                }

                Ok(())
            });

            scope_result?;
        }
    }

    progress::complete_with_duration(&progress_bar, start);
    Ok(())
}

fn decrypt_payload<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    cipher: &Cipher,
    payload: &PayloadKind,
) -> Result<(), CryptError> {
    let total_chunks = payload.chunk_count() as u64;
    let progress_bar = progress::create_bar("Decryption", total_chunks);
    let start = Instant::now();

    match payload {
        PayloadKind::Single => {
            let chunk = read_encrypted_chunk(reader)?;
            let plaintext = cipher.decrypt(&chunk)?;
            writer.write_all(plaintext.as_slice())?;
            progress_bar.set_position(total_chunks);
        }
        PayloadKind::Chunked { chunk_count } => {
            progress_bar.set_length(*chunk_count as u64);
            let worker_count = cmp::max(
                1,
                cmp::min(
                    num_cpus::get(),
                    cmp::min(*chunk_count as usize, MAX_PIPELINE_INFLIGHT),
                ),
            );
            // Keep a deeper task buffer so worker threads stay busy while this thread writes plaintext.
            let queue_bound = cmp::max(1, cmp::min(worker_count * 4, MAX_PIPELINE_INFLIGHT));
            let (task_tx, task_rx): (
                Sender<IndexedChunk<EncryptedChunk>>,
                Receiver<IndexedChunk<EncryptedChunk>>,
            ) = bounded(queue_bound);
            let (result_tx, result_rx) =
                bounded::<Result<IndexedChunk<Vec<u8>>, CryptError>>(queue_bound);
            let (zero_tx, zero_rx) = bounded::<Vec<u8>>(queue_bound);
            let zeroizer_count = cmp::max(1, cmp::min(worker_count, queue_bound));

            let scope_result = thread::scope(|scope| -> Result<(), CryptError> {
                for _ in 0..worker_count {
                    let worker_cipher = cipher.clone();
                    let worker_rx = task_rx.clone();
                    let worker_tx = result_tx.clone();
                    scope.spawn(move || {
                        while let Ok(task) = worker_rx.recv() {
                            let result = worker_cipher.decrypt(&task.data).map(|plaintext| {
                                let data = plaintext.into_vec();
                                IndexedChunk {
                                    index: task.index,
                                    data,
                                }
                            });
                            if worker_tx.send(result).is_err() {
                                break;
                            }
                        }
                    });
                }

                for _ in 0..zeroizer_count {
                    let zero_rx = zero_rx.clone();
                    scope.spawn(move || {
                        while let Ok(mut buf) = zero_rx.recv() {
                            buf.zeroize();
                        }
                    });
                }

                drop(result_tx);
                drop(zero_rx);

                let mut pending: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
                let mut next_index: u32 = 0;
                let mut received: u32 = 0;
                let mut dispatched: u32 = 0;
                let mut inflight: u32 = 0;
                let chunk_total = *chunk_count;
                let queue_limit = queue_bound as u32;
                let zero_tx_main = zero_tx.clone();

                while received < chunk_total {
                    // Fill the work queue up to the bound before draining results to avoid starving workers.
                    while dispatched < chunk_total && inflight < queue_limit {
                        let chunk = read_encrypted_chunk(reader)?;
                        task_tx
                            .send(IndexedChunk {
                                index: dispatched,
                                data: chunk,
                            })
                            .map_err(|_| {
                                CryptError::Crypto("Failed to dispatch decryption work".to_string())
                            })?;
                        dispatched += 1;
                        inflight += 1;
                    }

                    let indexed_plaintext = result_rx.recv().map_err(|_| {
                        CryptError::Crypto("Decryption worker terminated unexpectedly".to_string())
                    })??;
                    received += 1;
                    inflight = inflight.saturating_sub(1);

                    handle_plaintext_chunk(
                        writer,
                        &progress_bar,
                        &mut pending,
                        &mut next_index,
                        indexed_plaintext,
                        &zero_tx_main,
                    )?;
                }

                drop(task_tx);
                drop(zero_tx_main);
                drop(zero_tx);

                Ok(())
            });

            scope_result?;
        }
    }

    progress::complete_with_duration(&progress_bar, start);
    Ok(())
}

fn drain_encrypted_results<W: Write>(
    result_rx: &Receiver<Result<IndexedChunk<EncryptedChunk>, CryptError>>,
    writer: &mut W,
    progress_bar: &ProgressBar,
    pending: &mut BTreeMap<u32, EncryptedChunk>,
    next_index: &mut u32,
    received: &mut u32,
) -> Result<(), CryptError> {
    loop {
        match result_rx.try_recv() {
            Ok(indexed_chunk) => {
                let indexed_chunk = indexed_chunk?;
                *received += 1;
                handle_encrypted_chunk(writer, progress_bar, pending, next_index, indexed_chunk)?;
            }
            Err(TryRecvError::Empty) => return Ok(()),
            Err(TryRecvError::Disconnected) => {
                return Err(CryptError::Crypto(
                    "Encryption workers disconnected unexpectedly".to_string(),
                ));
            }
        }
    }
}

fn handle_encrypted_chunk<W: Write>(
    writer: &mut W,
    progress_bar: &ProgressBar,
    pending: &mut BTreeMap<u32, EncryptedChunk>,
    next_index: &mut u32,
    chunk: IndexedChunk<EncryptedChunk>,
) -> Result<(), CryptError> {
    let IndexedChunk { index, data } = chunk;

    if index == *next_index {
        write_chunk(writer, &data)?;
        progress_bar.inc(1);
        *next_index += 1;

        while let Some(next_chunk) = pending.remove(next_index) {
            write_chunk(writer, &next_chunk)?;
            progress_bar.inc(1);
            *next_index += 1;
        }
    } else {
        pending.insert(index, data);
    }

    Ok(())
}

fn handle_plaintext_chunk<W: Write>(
    writer: &mut W,
    progress_bar: &ProgressBar,
    pending: &mut BTreeMap<u32, Vec<u8>>,
    next_index: &mut u32,
    chunk: IndexedChunk<Vec<u8>>,
    zero_tx: &Sender<Vec<u8>>,
) -> Result<(), CryptError> {
    let IndexedChunk { index, data } = chunk;

    if index == *next_index {
        write_plaintext_chunk(writer, progress_bar, zero_tx, data)?;
        *next_index += 1;

        while let Some(next_plain) = pending.remove(next_index) {
            write_plaintext_chunk(writer, progress_bar, zero_tx, next_plain)?;
            *next_index += 1;
        }
    } else {
        pending.insert(index, data);
    }

    Ok(())
}

fn write_plaintext_chunk<W: Write>(
    writer: &mut W,
    progress_bar: &ProgressBar,
    zero_tx: &Sender<Vec<u8>>,
    data: Vec<u8>,
) -> Result<(), CryptError> {
    writer.write_all(data.as_slice())?;
    progress_bar.inc(1);
    zero_tx
        .send(data)
        .map_err(|_| CryptError::Crypto("Failed to schedule plaintext zeroization".to_string()))?;
    Ok(())
}

fn write_chunk<W: Write>(writer: &mut W, chunk: &EncryptedChunk) -> Result<(), CryptError> {
    let nonce_len = u16::try_from(chunk.nonce.len())
        .map_err(|_| CryptError::Crypto("Nonce too large to encode".to_string()))?;
    writer.write_all(&nonce_len.to_le_bytes())?;
    writer.write_all(&chunk.nonce)?;

    let ciphertext_len = u32::try_from(chunk.ciphertext.len())
        .map_err(|_| CryptError::Crypto("Ciphertext too large to encode".to_string()))?;
    writer.write_all(&ciphertext_len.to_le_bytes())?;
    writer.write_all(&chunk.ciphertext)?;

    Ok(())
}

fn read_encrypted_chunk<R: Read>(reader: &mut R) -> Result<EncryptedChunk, CryptError> {
    let nonce_len = read_u16(reader)? as usize;
    if nonce_len == 0 {
        return Err(CryptError::CorruptedFile(
            "Nonce length is zero".to_string(),
        ));
    }
    let mut nonce = vec![0u8; nonce_len];
    read_exact_checked(reader, &mut nonce)?;

    let ciphertext_len = read_u32(reader)? as usize;
    if ciphertext_len == 0 {
        return Err(CryptError::CorruptedFile(
            "Ciphertext length is zero".to_string(),
        ));
    }
    let mut ciphertext = vec![0u8; ciphertext_len];
    read_exact_checked(reader, &mut ciphertext)?;

    Ok(EncryptedChunk { nonce, ciphertext })
}

fn calculate_chunk_count(file_size: u64) -> Result<u64, CryptError> {
    let chunk_size = CHUNK_SIZE as u64;
    let chunks = if file_size == 0 {
        1
    } else {
        (file_size + chunk_size - 1) / chunk_size
    };

    if chunks > u32::MAX as u64 {
        return Err(CryptError::Crypto(
            "File too large to encrypt with chunk metadata".to_string(),
        ));
    }

    Ok(chunks)
}

fn read_u16<R: Read>(reader: &mut R) -> Result<u16, CryptError> {
    let mut buf = [0u8; 2];
    read_exact_checked(reader, &mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

fn read_u32<R: Read>(reader: &mut R) -> Result<u32, CryptError> {
    let mut buf = [0u8; 4];
    read_exact_checked(reader, &mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_exact_checked<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<(), CryptError> {
    reader.read_exact(buf).map_err(|err| {
        if err.kind() == io::ErrorKind::UnexpectedEof {
            CryptError::CorruptedFile("Unexpected end of file".to_string())
        } else {
            CryptError::FileAccess(err)
        }
    })
}
