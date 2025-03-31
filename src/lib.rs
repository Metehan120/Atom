use aes_gcm::{ aead::{ Aead, OsRng }, AeadCore, Key, KeyInit };
use memchr;
use rayon::prelude::*;
use thiserror::Error;
use std::{ result::Result, fs::File, io::{ Read, Write }, sync::Arc };
use std::sync::{ LazyLock, RwLock };

#[derive(Clone)]
pub enum Algorithms {
    LZ4,
    ZSTD,
}

#[derive(Error, Debug)]
pub enum Errors {
    #[error("File not found")]
    FileNotFound,
    #[error("File already exists")]
    FileAlreadyExists,
    #[error("AES encryption error: {0}")] AesEncryptionError(String),
    #[error("AES decryption error: {0}")] AesDecryptionError(String),
    #[error("Compression error: {0}")] CompressionError(String),
    #[error("Decompression error: {0}")] DecompressionError(String),
    #[error("Hashing error: {0}")] HashingError(String),
    #[error("File IO error: {0}")] FileIOError(String),
    #[error("Database error: {0}")] DatabaseError(String),
    #[error("Invalid algorithm: {0}")] InvalidAlgorithm(String),
    #[error("Invalid password: {0}")] InvalidPassword(String),
    #[error("Invalid data: {0}")] InvalidData(String),
    #[error("Invalid nonce: {0}")] InvalidNonce(String),
    #[error("Invalid key: {0}")] InvalidKey(String),
    #[error("Invalid entry: {0}")] InvalidEntry(String),
    #[error("Invalid length: {0}")] InvalidLength(String),
    #[error("Invalid value: {0}")] InvalidValue(String),
    #[error("Invalid format: {0}")] InvalidFormat(String),
    #[error("Invalid data block: {0}")] InvalidDataBlock(String),
    #[error("Invalid database file: {0}")] InvalidDatabaseFile(String),
    #[error("RW lock error: {0}")] RwLockError(String),
    #[error("Tokio runtime error: {0}")] TokioRuntimeError(String),
    #[error("Thread pool error: {0}")] ThreadPoolError(String),
    #[error("File is already exists: {0}")] FileAlreadyExistsError(String),
}

static PASSWORD: LazyLock<RwLock<String>> = LazyLock::new(|| RwLock::new(String::new()));
static ALGORITHM: LazyLock<RwLock<Algorithms>> = LazyLock::new(|| RwLock::new(Algorithms::ZSTD));

pub fn set_algorithm(new_algorithm: Algorithms) -> Result<(), Errors> {
    let mut algorithm_guard = ALGORITHM.write().map_err(|e| Errors::RwLockError(e.to_string()))?;
    *algorithm_guard = new_algorithm;

    Ok(())
}

fn get_algorithm() -> Result<Algorithms, Errors> {
    let algorithm_guard = ALGORITHM.read().map_err(|e| Errors::RwLockError(e.to_string()))?;
    Ok(algorithm_guard.clone())
}

pub fn set_password(new_password: &str) -> Result<(), Errors> {
    let mut password_guard = PASSWORD.write().map_err(|e| Errors::RwLockError(e.to_string()))?;
    *password_guard = new_password.into();

    Ok(())
}

fn get_password() -> Result<String, Errors> {
    let password_guard = PASSWORD.read().map_err(|e| Errors::RwLockError(e.to_string()))?;
    Ok(password_guard.clone())
}

fn compress(content: Vec<u8>) -> Result<Vec<u8>, Errors> {
    let compressed_data = match get_algorithm()? {
        Algorithms::LZ4 => lz4_flex::compress_prepend_size(&content),
        Algorithms::ZSTD =>
            zstd
                ::encode_all(content.as_slice(), 0)
                .map_err(|e| Errors::CompressionError(e.to_string()))?,
    };
    Ok(compressed_data)
}

fn decompress(content: Vec<u8>) -> Result<Vec<u8>, Errors> {
    let decompressed_data = match get_algorithm()? {
        Algorithms::LZ4 =>
            lz4_flex
                ::decompress_size_prepended(&content)
                .map_err(|e| Errors::DecompressionError(e.to_string()))?,
        Algorithms::ZSTD =>
            zstd
                ::decode_all(content.as_slice())
                .map_err(|e| Errors::DecompressionError(e.to_string()))?,
    };

    Ok(decompressed_data)
}

fn hash_file_name(input: &str) -> String {
    let hash = blake3::hash(input.as_bytes());
    hash.to_hex()[..64].to_string()
}

fn hash_key(input: &str) -> [u8; 32] {
    let hash = blake3::hash(input.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash.as_bytes()[..32]);
    key
}

fn aes_encryption(data: Vec<u8>) -> std::result::Result<(Vec<u8>, Vec<u8>), Errors> {
    let key = hash_key(get_password()?.as_str());
    let key = Key::<aes_gcm::Aes256Gcm>::from_slice(&key);
    let cipher = aes_gcm::Aes256Gcm::new(key);
    let nonce = aes_gcm::Aes256Gcm::generate_nonce(&mut OsRng);

    let out = cipher
        .encrypt(&nonce, data.as_ref())
        .map_err(|e| Errors::AesEncryptionError(e.to_string()))?;

    Ok((out, nonce.to_vec()))
}

fn aes_decryption(data: Vec<u8>, nonce_bytes: Vec<u8>) -> Result<Vec<u8>, Errors> {
    let key_hash = hash_key(get_password()?.as_str());
    let key = Key::<aes_gcm::Aes256Gcm>::from_slice(&key_hash);
    let cipher = aes_gcm::Aes256Gcm::new(&key);
    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes.as_slice());

    cipher.decrypt(nonce, &*data).map_err(|e| Errors::AesDecryptionError(e.to_string()))
}

pub fn initialize(database_file_name: &str) -> Result<(), Errors> {
    let mut file = match std::fs::File::open(database_file_name) {
        Ok(file) => file,
        Err(_) =>
            std::fs::File
                ::create(database_file_name)
                .map_err(|e| { Errors::FileIOError(e.to_string()) })?,
    };

    file
        .write_all(
            format!(
                "ATOM: 0X1B4;STD-FEATURE: THREAD-PARALLEL;DATA-BASE-NAME: {database_file_name};\n"
            ).as_bytes()
        )
        .map_err(|e| Errors::FileIOError(e.to_string()))?;

    Ok(())
}

pub async fn find_data_block(line_to_find: &[u8], content: Vec<u8>) -> Result<Vec<u8>, Errors> {
    let mut search_pattern = Vec::from(line_to_find);
    search_pattern.extend_from_slice(&[b':', b' ']);

    tokio::task
        ::spawn_blocking(move || {
            if let Some(start) = memchr::memmem::find(&content, &search_pattern) {
                let start_index = start + search_pattern.len();

                if let Some(pipe_index) = memchr::memmem::find(&content[start_index..], b"|") {
                    let len_bytes = content[start_index..start_index + pipe_index].to_vec();
                    let len = len_bytes
                        .iter()
                        .fold(0usize, |acc, &b| acc * 10 + ((b - b'0') as usize));
                    let value_start = start_index + pipe_index + 1;
                    let len = std::cmp::min(len, content.len() - value_start);
                    if value_start + len <= content.len() {
                        return content[value_start..value_start + len].to_vec();
                    }
                }
            }

            Vec::new()
        }).await
        .map_err(|e| Errors::TokioRuntimeError(e.to_string()))
}

pub async fn read_data_block(data_file_name: &str, database_file: &str) -> Result<Vec<u8>, Errors> {
    let mut database_data_vector = Vec::new();
    let mut database_file = std::fs::File
        ::open(database_file)
        .map_err(|e| { Errors::FileIOError(e.to_string()) })?;
    database_file
        .read_to_end(&mut database_data_vector)
        .map_err(|e| { Errors::FileIOError(e.to_string()) })?;

    let database_data_vector = Arc::new(database_data_vector);

    match
        !memchr::memmem
            ::find(
                &database_data_vector,
                hash_file_name(format!("{}.nonce", data_file_name).as_str()).as_bytes()
            )
            .is_none()
    {
        true => {
            let nonce_file_name = hash_file_name(format!("{}.nonce", data_file_name).as_str());
            let data_file_name = hash_file_name(data_file_name);
            let nonce = find_data_block(
                nonce_file_name.as_bytes(),
                (*database_data_vector).clone()
            ).await;
            let file_data = find_data_block(
                data_file_name.as_bytes(),
                (*database_data_vector).clone()
            ).await;
            let decrypted_data = tokio::task
                ::spawn_blocking(move || {
                    match (file_data, nonce) {
                        (Ok(file_data), Ok(nonce)) =>
                            aes_decryption(file_data, nonce).unwrap_or_else(|e| {
                                panic!("Error: {}", e)
                            }),
                        _ => Vec::new(),
                    }
                }).await
                .map_err(|e| Errors::TokioRuntimeError(e.to_string()))?;

            let decompressed_data = tokio::task
                ::spawn_blocking(move || decompress(decrypted_data)).await
                .unwrap()
                .map_err(|e| Errors::DecompressionError(e.to_string()))?;

            return Ok(decompressed_data);
        }
        false => {
            let data_file_name = hash_file_name(data_file_name);
            let find_result = find_data_block(
                data_file_name.as_bytes(),
                (*database_data_vector).clone()
            ).await;
            return tokio::task
                ::spawn_blocking(move || find_result.and_then(decompress)).await
                .map_err(|e| Errors::TokioRuntimeError(e.to_string()))?
                .map_err(|e| Errors::DecompressionError(e.to_string()));
        }
    }
}

pub async fn read_multiple_data_block(
    data_file_names: Vec<&str>,
    database_file: &str
) -> Result<Vec<Vec<u8>>, Errors> {
    let mut database_data_vector = Vec::new();
    let mut database_file = std::fs::File
        ::open(database_file)
        .map_err(|e| { Errors::FileIOError(e.to_string()) })?;
    database_file
        .read_to_end(&mut database_data_vector)
        .map_err(|e| { Errors::FileIOError(e.to_string()) })?;

    let database_data_vector = Arc::new(database_data_vector);

    let mut out_data_vector = Vec::new();

    for i in data_file_names {
        match
            !memchr::memmem
                ::find(
                    &*database_data_vector,
                    hash_file_name(format!("{}.nonce", i).as_str()).as_bytes()
                )
                .is_none()
        {
            true => {
                let data_file_name = hash_file_name(i);
                let nonce_file_name = format!("{}.nonce", i);
                let nonce_file_name = hash_file_name(&nonce_file_name);
                let nonce = find_data_block(
                    nonce_file_name.as_bytes(),
                    (*database_data_vector).clone()
                ).await;
                let file_data = find_data_block(
                    data_file_name.as_bytes(),
                    (*database_data_vector).clone()
                ).await;

                let decompressed_data = tokio::task
                    ::spawn_blocking(move || {
                        let decrypted_data = match (file_data, nonce) {
                            (Ok(file_data), Ok(nonce)) =>
                                aes_decryption(file_data, nonce).unwrap_or_else(|e| {
                                    panic!("Error: {}", e)
                                }),
                            _ => panic!("Error: Invalid file data or nonce"),
                        };
                        decompress(decrypted_data)
                    }).await
                    .map_err(|e| Errors::TokioRuntimeError(e.to_string()))?;

                out_data_vector.push(decompressed_data);
            }
            false => {
                let find_result = find_data_block(
                    hash_file_name(i).as_bytes(),
                    (*database_data_vector).clone()
                ).await;

                let decompressed_data = tokio::task::spawn_blocking(move || {
                    find_result
                        .and_then(decompress)
                        .unwrap_or_else(|e| { panic!("Error during decompression: {}", e) })
                });
                out_data_vector.push(
                    Ok(
                        decompressed_data.await.map_err(|e| {
                            Errors::TokioRuntimeError(e.to_string())
                        })?
                    )
                );
            }
        }
    }

    out_data_vector.into_iter().collect::<Result<Vec<_>, _>>()
}

pub async fn remove_data_block(
    data_file_names: Vec<&str>,
    database_file_name: &str
) -> Result<(), Errors> {
    let remove_entry = |entry_name: &str, file_data: &mut Vec<u8>| {
        let mut search_pattern = Vec::from(entry_name.as_bytes());
        search_pattern.extend_from_slice(&[b':', b' ']);

        if let Some(start) = memchr::memmem::find(file_data, &search_pattern) {
            let start_index = start + search_pattern.len();

            if let Some(pipe_index) = file_data[start_index..].iter().position(|&b| b == b'|') {
                let len_bytes = &file_data[start_index..start_index + pipe_index];
                let len = len_bytes.iter().fold(0usize, |acc, &b| acc * 10 + ((b - b'0') as usize));
                let value_start = start_index + pipe_index + 1;
                let value_end = value_start + len;

                if value_end < file_data.len() {
                    // finds the end value
                    let end = file_data[value_end..]
                        .iter()
                        .position(|&b| b == b';')
                        .map(|e| value_end + e)
                        .unwrap_or(file_data.len());

                    file_data.par_drain(start..=end);
                }
            }
        }
    };

    let mut database_data_vector = Vec::new();
    let mut database_file = std::fs::File
        ::open(database_file_name)
        .map_err(|e| { Errors::FileIOError(e.to_string()) })?;
    database_file
        .read_to_end(&mut database_data_vector)
        .map_err(|e| { Errors::FileIOError(e.to_string()) })?;

    for i in data_file_names {
        let i = &hash_file_name(i);
        remove_entry(i, &mut database_data_vector);

        if
            !memchr::memmem
                ::find(
                    &database_data_vector,
                    hash_file_name(format!("{}.nonce", i).as_str()).as_bytes()
                )
                .is_none()
        {
            let nonce_file_name = format!("{}.nonce", i);
            let nonce_file_name = hash_file_name(&nonce_file_name);
            remove_entry(&nonce_file_name, &mut database_data_vector);
        }
    }

    let database_file = std::fs::OpenOptions
        ::new()
        .write(true)
        .truncate(true)
        .open(database_file_name)
        .map_err(|e| Errors::FileIOError(e.to_string()));
    database_file?
        .write_all(&database_data_vector)
        .map_err(|e| { Errors::FileIOError(e.to_string()) })?;

    Ok(())
}

pub async fn add_data_block(
    data_files: Vec<&str>,
    database_file: &str,
    encrypt: bool
) -> Result<(), Errors> {
    let data_file = Arc::new(
        data_files
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
    );

    let database_file = Arc::new(database_file.to_string());

    tokio::task
        ::spawn_blocking({
            move || {
                let mut database_file_data = Vec::new();

                {
                    let mut database_file = std::fs::File
                        ::open(&*database_file)
                        .map_err(|e| { Errors::FileIOError(e.to_string()) })
                        .unwrap_or_else(|e| { panic!("Error: {}", e) });
                    database_file
                        .read_to_end(&mut database_file_data)
                        .map_err(|e| { Errors::FileIOError(e.to_string()) })
                        .unwrap_or_else(|e| { panic!("Error: {}", e) });
                }

                for i in &*data_file {
                    let mut data_file_vector_data = Vec::new();

                    {
                        let mut data_file = std::fs::File
                            ::open(&i)
                            .map_err(|e| { Errors::FileIOError(e.to_string()) })
                            .unwrap_or_else(|e| { panic!("Error: {}", e) });
                        data_file
                            .read_to_end(&mut data_file_vector_data)
                            .map_err(|e| { Errors::FileIOError(e.to_string()) })
                            .unwrap_or_else(|e| { panic!("Error: {}", e) });
                    }

                    let (data, nonce) = match encrypt {
                        true => {
                            let compressed = aes_encryption(
                                compress(data_file_vector_data)
                                    .map_err(|e| { Errors::CompressionError(e.to_string()) })
                                    .unwrap_or_else(|e| { panic!("Error: {}", e) })
                            ).unwrap_or_else(|e| { panic!("Error: {}", e) });
                            compressed
                        }
                        false =>
                            (
                                compress(data_file_vector_data).unwrap_or_else(|e|
                                    panic!("Error: {e}")
                                ),
                                Vec::new(),
                            ),
                    };

                    let entry = format!("{}: {}|", hash_file_name(i), data.len());

                    if memchr::memmem::find(&database_file_data, entry.as_bytes()).is_none() {
                        database_file_data.extend(entry.as_bytes());

                        match data.len() > 1000000 {
                            true => database_file_data.par_extend(data),
                            false => database_file_data.extend(data),
                        }

                        database_file_data.extend(b";");

                        if encrypt {
                            let hash = hash_file_name(format!("{}.nonce", i).as_str());
                            let nonce_entry = format!("{}: {}|", hash, nonce.len());
                            database_file_data.extend(nonce_entry.as_bytes());
                            database_file_data.extend(nonce);
                            database_file_data.extend(b";");
                        }
                    }
                }

                let mut database_file = std::fs::OpenOptions
                    ::new()
                    .write(true)
                    .truncate(true)
                    .open(&*database_file)
                    .unwrap_or_else(|e| { panic!("Error: {}", e) });
                database_file
                    .write_all(&database_file_data)
                    .map_err(|e| { Errors::FileIOError(e.to_string()) })
                    .unwrap_or_else(|e| { panic!("Error: {}", e) });
            }
        }).await
        .map_err(|e| Errors::TokioRuntimeError(e.to_string()))?;
    Ok(())
}

pub async fn update_data_block(
    data_file_names: Vec<&str>,
    database_file_name: &str,
    encrypt: bool
) -> Result<(), Errors> {
    remove_data_block(data_file_names.clone(), database_file_name).await?;
    add_data_block(data_file_names, database_file_name, encrypt).await?;
    Ok(())
}

pub async fn export_file(
    data_file_name: Vec<&str>,
    database_file_name: &str
) -> Result<(), Errors> {
    for i in data_file_name {
        let data: Vec<u8> = read_data_block(&i, database_file_name).await?;

        if
            File::open(i)
                .and_then(|file| file.metadata())
                .is_ok()
        {
            panic!("File already exists: {}", i);
        }

        let mut file = std::fs::File
            ::create(i)
            .map_err(|e| { Errors::FileIOError(e.to_string()) })?;
        file.write_all(&data).map_err(|e| { Errors::FileIOError(e.to_string()) })?;
    }

    Ok(())
}
