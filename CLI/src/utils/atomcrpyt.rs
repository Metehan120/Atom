use argon2::{Argon2, password_hash::SaltString};
use blake3::derive_key;
use rand::{TryRngCore, rngs::OsRng};
use rayon::prelude::*;
use subtle::ConstantTimeEq;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Errors {
    #[error("Decryption failed: {0}")]
    InvalidNonce(String),
    #[error("Invalid MAC: {0}")]
    InvalidMac(String),
    #[error("XOR failed: {0}")]
    InvalidXor(String),
    #[error("Thread Pool Failed: {0}")]
    ThreadPool(String),
    #[error("Argon2 failed: {0}")]
    Argon2Failed(String),
}

pub fn nonce() -> Result<[u8; 32], Errors> {
    let mut nonce = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|e| Errors::InvalidNonce(e.to_string()))?; // Generate a 32 byte nonce using OsRng

    Ok(*blake3::hash(&nonce).as_bytes()) // Hash the nonce to get a 32 byte more random nonce (Extra Security)
}

fn xor_encrypt(nonce: &[u8], pwd: &[u8], input: &[u8]) -> Result<Vec<u8>, Errors> {
    let out = input
        .par_iter()
        .enumerate()
        .map(|(i, b)| {
            let masked = b ^ (nonce[i % nonce.len()] ^ pwd[i % pwd.len()]); // XOR the byte with the nonce and password
            let mut masked = masked.rotate_left((nonce[i % nonce.len()] % 8) as u32); // Rotate the byte left by the nonce value

            masked = masked.wrapping_add(nonce[i % nonce.len()]); // Add the nonce to the byte
            masked = masked.wrapping_add(pwd[i % pwd.len()]); // Add the password to the byte

            masked
        })
        .collect::<Vec<u8>>();

    match out.is_empty() {
        true => return Err(Errors::InvalidXor("Empty vector".to_string())),
        false => Ok(out),
    }
}

fn xor_decrypt(nonce: &[u8], pwd: &[u8], input: &[u8]) -> Result<Vec<u8>, Errors> {
    let out = input
        .par_iter()
        .enumerate()
        .map(|(i, b)| {
            let masked = b.wrapping_sub(pwd[i % pwd.len()]); // Subtract the password from the byte
            let masked = masked.wrapping_sub(nonce[i % nonce.len()]); // Subtract the nonce from the byte

            let masked = masked.rotate_right((nonce[i % nonce.len()] % 8) as u32); // Rotate the byte right by the nonce value

            masked ^ (nonce[i % nonce.len()] ^ pwd[i % pwd.len()]) // XOR the byte with the nonce and password
        })
        .collect::<Vec<u8>>();

    match out.is_empty() {
        true => return Err(Errors::InvalidXor("Empty vector".to_string())),
        false => Ok(out),
    }
}

fn mix_blocks(data: &mut Vec<u8>, nonce: &[u8]) -> Result<Vec<u8>, Errors> {
    let thread = num_cpus::get() / 2;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(thread)
        .build()
        .map_err(|e| Errors::ThreadPool(e.to_string()))?;

    if data.len() < 3 {
        return Ok(data.to_vec());
    }

    let pool = pool.install(|| {
        data.into_par_iter()
            .enumerate()
            .map(|(i, byte)| {
                let n = nonce[i % nonce.len()];
                let mut byte = *byte;
                byte = byte.wrapping_add(n);
                byte = byte.rotate_right((n % 8) as u32); // Rotate the byte right by the nonce value
                byte ^= n; // XOR the byte with the nonce
                byte = byte.wrapping_add(n);

                byte
            })
            .collect::<Vec<u8>>()
    });

    Ok(pool)
}

fn unmix_blocks(data: &mut Vec<u8>, nonce: &[u8]) -> Result<Vec<u8>, Errors> {
    let thread = num_cpus::get() / 2;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(thread)
        .build()
        .map_err(|e| Errors::ThreadPool(e.to_string()))?;

    if data.len() < 3 {
        return Ok(data.to_vec());
    }

    let pool = pool.install(|| {
        data.into_par_iter()
            .enumerate()
            .map(|(i, byte)| {
                let n = nonce[i % nonce.len()];
                let mut byte = *byte;
                byte = byte.wrapping_sub(n);
                byte ^= n; // XOR the byte with the nonce
                byte = byte.rotate_left((n % 8) as u32); // Rotate the byte left by the nonce value
                byte = byte.wrapping_sub(n);

                byte
            })
            .collect::<Vec<u8>>()
    });

    Ok(pool)
}

fn encrypt_password(pwd: &[u8], salt: &[u8]) -> Result<Vec<u8>, Errors> {
    let salt = SaltString::encode_b64(salt).map_err(|e| Errors::Argon2Failed(e.to_string()))?;
    let argon = Argon2::default();

    let mut out = vec![0u8; 32]; // 256-bit key
    argon
        .hash_password_into(pwd, salt.as_str().as_bytes(), &mut out)
        .map_err(|e| Errors::Argon2Failed(e.to_string()))?;

    Ok(out)
}

fn generate_inv_s_box(s_box: &[u8; 256]) -> [u8; 256] {
    let mut inv_s_box = [0u8; 256];
    for (i, &val) in s_box.iter().enumerate() {
        // Iterate over the s_box
        inv_s_box[val as usize] = i as u8; // Inverse the s_box
    }

    inv_s_box
}

fn generate_dynamic_sbox(nonce: &[u8], key: &[u8]) -> [u8; 256] {
    let mut sbox: [u8; 256] = [0; 256];
    for i in 0..256 {
        sbox[i] = i as u8;
    }

    let seed = blake3::hash(&[nonce, key].concat()).as_bytes().to_vec();

    for i in (1..256).rev() {
        let index = (seed[i % seed.len()] as usize + seed[(i * 7) % seed.len()] as usize) % (i + 1); // Generate a random index
        sbox.swap(i, index); // Swap the values in the sbox
    }

    sbox
}

fn in_s_bytes(data: &[u8], nonce: &[u8], pwd: &[u8]) -> Vec<u8> {
    let sbox = generate_dynamic_sbox(nonce, pwd); // Generate the sbox
    let inv_sbox = generate_inv_s_box(&sbox); // Generate the inverse sbox

    data.par_iter().map(|b| inv_sbox[*b as usize]).collect() // Inverse the sbox
}

fn s_bytes(data: &[u8], sbox: &[u8; 256]) -> Vec<u8> {
    data.par_iter().map(|b| sbox[*b as usize]).collect() // Apply the sbox
}

fn dynamic_sizes(data_len: u64) -> u32 {
    match data_len {
        0..1_000 => 14,
        1_000..10_000 => 24,
        10_000..100_000 => 64,
        100_000..1_000_000 => 128,
        1_000_000..10_000_000 => 4096,
        10_000_000..100_000_000 => 8096,
        100_000_000..1_000_000_000 => 16384,
        1_000_000_000..10_000_000_000 => 16384,
        10_000_000_000..100_000_000_000 => 32768,
        100_000_000_000..1_000_000_000_000 => 32768,
        1_000_000_000_000..10_000_000_000_000 => 65536,
        10_000_000_000_000..100_000_000_000_000 => 65536,
        100_000_000_000_000..1_000_000_000_000_000 => 1048576,
        1_000_000_000_000_000..10_000_000_000_000_000 => 1048576,
        10_000_000_000_000_000..100_000_000_000_000_000 => 2097152,
        100_000_000_000_000_000..1_000_000_000_000_000_000 => 2097152,
        1_000_000_000_000_000_000..10_000_000_000_000_000_000 => 4194304,
        _ => unreachable!(),
    }
}

fn get_chunk_sizes(data_len: usize, nonce: &[u8], key: &[u8]) -> Vec<usize> {
    let mut sizes = Vec::new();
    let mut pos = 0;
    let hash = blake3::hash(&[nonce, key].concat());
    let seed = hash.as_bytes();

    let data_size = dynamic_sizes(data_len as u64) as usize;

    while pos < data_len {
        let size = 4 + (seed[pos % seed.len()] as usize % data_size); // Generate a random size for the chunk
        sizes.push(size.min(data_len - pos));
        pos += size;
    }

    sizes
}

fn dynamic_chunk_shift(data: &[u8], nonce: &[u8], password: &[u8]) -> Vec<u8> {
    let key = blake3::hash(&[nonce, password].concat())
        .as_bytes()
        .to_vec();

    let chunk_sizes = get_chunk_sizes(data.len(), nonce, &key);

    let mut shifted = Vec::new();
    let mut cursor = 0;

    for (i, size) in chunk_sizes.iter().enumerate() {
        let mut chunk = data[cursor..cursor + size].to_vec();

        let rotate_by = (nonce[i % nonce.len()] % 8) as u32; // Rotate the byte left by the nonce value
        let xor_val = key[i % key.len()]; // XOR the byte with the nonce

        chunk.par_iter_mut().for_each(|b| {
            *b = b.rotate_left(rotate_by); // Rotate the byte left by the nonce value
            *b ^= xor_val; // XOR the byte with the nonce
        });

        shifted.par_extend(chunk);
        cursor += size; // Move the cursor to the next chunk
    }

    shifted
}

fn dynamic_chunk_unshift(data: &[u8], nonce: &[u8], password: &[u8]) -> Vec<u8> {
    let key = blake3::hash(&[nonce, password].concat())
        .as_bytes()
        .to_vec();
    let chunk_sizes = get_chunk_sizes(data.len(), nonce, &key);

    let mut original = Vec::new();
    let mut cursor = 0;

    for (i, size) in chunk_sizes.iter().enumerate() {
        let mut chunk = data[cursor..cursor + size].to_vec();

        let rotate_by = (nonce[i % nonce.len()] % 8) as u32; // Rotate the byte left by the nonce value
        let xor_val = key[i % key.len()]; // XOR the byte with the nonce

        chunk.par_iter_mut().for_each(|b| {
            *b ^= xor_val; // XOR the byte with the nonce
            *b = b.rotate_right(rotate_by); // Rotate the byte right by the nonce value
        });

        original.par_extend(chunk);
        cursor += size; // Move the cursor to the next chunk
    }

    original
}

pub fn encrypt(pwd: &str, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, Errors> {
    let pwd = derive_key(pwd, nonce);
    let pwd = encrypt_password(&pwd, nonce)?;
    let mut out_vec = Vec::new();

    let s_block = generate_dynamic_sbox(nonce, &pwd);
    let mixed_data = mix_blocks(&mut s_bytes(data, &s_block), nonce)?;
    let mixed_data = dynamic_chunk_shift(&mixed_data, nonce, &pwd);
    let crypted = mixed_data
        .par_chunks(dynamic_sizes(mixed_data.len() as u64) as usize)
        .map(|data: &[u8]| {
            xor_encrypt(nonce, &pwd, &data).unwrap_or_else(|e| panic!("XOR Encryption Error: {e}"))
        })
        .flatten()
        .collect::<Vec<u8>>();

    let mac = *blake3::keyed_hash(blake3::hash(&crypted).as_bytes(), &data).as_bytes(); // Generate a MAC for the data

    out_vec.extend(crypted.clone());
    out_vec.extend(mac);

    Ok(out_vec)
}

pub fn decrypt(pwd: &str, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, Errors> {
    let pwd = derive_key(pwd, nonce);
    let pwd = encrypt_password(&pwd, nonce)?;

    let total_len = data.len();

    if total_len < 32 {
        return Err(Errors::InvalidMac(
            "Data is too short to contain a valid MAC".to_string(),
        ));
    }

    let (crypted, mac_key) = data.split_at(total_len - 32);

    let xor_decrypted = crypted
        .to_vec()
        .par_chunks_mut(dynamic_sizes(crypted.len() as u64) as usize)
        .map(|data: &mut [u8]| {
            xor_decrypt(nonce, &pwd, data).unwrap_or_else(|e| panic!("XOR Decryption Error: {e}"))
        })
        .flatten()
        .collect::<Vec<u8>>();
    let mut unshifted = dynamic_chunk_unshift(&xor_decrypted, nonce, &pwd);
    let unmixed = unmix_blocks(&mut unshifted, nonce);
    let decrypted_data = in_s_bytes(&unmixed?, nonce, &pwd);

    let mac = blake3::keyed_hash(blake3::hash(&crypted).as_bytes(), &decrypted_data); // Generate a MAC for the data

    if mac.as_bytes().ct_eq(mac_key).unwrap_u8() != 1 {
        // Check if the MAC is valid
        return Err(Errors::InvalidMac(
            "Data Changed / Corrupted / False Key".to_string(),
        ));
    }

    Ok(decrypted_data)
}
