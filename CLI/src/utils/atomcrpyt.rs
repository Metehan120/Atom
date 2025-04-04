use rand::{TryRngCore, rngs::OsRng};
use rayon::prelude::*;

const S_BOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

fn generate_inv_s_box(s_box: &[u8; 256]) -> [u8; 256] {
    let mut inv_s_box = [0u8; 256];
    for (i, &val) in s_box.iter().enumerate() {
        inv_s_box[val as usize] = i as u8;
    }
    inv_s_box
}

pub fn nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    OsRng.try_fill_bytes(&mut nonce).unwrap();

    *blake3::hash(&nonce).as_bytes()
}

fn xor_encrypt_decrypt(nonce: &[u8], pwd: &[u8], input: &[u8]) -> Vec<u8> {
    let pwd = encrpyt_password(&pwd, nonce);

    let out = input
        .par_iter()
        .enumerate()
        .map(|(i, b)| b ^ (nonce[i % nonce.len()] ^ pwd[i % pwd.len()]))
        .collect::<Vec<u8>>();

    match out.is_empty() {
        true => panic!("Empty vector"),
        false => out,
    }
}

fn mix_blocks(data: &mut Vec<u8>, nonce: &[u8]) -> Vec<u8> {
    if data.len() < 3 {
        return data.to_vec();
    }

    for round in 0..=2 {
        data.par_iter_mut().enumerate().for_each(|(i, byte)| {
            let n = nonce[i % nonce.len()];
            match round {
                0 => *byte = byte.wrapping_add(n),
                1 => {
                    *byte = byte.rotate_right(3);
                    *byte ^= n;
                }
                2 => *byte = byte.wrapping_add(n),
                _ => unreachable!(),
            }
        });
    }
    data.to_vec()
}

fn unmix_blocks(data: &mut Vec<u8>, nonce: &[u8]) -> Vec<u8> {
    if data.len() < 3 {
        return data.to_vec();
    }

    for round in (0..=2).rev() {
        data.par_iter_mut().enumerate().for_each(|(i, byte)| {
            let n = nonce[i % nonce.len()];
            match round {
                2 => *byte = byte.wrapping_sub(n),
                1 => {
                    *byte = *byte ^ n;
                    *byte = byte.rotate_left(3);
                }
                0 => *byte = byte.wrapping_sub(n),
                _ => unreachable!(),
            }
        });
    }

    data.to_vec()
}

fn encrpyt_password(pwd: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut pwd = pwd.to_vec();

    for _x in 0..20 {
        for round in 0..=3 {
            pwd.par_iter_mut().enumerate().for_each(|(i, byte)| {
                let n = salt[i % salt.len()];
                match round {
                    0 => *byte = byte.wrapping_add(n),
                    1 => {
                        *byte = byte.rotate_right(3);
                        *byte ^= n;
                    }
                    2 => *byte = byte.wrapping_add(n),
                    3 => *byte = byte.wrapping_mul(n | 1),
                    _ => unreachable!(),
                }
            });
        }

        if _x % 10 == 0 && _x > 0 {
            pwd = blake3::hash(&pwd).as_bytes().to_vec();
        }
    }

    blake3::hash(&pwd).as_bytes().to_vec()
}

fn s_bytes(data: &[u8]) -> Vec<u8> {
    let mut data = data.to_vec();

    data.par_iter_mut().enumerate().for_each(|(_i, byte)| {
        *byte = S_BOX[*byte as usize];
    });

    data
}

fn in_s_bytes(data: &[u8]) -> Vec<u8> {
    let mut data = data.to_vec();

    data.par_iter_mut().enumerate().for_each(|(_i, byte)| {
        *byte = generate_inv_s_box(&S_BOX)[*byte as usize];
    });

    data
}

pub fn encrpyt(pwd: &str, data: &[u8], nonce: &[u8]) -> Vec<u8> {
    let pwd = encrpyt_password(pwd.as_bytes(), nonce);

    let data = mix_blocks(&mut s_bytes(data), nonce);

    xor_encrypt_decrypt(nonce, &pwd, &data)
}

pub fn decrpyt(pwd: &str, data: &[u8], nonce: &[u8]) -> Vec<u8> {
    let pwd = encrpyt_password(pwd.as_bytes(), nonce);

    let data = in_s_bytes(&unmix_blocks(
        &mut xor_encrypt_decrypt(nonce, &pwd, &data),
        nonce,
    ));

    data
}
