[![Static Badge](https://img.shields.io/badge/Atom-Archive?label=1.2.1)](https://crates.io/crates/atom-archive)
[![Static Badge](https://img.shields.io/badge/Atom-Archive?label=docs)](https://docs.rs/atom-archive)
[![Static Badge](https://img.shields.io/badge/Atom-Discord?label=Discord&color=rgb(100%2C100%2C255))](https://discord.gg/FX9bBpBbMw)

# 🚨 EXPERIMENTAL FEATURE: AtomCrypte.
# ⚠️ AtomCrypte is extremely fast on small files, but *NOT RECOMMENDED FOR PRODUCTION USE* – potential security weaknesses exist.
# 🔐 ***AES-256 remains the default encryption algorithm.***

## What is Atom?:
1. Atom is a file archive tool like RAR or ZIP – but different. Instead of scanning the whole archive, it locates and operates on specific files.
2. Uses Rayon & Tokio for full async + parallelism. Result? 🔥 Blazing-fast performance.
3. Available as a Rust library and CLI (GUI coming soon 👀).

## Why Atom?:
1. Atom using full potentional of CPU.
2. Supports both LZ4 and ZSTD – pick between raw speed or tighter compression.

## 📊 Compression Benchmarks (Without Encryption)
| Algorithms | LZ4          | ZSTD (0)     |
|------------|--------------|--------------|
| 400MB .exe | ~1.5 Seconds | ~2 Seconds   |
| 200MB .exe | ~700 MS      | ~1 Seconds   |
| 100MB .exe | ~250 MS      | ~500 MS      |

## 📉 Decompression Benchmarks (Without Encryption)
| Algorithms | LZ4          | ZSTD (0)     |
|------------|--------------|--------------|
| 400MB .exe | ~200 MS      | ~800 MS      |
| 200MB .exe | ~150 MS      | ~350 MS      |
| 100MB .exe | ~100 MS      | ~200 MS      |

## 🧪 CLI Flags
1.  -c, --archive <archive> -> Set the archive file
2.  -a, --add <FILES>... -> Add files to the Files
3. -r, --remove <FILES>... -> Remove files from the Files
4.  -u, --update-files <FILES>... -> Update the data block of the Files
5.  -x, --extract <FILES>... -> Extract files from the Files
6.  -e, --encrypt Encrypt the Files
7.  -p, --password <password> -> Set the password for the Files
8.  -A, --algorithm <algorithm_set> -> Set the algorithm for the Files (Compression Alghorithm's: "lz4/zstd")
10.  -C, --compression <compression_level> -> Set the compression level for the Files
11.  -l, --list -> List the files in the archive
12.  -n, --new -> Creates archive file
13.  -N, --name-mapping -> Sets name mapping off (***Increases Security***)
14.  -P, --atomcrypte -> Sets name AtomCrypte on/off (***EXPERIMENTAL***)
15.  -h, --help -> Print help
16.  -V, --version -> Print version

# How to use:
```rust
use atom::*;

#[tokio::main]
async fn main() {
    set_algorithm(atom::Algorithms::ZSTD).unwrap();
    set_password("testpassword").unwrap();
    set_zstd_compression_level(10).unwrap();
    set_name_mapping(false).unwrap();
    set_encryption_algorithm(atom::EncryptionAlgorithms::AES)

    let (hash_file_name, file_name) = get_file_names().await.unwrap(); // only works when mapping enabled
    add_data_block(vec!["test.txt" /* ... */], "test", false).await.unwrap();
    remove_data_block(vec!["test.txt" /* ... */], "test").await.unwrap();
    export_file(vec!["test.txt" /* ... */], "test").await.unwrap();
    read_data_block("test.txt", "test").await.unwrap();
    read_multiple_data_block(vec!["test.txt" /* ... */], "test").await.unwrap();
    update_data_block(vec!["test.txt" /* ... */], "test", false).await.unwrap();
}

```

# Which case you should use and you shouldn't use:

## ⚠️ When not to use Atom:
1. 🚫 Game development – file loading can be slow
2. 🚫 With already compressed files (like .zip, .mp4, etc.)
3. Huge files (1GB+) – works, but performance may suffer

## ✅ When you should use Atom:
1. ✅ Archiving large groups of small/medium files/large files (200MB+)
2. ✅ Protecting archives with AES-256-GCM
3. ✅ When you want parallel + async + Rust performance

## 🧪 Wanna try AtomCrypte?
1. CLI (***EXPERIMENTAL USE ONLY***):
- ``atom -c archive.atom -a myfile.txt -e -p "supersecret" -P``
2. Code (***EXPERIMENTAL USE ONLY***):
- ```rust
    set_encryption_algorithm(atom::EncryptionAlgorithms::ATOM)