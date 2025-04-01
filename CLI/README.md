# Atom

## What Atom?:
1. Atom is a File Archive like Rar & Zip but its making something different: Instead of searhing through whole Archive Atom is just finding sepcific File and working on it.
2. Atom using Rayon & Tokio to make thing Parallel and Async because of this the performance impact is significant.
3. Atom is an just Rust Library for now, soon CLI and GUI will be added.

## Why Atom?:
1. As I mentioned before Atom using full potentionel of CPU, because of that Atom way faster.
2. Atom using LZ4 & ZSTD because of that you should able switch between Speed and Efficiency.

# Benchmarks (Without Encryption):
| Algorithms | LZ4 (0)      | ZSTD         |
|------------|--------------|--------------|
| 400MB .exe | ~2.4 Seconds | ~2.8 Seconds |
| 200MB .exe | ~1.2 Seconds | ~1.2 Seconds |
| 100MB .exe | ~500 MS      | ~500 MS      |

# How to use:
```rust
use atom::*;

#[tokio::main]
async fn main() {
    set_algorithm(atom::Algorithms::ZSTD).unwrap();
    set_password("testpassword").unwrap();
    set_zstd_compression_level(10).unwrap();

    add_data_block(vec!["test.txt" /* ... */], "test", false).await.unwrap();
    remove_data_block(vec!["test.txt" /* ... */], "test").await.unwrap();
    export_file(vec!["test.txt" /* ... */], "test").await.unwrap();
    read_data_block("test.txt", "test").await.unwrap();
    read_multiple_data_block(vec!["test.txt" /* ... */], "test").await.unwrap();
    update_data_block(vec!["test.txt" /* ... */], "test", false).await.unwrap();
}

```

# Which case you should use and you shouldn't use:

## You shouldn't:
1. Game development (Game loads will extremly slow but if you use just for small files it'll alright I guess)
2. With Compressed Files
3. 1GB+ Files (If you want you can use of course)

## You should:
1. Archiving 100mb+ data archives
2. Archiving small files
3. Protecting your own Archive (Atom using AES-256-GCM so Atom is almost impenetrable)
