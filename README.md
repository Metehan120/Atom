# Atom

## What is Atom?:
1. Atom is a File Archive like Rar & Zip but its making something different: Instead of searhing through whole Archive Atom is just finding sepcific File and working on it.
2. Atom using Rayon & Tokio to make thing Parallel and Async because of this the performance impact is significant.
3. Atom is an just Rust Library and CLI only for now, soon GUI will be added.

## Why Atom?:
1. As I mentioned before Atom using full potentionel of CPU, because of that Atom way faster.
2. Atom using LZ4 & ZSTD because of that you should able switch between Speed and Efficiency.

# Compression Benchmarks (Without Encryption):
| Algorithms | LZ4          | ZSTD (0)     |
|------------|--------------|--------------|
| 400MB .exe | ~1.5 Seconds | ~2 Seconds   |
| 200MB .exe | ~700 MS      | ~1 Seconds   |
| 100MB .exe | ~250 MS      | ~500 MS      |

## How to use CLI:
1. -c, --archive <archive>                Set the archive file
2. -a, --add <FILES>...                   Add files to the Files
3. -r, --remove <FILES>...                Remove files from the Files
4. -u, --update_files <FILES>...          Update the data block of the Files
5. -x, --extract <FILES>...               Extract files from the Files
6. -e, --encrypt <encrypt>                Encrypt the Files [default: false]
7. -p, --password <password>              Set the password for the Files
8. -A, --algorithm <zstd // lz4)        Set the algorithm for the Files
9. -C, --compression <compression_level>  Set the compression level for the Files
10. -l, --list                             List the files in the archive
11. -n, --new                              Creates archive file
12. -h, --help                             Print help
13. -V, --version                          Print version
14.  -N, --name-mapping                    Sets name mapping on/off (Name mapping is bad for security if added to command setting mapping off)
15. NOT: -e only needed for -a and -u

# How to use:
```rust
use atom::*;

#[tokio::main]
async fn main() {
    set_algorithm(atom::Algorithms::ZSTD).unwrap();
    set_password("testpassword").unwrap();
    set_zstd_compression_level(10).unwrap();
    set_name_mapping(false).unwrap();

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

## You shouldn't:
1. Game development (Game loads will extremly slow but if you use just for small files it'll alright I guess)
2. With Compressed Files
3. 1GB+ Files (If you want you can use of course)

## You should:
1. Archiving 100mb+ data archives
2. Archiving small files
3. Protecting your own Archive (Atom using AES-256-GCM so Atom is almost impenetrable)
