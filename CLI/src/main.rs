use atom_cli::*;
use clap::{Arg, Command};
use memchr::memchr;
use std::{fs::File, io::Read};

#[tokio::main]
async fn main() {
    let command = Command::new("atom")
        .version("1.1")
        .about("Atom Archive")
        .args(vec![
            Arg::new("archive")
                .long("archive")
                .short('c')
                .help("Set the archive file")
                .required(true),
            Arg::new("add_files")
                .long("add")
                .short('a')
                .help("Add files to the Files")
                .value_name("FILES")
                .required(false)
                .num_args(1..),
            Arg::new("remove_files")
                .long("remove")
                .short('r')
                .help("Remove files from the Files")
                .value_name("FILES")
                .required(false)
                .num_args(1..),
            Arg::new("update_data_block")
                .long("update_files")
                .short('u')
                .help("Update the data block of the Files")
                .value_name("FILES")
                .required(false)
                .num_args(1..),
            Arg::new("extract")
                .long("extract")
                .short('x')
                .help("Extract files from the Files")
                .value_name("FILES")
                .required(false)
                .num_args(1..),
            Arg::new("encrypt")
                .long("encrypt")
                .short('e')
                .help("Encrypt the Files")
                .required(false)
                .default_value("false"),
            Arg::new("password")
                .long("password")
                .short('p')
                .help("Set the password for the Files")
                .required(false),
            Arg::new("algorithm_set")
                .long("algorithm")
                .short('A')
                .help("Set the algorithm for the Files")
                .required(false),
            Arg::new("compression_level")
                .long("compression")
                .short('C')
                .help("Set the compression level for the Files")
                .required(false),
            Arg::new("list")
                .long("list")
                .short('l')
                .help("List the files in the archive")
                .action(clap::ArgAction::SetTrue),
            Arg::new("new")
                .long("new")
                .short('n')
                .help("Creates archive file")
                .action(clap::ArgAction::SetTrue),
        ]);

    let matches = command.get_matches();
    let archive = matches.get_one::<String>("archive").unwrap().as_str();
    let encrypt = matches
        .get_one::<String>("encrypt")
        .unwrap()
        .parse::<bool>()
        .unwrap();

    if let Some(password) = matches.get_one::<String>("password") {
        let password = password.as_str();
        set_password(password).unwrap();
    }

    if let Some(algorithm) = matches.get_one::<String>("algorithm_set") {
        let algorithm = if algorithm == "lz4" {
            Algorithms::LZ4
        } else if algorithm == "zstd" {
            Algorithms::ZSTD
        } else {
            panic!("Algorithm not supported")
        };

        set_algorithm(algorithm).unwrap_or_else(|e| panic!("Error: {e}"));
    }

    if let Some(password) = matches.get_one::<String>("password") {
        let password = password.as_str();
        set_password(password).unwrap_or_else(|e| panic!("Error: {e}"));
    }

    if let Some(level) = matches.get_one::<u8>("compression_level") {
        set_zstd_compression_level(*level).unwrap_or_else(|e| panic!("Error: {e}"));
    }

    if let Some(files) = matches.get_many::<String>("add_files") {
        let mut vector = Vec::new();
        files.for_each(|file| {
            vector.push(file.to_string());
        });

        add_data_block(
            vector.iter().map(|s| s.as_str()).collect(),
            archive,
            encrypt,
        )
        .await
        .unwrap_or_else(|e| panic!("Error: {e}"));
    } else if let Some(files) = matches.get_many::<String>("remove_files") {
        let mut vector = Vec::new();
        files.for_each(|file| {
            vector.push(file.to_string());
        });

        remove_data_block(vector.iter().map(|s| s.as_str()).collect(), archive)
            .await
            .unwrap_or_else(|e| panic!("Error: {e}"));
    } else if let Some(files) = matches.get_many::<String>("update_data_block") {
        let mut vector = Vec::new();
        files.for_each(|file| {
            vector.push(file.to_string());
        });

        update_data_block(
            vector.iter().map(|s| s.as_str()).collect(),
            archive,
            encrypt,
        )
        .await
        .unwrap_or_else(|e| panic!("Error: {e}"));
    } else if let Some(files) = matches.get_many::<String>("extract") {
        let mut vector = Vec::new();
        files.for_each(|file| {
            vector.push(file.to_string());
        });

        export_file(vector.iter().map(|s| s.as_str()).collect(), archive)
            .await
            .unwrap_or_else(|e| panic!("Error: {e}"));
    } else if matches.get_flag("list") {
        let mut file = File::open(archive).unwrap_or_else(|e| panic!("Error: {e}"));

        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .unwrap_or_else(|e| panic!("Error: {e}"));

        println!("Archive Includes (All names are hashed): ");

        let mut offset = 0;
        while offset < data.len() {
            let colon_rel = match memchr(b':', &data[offset..]) {
                Some(pos) => pos,
                None => break,
            };
            let colon_pos = offset + colon_rel;

            let pipe_rel = match memchr(b'|', &data[colon_pos..]) {
                Some(pos) => pos,
                None => break,
            };
            let pipe_pos = colon_pos + pipe_rel;

            let hash = &data[offset..colon_pos];
            let hash_str = String::from_utf8_lossy(hash);

            let len_bytes = &data[colon_pos + 1..pipe_pos];
            let mut len_value = 0;

            let mut i = 0;
            while i < len_bytes.len() && (len_bytes[i] == b' ' || len_bytes[i] == b'\t') {
                i += 1;
            }

            // Sonra sayıları oku
            while i < len_bytes.len() && len_bytes[i] >= b'0' && len_bytes[i] <= b'9' {
                len_value = len_value * 10 + (len_bytes[i] - b'0') as usize;
                i += 1;
            }

            println!("- {} ({} bayt)", hash_str, len_value);

            offset = pipe_pos + 1 + len_value;

            if offset < data.len() && data[offset] == b';' {
                offset += 1;
            }
        }
    } else {
        initialize(archive).unwrap_or_else(|e| panic!("Error: {e}"));
    }
}
