// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright 2025-2026 Edward Scroop <edward.scroop@gmail.com>

use hashsum::{
    Algorithm, FILE_BUFFER, State,
    hash_algorithm::{
        Hash,
        fnv::{FNV32, FNV32a, FNV64, FNV64a},
        md5::MD5,
        sha1::SHA1,
        sha2::{SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256},
        sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512},
    },
};
use std::{
    fs::File,
    io::{self, BufReader},
    process,
};

fn main() {
    let state = State::process_arguments();
    let mut counter = 0;
    let mut no_args = false;

    if state.arguments.is_empty() {
        no_args = true;
    }

    loop {
        let data: Vec<u8>;
        let hashed_result: String;

        if no_args || state.arguments[counter] == "-" {
            // Read data from stdin
            let mut stdin = String::new();

            let mut bytes_read = io::stdin().read_line(&mut stdin).unwrap_or(0);
            while bytes_read != 0 {
                bytes_read = match io::stdin().read_line(&mut stdin) {
                    Ok(f) => f,
                    Err(error) => {
                        eprintln!("Error reading stdin: {}", error);
                        process::exit(1);
                    }
                }
            }

            data = stdin.clone().into_bytes();

            let hash_function = match state.algorithm {
                Algorithm::MD5 => MD5::hash_slice,
                Algorithm::SHA1 => SHA1::hash_slice,
                Algorithm::SHA224 => SHA224::hash_slice,
                Algorithm::SHA256 => SHA256::hash_slice,
                Algorithm::SHA384 => SHA384::hash_slice,
                Algorithm::SHA512 => SHA512::hash_slice,
                Algorithm::SHA512_224 => SHA512_224::hash_slice,
                Algorithm::SHA512_256 => SHA512_256::hash_slice,
                Algorithm::SHA3_224 => SHA3_224::hash_slice,
                Algorithm::SHA3_256 => SHA3_256::hash_slice,
                Algorithm::SHA3_384 => SHA3_384::hash_slice,
                Algorithm::SHA3_512 => SHA3_512::hash_slice,
                Algorithm::FNV32 => FNV32::hash_slice,
                Algorithm::FNV32a => FNV32a::hash_slice,
                Algorithm::FNV64 => FNV64::hash_slice,
                Algorithm::FNV64a => FNV64a::hash_slice,
            };

            hashed_result = hash_function(&data);
        } else {
            // Read data from file passed as argument
            let file_handle = match File::open(&state.arguments[counter]) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Error opening file {}: {}", state.arguments[counter], e);
                    process::exit(1);
                }
            };

            let message = BufReader::with_capacity(FILE_BUFFER, file_handle);
            let hash_function = match state.algorithm {
                Algorithm::MD5 => MD5::hash_stream,
                Algorithm::SHA1 => SHA1::hash_stream,
                Algorithm::SHA224 => SHA224::hash_stream,
                Algorithm::SHA256 => SHA256::hash_stream,
                Algorithm::SHA384 => SHA384::hash_stream,
                Algorithm::SHA512 => SHA512::hash_stream,
                Algorithm::SHA512_224 => SHA512_224::hash_stream,
                Algorithm::SHA512_256 => SHA512_256::hash_stream,
                Algorithm::SHA3_224 => SHA3_224::hash_stream,
                Algorithm::SHA3_256 => SHA3_256::hash_stream,
                Algorithm::SHA3_384 => SHA3_384::hash_stream,
                Algorithm::SHA3_512 => SHA3_512::hash_stream,
                Algorithm::FNV32 => FNV32::hash_stream,
                Algorithm::FNV32a => FNV32a::hash_stream,
                Algorithm::FNV64 => FNV64::hash_stream,
                Algorithm::FNV64a => FNV64a::hash_stream,
            };

            hashed_result = match hash_function(message) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Error opening file {}: {}", state.arguments[counter], e);
                    process::exit(1);
                }
            }
        }

        if !no_args {
            println!("{} {}", hashed_result, state.arguments[counter]);
        } else {
            println!("{} -", hashed_result);
        }

        if counter + 1 >= state.arguments.len() {
            break;
        }
        counter += 1;
    }
}
