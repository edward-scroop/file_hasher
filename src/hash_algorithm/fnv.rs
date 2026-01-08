// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright 2026 Edward Scroop <edward.scroop@gmail.com>

use crate::{MIB, hash_algorithm::Hash};

pub struct FNV32 {}
pub struct FNV32a {}
pub struct FNV64 {}
pub struct FNV64a {}

struct FNVContext32 {
    hash: u32,
}

struct FNVContext64 {
    hash: u64,
}

impl Default for FNVContext32 {
    fn default() -> Self {
        Self {
            hash: 0x81_1C_9D_C5u32,
        }
    }
}

impl Default for FNVContext64 {
    fn default() -> Self {
        Self {
            hash: 0xCB_F2_9C_E4_84_22_23_25u64,
        }
    }
}

impl FNV32 {
    fn hash_block(mut context: FNVContext32, data: &[u8]) -> FNVContext32 {
        for byte in data {
            context.hash = context.hash.wrapping_mul(0x01_00_01_93u32);
            context.hash ^= *byte as u32;
        }

        context
    }

    fn print_hash(context: &FNVContext32) -> String {
        let mut return_string = String::new();

        for byte in context.hash.to_be_bytes() {
            return_string.push_str(&format!("{:02x}", byte));
        }

        return_string
    }
}

impl Hash for FNV32 {
    fn hash_slice(message: &[u8]) -> String {
        let mut context: FNVContext32 = Default::default();

        context = Self::hash_block(context, message);

        Self::print_hash(&context)
    }

    fn hash_stream(mut stream: impl std::io::Read) -> std::io::Result<String> {
        let mut context: FNVContext32 = Default::default();
        let mut buffer = [0u8; 10 * MIB];

        loop {
            let bytes_read = stream.read(&mut buffer)?;

            if bytes_read == 0 {
                break;
            }

            context = Self::hash_block(context, &buffer[0..bytes_read]);
        }

        Ok(Self::print_hash(&context))
    }
}

impl FNV32a {
    fn hash_block(mut context: FNVContext32, data: &[u8]) -> FNVContext32 {
        for byte in data {
            context.hash ^= *byte as u32;
            context.hash = context.hash.wrapping_mul(0x01_00_01_93u32);
        }

        context
    }

    fn print_hash(context: &FNVContext32) -> String {
        let mut return_string = String::new();

        for byte in context.hash.to_be_bytes() {
            return_string.push_str(&format!("{:02x}", byte));
        }

        return_string
    }
}

impl Hash for FNV32a {
    fn hash_slice(message: &[u8]) -> String {
        let mut context: FNVContext32 = Default::default();

        context = Self::hash_block(context, message);

        Self::print_hash(&context)
    }

    fn hash_stream(mut stream: impl std::io::Read) -> std::io::Result<String> {
        let mut context: FNVContext32 = Default::default();
        let mut buffer = [0u8; 10 * MIB];

        loop {
            let bytes_read = stream.read(&mut buffer)?;

            if bytes_read == 0 {
                break;
            }

            context = Self::hash_block(context, &buffer[0..bytes_read]);
        }

        Ok(Self::print_hash(&context))
    }
}

impl FNV64 {
    fn hash_block(mut context: FNVContext64, data: &[u8]) -> FNVContext64 {
        for byte in data {
            context.hash = context.hash.wrapping_mul(0x00_00_01_00_00_00_01_B3u64);
            context.hash ^= *byte as u64;
        }

        context
    }

    fn print_hash(context: &FNVContext64) -> String {
        let mut return_string = String::new();

        for byte in context.hash.to_be_bytes() {
            return_string.push_str(&format!("{:02x}", byte));
        }

        return_string
    }
}

impl Hash for FNV64 {
    fn hash_slice(message: &[u8]) -> String {
        let mut context: FNVContext64 = Default::default();

        context = Self::hash_block(context, message);

        Self::print_hash(&context)
    }

    fn hash_stream(mut stream: impl std::io::Read) -> std::io::Result<String> {
        let mut context: FNVContext64 = Default::default();
        let mut buffer = [0u8; 10 * MIB];

        loop {
            let bytes_read = stream.read(&mut buffer)?;

            if bytes_read == 0 {
                break;
            }

            context = Self::hash_block(context, &buffer[0..bytes_read]);
        }

        Ok(Self::print_hash(&context))
    }
}

impl FNV64a {
    fn hash_block(mut context: FNVContext64, data: &[u8]) -> FNVContext64 {
        for byte in data {
            context.hash ^= *byte as u64;
            context.hash = context.hash.wrapping_mul(0x00_00_01_00_00_00_01_B3u64);
        }

        context
    }

    fn print_hash(context: &FNVContext64) -> String {
        let mut return_string = String::new();

        for byte in context.hash.to_be_bytes() {
            return_string.push_str(&format!("{:02x}", byte));
        }

        return_string
    }
}

impl Hash for FNV64a {
    fn hash_slice(message: &[u8]) -> String {
        let mut context: FNVContext64 = Default::default();

        context = Self::hash_block(context, message);

        Self::print_hash(&context)
    }

    fn hash_stream(mut stream: impl std::io::Read) -> std::io::Result<String> {
        let mut context: FNVContext64 = Default::default();
        let mut buffer = [0u8; 10 * MIB];

        loop {
            let bytes_read = stream.read(&mut buffer)?;

            if bytes_read == 0 {
                break;
            }

            context = Self::hash_block(context, &buffer[0..bytes_read]);
        }

        Ok(Self::print_hash(&context))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv32_empty_hash() {
        assert_eq!(FNV32::hash_slice(&[]), "811c9dc5");
        assert_eq!(FNV32a::hash_slice(&[]), "811c9dc5");
    }

    #[test]
    fn fnv64_empty_hash() {
        assert_eq!(FNV64::hash_slice(&[]), "cbf29ce484222325");
        assert_eq!(FNV64a::hash_slice(&[]), "cbf29ce484222325");
    }

    #[test]
    fn fnv32_rfc_hash_suite() {
        assert_eq!(FNV32::hash_slice("a".as_bytes()), "050c5d7e");

        assert_eq!(FNV32::hash_slice("foobar".as_bytes()), "31f0b262");
    }

    #[test]
    fn fnv32a_rfc_hash_suite() {
        assert_eq!(FNV32a::hash_slice("a".as_bytes()), "e40c292c");

        assert_eq!(FNV32a::hash_slice("foobar".as_bytes()), "bf9cf968");
    }

    #[test]
    fn fnv64_rfc_hash_suite() {
        assert_eq!(FNV64::hash_slice("a".as_bytes()), "af63bd4c8601b7be");

        assert_eq!(FNV64::hash_slice("foobar".as_bytes()), "340d8765a4dda9c2");
    }

    #[test]
    fn fnv64a_rfc_hash_suite() {
        assert_eq!(FNV64a::hash_slice("a".as_bytes()), "af63dc4c8601ec8c");

        assert_eq!(FNV64a::hash_slice("foobar".as_bytes()), "85944171f73967e8");
    }
}
