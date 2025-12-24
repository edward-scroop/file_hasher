use std::io::Read;

pub mod md5;

pub trait Hash {
    fn hash_slice(message: &[u8]) -> String;

    fn hash_stream(message: impl Read) -> std::io::Result<String>;
}
