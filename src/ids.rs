use rand::RngCore;

use crate::{AppError, AppResult};

pub fn validate_file_id(id: &str) -> AppResult<()> {
    let ok_len = (10..=16).contains(&id.len());
    if ok_len && id.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

pub fn random_hex(bytes: usize) -> String {
    let mut out = vec![0_u8; bytes];
    rand::rng().fill_bytes(&mut out);
    to_hex(&out)
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        s.push(HEX[(byte >> 4) as usize] as char);
        s.push(HEX[(byte & 0x0f) as usize] as char);
    }
    s
}
