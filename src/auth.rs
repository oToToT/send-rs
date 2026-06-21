use axum::http::{HeaderMap, header};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::{AppError, AppResult, ids};

type HmacSha256 = Hmac<Sha256>;

pub fn new_nonce() -> String {
    let bytes = random_bytes(16);
    STANDARD.encode(bytes)
}

pub fn parse_send_v1(headers: &HeaderMap) -> AppResult<Vec<u8>> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::Unauthorized)?;
    let Some(token) = value.strip_prefix("send-v1 ") else {
        return Err(AppError::Unauthorized);
    };
    decode_base64(token).ok_or(AppError::Unauthorized)
}

pub fn verify_hmac(auth_key_b64: &str, nonce_b64: &str, provided: &[u8]) -> AppResult<()> {
    let key = decode_base64(auth_key_b64).ok_or(AppError::Unauthorized)?;
    let nonce = decode_base64(nonce_b64).ok_or(AppError::Unauthorized)?;
    let mut mac = HmacSha256::new_from_slice(&key).map_err(|_| AppError::Unauthorized)?;
    mac.update(&nonce);
    let expected = mac.finalize().into_bytes();
    if expected.as_slice().ct_eq(provided).into() {
        Ok(())
    } else {
        Err(AppError::Unauthorized)
    }
}

pub fn verify_owner(stored: &str, provided: &str) -> AppResult<()> {
    if stored.as_bytes().ct_eq(provided.as_bytes()).into() {
        Ok(())
    } else {
        Err(AppError::Unauthorized)
    }
}

pub fn owner_token_digest(key: &[u8], token: &str) -> AppResult<String> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| AppError::Storage("invalid owner-token key".into()))?;
    mac.update(token.as_bytes());
    Ok(STANDARD_NO_PAD.encode(mac.finalize().into_bytes()))
}

pub fn verify_owner_digest(key: &[u8], stored: &str, provided: &str) -> AppResult<()> {
    let digest = owner_token_digest(key, provided)?;
    verify_owner(stored, &digest)
}

pub fn random_owner() -> String {
    ids::random_hex(10)
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; len];
    use rand::RngCore;
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

fn decode_base64(value: &str) -> Option<Vec<u8>> {
    STANDARD
        .decode(value)
        .or_else(|_| STANDARD_NO_PAD.decode(value))
        .or_else(|_| URL_SAFE.decode(value))
        .or_else(|_| URL_SAFE_NO_PAD.decode(value))
        .ok()
}
