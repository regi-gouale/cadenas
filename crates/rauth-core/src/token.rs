use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Generate a URL-safe random token with `bytes` of entropy.
pub fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

/// Stable, non-reversible fingerprint of a token (for storage / lookup keys).
pub fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex::encode(digest)
}
