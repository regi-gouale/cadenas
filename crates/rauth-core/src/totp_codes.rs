//! Pure RFC 6238 TOTP (HMAC-SHA1, 30s, 6 digits).
//!
//! Used by [`crate::auth::Auth`] for second-factor verification. Re-exported
//! by `rauth-totp` for app developers that want to render QR codes.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

type HmacSha1 = Hmac<Sha1>;

pub const STEP_SECONDS: u64 = 30;
pub const DIGITS: u32 = 6;

/// Compute the TOTP code for a given Unix timestamp.
pub fn totp_at(secret_b32: &str, unix_seconds: u64) -> Option<String> {
    let key = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret_b32)?;
    let counter = unix_seconds / STEP_SECONDS;
    let mut mac = HmacSha1::new_from_slice(&key).ok()?;
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();

    let offset = (result[result.len() - 1] & 0x0f) as usize;
    let bin = ((u32::from(result[offset]) & 0x7f) << 24)
        | ((u32::from(result[offset + 1]) & 0xff) << 16)
        | ((u32::from(result[offset + 2]) & 0xff) << 8)
        | (u32::from(result[offset + 3]) & 0xff);
    let modulus = 10u32.pow(DIGITS);
    Some(format!(
        "{:0width$}",
        bin % modulus,
        width = DIGITS as usize
    ))
}

/// Verify a TOTP code with a +/- 1 step tolerance (constant-time compare).
pub fn verify(secret_b32: &str, code: &str, unix_seconds: u64) -> bool {
    for delta in [-1i64, 0, 1] {
        let t = (unix_seconds as i64 + delta * STEP_SECONDS as i64).max(0) as u64;
        if let Some(expected) = totp_at(secret_b32, t) {
            if expected.as_bytes().ct_eq(code.as_bytes()).into() {
                return true;
            }
        }
    }
    false
}
