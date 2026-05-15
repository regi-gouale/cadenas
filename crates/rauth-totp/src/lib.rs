//! TOTP (RFC 6238) helpers + plugin scaffold.
//!
//! This crate ships a pure-Rust TOTP generator/verifier suitable for
//! second-factor authentication. Storage of per-user secrets and the HTTP
//! enrolment/challenge flow will be wired into `Auth` in a follow-up.

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;
use subtle::ConstantTimeEq;

type HmacSha1 = Hmac<Sha1>;

const STEP_SECONDS: u64 = 30;
const DIGITS: u32 = 6;

/// Generate a fresh random TOTP secret (20 bytes), base32-encoded.
pub fn generate_secret_base32() -> String {
    let mut buf = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut buf);
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &buf)
}

/// Compute the TOTP code for a given Unix timestamp.
pub fn totp_at(secret_b32: &str, unix_seconds: u64) -> Option<String> {
    let key = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret_b32)?;
    let counter = unix_seconds / STEP_SECONDS;
    let mut mac = HmacSha1::new_from_slice(&key).ok()?;
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();

    let offset = (result[result.len() - 1] & 0x0f) as usize;
    let bin_code = ((u32::from(result[offset]) & 0x7f) << 24)
        | ((u32::from(result[offset + 1]) & 0xff) << 16)
        | ((u32::from(result[offset + 2]) & 0xff) << 8)
        | (u32::from(result[offset + 3]) & 0xff);
    let modulus = 10u32.pow(DIGITS);
    Some(format!("{:0width$}", bin_code % modulus, width = DIGITS as usize))
}

/// Verify a TOTP code with a +/- 1 step tolerance.
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

/// Build an `otpauth://` URI ready for QR code rendering.
pub fn provisioning_uri(issuer: &str, account: &str, secret_b32: &str) -> String {
    let label = url::form_urlencoded::byte_serialize(format!("{issuer}:{account}").as_bytes())
        .collect::<String>();
    let issuer_q = url::form_urlencoded::byte_serialize(issuer.as_bytes()).collect::<String>();
    format!("otpauth://totp/{label}?secret={secret_b32}&issuer={issuer_q}&digits=6&period=30")
}
