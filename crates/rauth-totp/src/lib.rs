//! TOTP (RFC 6238) helpers + Axum endpoints.
//!
//! The pure algorithm lives in `rauth_core::totp_codes`; this crate
//! re-exports it and ships small helpers + an optional Axum router.

pub use rauth_core::totp_codes::{totp_at, verify, DIGITS, STEP_SECONDS};

use rand::RngCore;

#[cfg(feature = "axum")]
pub mod axum_router;

/// Generate a fresh random TOTP secret (20 bytes), base32-encoded.
pub fn generate_secret_base32() -> String {
    let mut buf = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut buf);
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &buf)
}

/// Build an `otpauth://` URI ready for QR code rendering.
pub fn provisioning_uri(issuer: &str, account: &str, secret_b32: &str) -> String {
    let label = url::form_urlencoded::byte_serialize(format!("{issuer}:{account}").as_bytes())
        .collect::<String>();
    let issuer_q = url::form_urlencoded::byte_serialize(issuer.as_bytes()).collect::<String>();
    format!("otpauth://totp/{label}?secret={secret_b32}&issuer={issuer_q}&digits=6&period=30")
}
