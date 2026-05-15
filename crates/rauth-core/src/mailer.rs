use crate::error::Result;
use async_trait::async_trait;
use std::sync::Arc;

/// Outbound transactional email transport. Implement this for SMTP, SES,
/// Postmark, Resend, etc. A `LogMailer` is provided for development.
#[async_trait]
pub trait Mailer: Send + Sync + 'static {
    async fn send_verification_email(&self, to: &str, link: &str) -> Result<()>;
    async fn send_password_reset_email(&self, to: &str, link: &str) -> Result<()>;
}

pub type SharedMailer = Arc<dyn Mailer>;

/// Dev-only mailer that just logs the link via `tracing`.
#[derive(Default, Clone, Copy)]
pub struct LogMailer;

#[async_trait]
impl Mailer for LogMailer {
    async fn send_verification_email(&self, to: &str, link: &str) -> Result<()> {
        tracing::info!(target: "rauth::mailer", to, link, "verification email");
        Ok(())
    }

    async fn send_password_reset_email(&self, to: &str, link: &str) -> Result<()> {
        tracing::info!(target: "rauth::mailer", to, link, "password reset email");
        Ok(())
    }
}
