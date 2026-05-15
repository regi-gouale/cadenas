use crate::{
    account::{Account, NewAccount},
    error::Result,
    session::{NewSession, Session},
    user::{NewUser, User, UserId},
    verification::{NewVerification, Verification},
};
use async_trait::async_trait;

/// Storage abstraction. Every adapter (SQLx, in-memory, Redis...) implements this.
#[async_trait]
pub trait Storage: Send + Sync + 'static {
    // --- Users ---
    async fn create_user(&self, input: NewUser) -> Result<User>;
    async fn find_user_by_id(&self, id: &UserId) -> Result<Option<User>>;
    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>>;
    async fn update_user(&self, user: &User) -> Result<()>;

    // --- Accounts (credentials + federated) ---
    async fn create_account(&self, input: NewAccount) -> Result<Account>;
    async fn find_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> Result<Option<Account>>;
    async fn find_account_by_user(
        &self,
        user_id: &UserId,
        provider: &str,
    ) -> Result<Option<Account>>;
    async fn update_account(&self, account: &Account) -> Result<()>;

    // --- Sessions ---
    async fn create_session(&self, input: NewSession) -> Result<Session>;
    async fn find_session(&self, token_hash: &str) -> Result<Option<Session>>;
    async fn delete_session(&self, token_hash: &str) -> Result<()>;
    async fn delete_sessions_for_user(&self, user_id: &UserId) -> Result<()>;

    // --- Verifications ---
    async fn create_verification(&self, input: NewVerification) -> Result<Verification>;
    /// Atomically fetch + delete the matching verification, if not expired.
    async fn consume_verification(
        &self,
        identifier: &str,
        purpose: &str,
        value_hash: &str,
    ) -> Result<Option<Verification>>;

    /// Same as [`consume_verification`] but matches on `(purpose, value_hash)`
    /// only — used for URL-token flows where the identifier is unknown.
    async fn consume_verification_by_value(
        &self,
        purpose: &str,
        value_hash: &str,
    ) -> Result<Option<Verification>>;

    /// Consume by `(identifier, purpose)` — used for OAuth `state` lookup.
    async fn consume_verification_by_identifier(
        &self,
        identifier: &str,
        purpose: &str,
    ) -> Result<Option<Verification>>;
}
