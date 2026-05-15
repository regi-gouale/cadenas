use crate::{
    account::{Account, NewAccount},
    error::Result,
    organization::{Membership, Organization, OrganizationId, Role},
    session::{NewSession, Session},
    totp::TotpFactor,
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

    // --- TOTP (second factor) ---
    async fn get_totp(&self, user_id: &UserId) -> Result<Option<TotpFactor>>;
    async fn upsert_totp(&self, user_id: &UserId, secret_b32: &str, enabled: bool) -> Result<()>;
    async fn delete_totp(&self, user_id: &UserId) -> Result<()>;

    // --- Organizations ---
    async fn create_organization(&self, slug: &str, name: &str) -> Result<Organization>;
    async fn find_organization_by_id(&self, id: &OrganizationId) -> Result<Option<Organization>>;
    async fn find_organization_by_slug(&self, slug: &str) -> Result<Option<Organization>>;
    async fn delete_organization(&self, id: &OrganizationId) -> Result<()>;
    async fn list_organizations_for_user(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<(Organization, Role)>>;

    async fn add_member(
        &self,
        org_id: &OrganizationId,
        user_id: &UserId,
        role: Role,
    ) -> Result<Membership>;
    async fn update_member_role(
        &self,
        org_id: &OrganizationId,
        user_id: &UserId,
        role: Role,
    ) -> Result<()>;
    async fn remove_member(&self, org_id: &OrganizationId, user_id: &UserId) -> Result<()>;
    async fn find_membership(
        &self,
        org_id: &OrganizationId,
        user_id: &UserId,
    ) -> Result<Option<Membership>>;
    async fn list_members(&self, org_id: &OrganizationId) -> Result<Vec<Membership>>;
}
