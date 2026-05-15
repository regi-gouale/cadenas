use crate::{error::Result, session::Session, user::User};
use async_trait::async_trait;
use std::sync::Arc;

/// Hooks fired during authentication flows. All methods default to no-op so
/// plugins only override what they care about.
#[async_trait]
pub trait Plugin: Send + Sync + 'static {
    fn name(&self) -> &'static str;

    async fn on_user_created(&self, _user: &User) -> Result<()> {
        Ok(())
    }

    async fn before_sign_in(&self, _email: &str) -> Result<()> {
        Ok(())
    }

    async fn after_sign_in(&self, _user: &User, _session: &Session) -> Result<()> {
        Ok(())
    }

    async fn before_sign_out(&self, _session: &Session) -> Result<()> {
        Ok(())
    }
}

pub type SharedPlugin = Arc<dyn Plugin>;
