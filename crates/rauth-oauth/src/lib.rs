//! OAuth2 / OIDC plugin for rauth.
//!
//! Status: scaffolded. Provider implementations (Google, GitHub, ...) and the
//! `/oauth/{provider}/start` + `/oauth/{provider}/callback` flow will be added
//! in a follow-up: state/PKCE generation, token exchange via `reqwest`, and
//! account linking through [`rauth_core::Storage`].

use rauth_core::plugin::Plugin;

#[derive(Debug, Clone)]
pub struct OAuthProviderConfig {
    pub id: String,
    pub client_id: String,
    pub client_secret: String,
    pub authorize_url: String,
    pub token_url: String,
    pub userinfo_url: String,
    pub scopes: Vec<String>,
    pub redirect_uri: String,
}

#[derive(Default)]
pub struct OAuthPlugin {
    pub providers: Vec<OAuthProviderConfig>,
}

impl OAuthPlugin {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_provider(mut self, p: OAuthProviderConfig) -> Self {
        self.providers.push(p);
        self
    }
}

#[async_trait::async_trait]
impl Plugin for OAuthPlugin {
    fn name(&self) -> &'static str {
        "oauth"
    }
}
