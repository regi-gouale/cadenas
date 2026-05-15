use time::Duration;

#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Public base URL of the application (used to build absolute links).
    pub base_url: String,
    /// Cookie name for the session token.
    pub session_cookie_name: String,
    /// Session lifetime.
    pub session_ttl: Duration,
    /// Verification token lifetime (email verify, password reset).
    pub verification_ttl: Duration,
    /// Minimum password length enforced at signup.
    pub min_password_length: usize,
    /// Whether email verification is required before signing in.
    pub require_email_verification: bool,
    /// Automatically send a verification email after `sign_up_email`.
    pub send_verification_email_on_signup: bool,
    /// Trust the `X-Forwarded-For` header to extract the client IP.
    pub trust_proxy: bool,
    /// Frontend path appended to `base_url` for email-verification links.
    /// The token is appended as `?token=...`.
    pub email_verification_path: String,
    /// Frontend path appended to `base_url` for password-reset links.
    pub password_reset_path: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:3000".into(),
            session_cookie_name: "rauth.session".into(),
            session_ttl: Duration::days(30),
            verification_ttl: Duration::hours(1),
            min_password_length: 8,
            require_email_verification: false,
            send_verification_email_on_signup: false,
            trust_proxy: false,
            email_verification_path: "/verify-email".into(),
            password_reset_path: "/reset-password".into(),
        }
    }
}
