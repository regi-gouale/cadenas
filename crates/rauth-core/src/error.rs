use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("user already exists")]
    UserAlreadyExists,

    #[error("user not found")]
    UserNotFound,

    #[error("session not found or expired")]
    InvalidSession,

    #[error("verification token invalid or expired")]
    InvalidVerification,

    #[error("rate limited")]
    RateLimited,

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden")]
    Forbidden,

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("password hash error: {0}")]
    Password(String),

    #[error("storage error: {0}")]
    Storage(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("plugin error: {0}")]
    Plugin(String),

    #[error(transparent)]
    Other(#[from] anyhow_like::AnyError),
}

impl Error {
    pub fn storage<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Storage(Box::new(err))
    }

    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::BadRequest(msg.into())
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

// Tiny anyhow-like wrapper so we can `From`-convert arbitrary string errors
// without pulling `anyhow` into this crate.
mod anyhow_like {
    #[derive(Debug)]
    pub struct AnyError(pub String);

    impl std::fmt::Display for AnyError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }

    impl std::error::Error for AnyError {}
}
