use serde::Deserialize;
use std::fmt;
use supabase_client_core::SupabaseError;

/// Error response format from the GoTrue API.
///
/// GoTrue may return errors in different shapes; this covers the common fields.
#[derive(Debug, Clone, Deserialize)]
pub struct GoTrueErrorResponse {
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_description: Option<String>,
    #[serde(default)]
    pub msg: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub code: Option<i32>,
    #[serde(default)]
    pub error_code: Option<String>,
}

impl GoTrueErrorResponse {
    /// Extract the most informative error message from the response.
    pub fn error_message(&self) -> String {
        self.msg
            .as_deref()
            .or(self.message.as_deref())
            .or(self.error_description.as_deref())
            .or(self.error.as_deref())
            .unwrap_or("Unknown error")
            .to_string()
    }
}

/// Auth-specific errors.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// HTTP transport error from reqwest.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// GoTrue API returned an error response.
    #[error("Auth API error ({status}): {message}")]
    Api {
        status: u16,
        message: String,
        #[source]
        error_code: Option<AuthErrorCode>,
    },

    /// Invalid configuration (missing URL or key).
    #[error("Invalid auth configuration: {0}")]
    InvalidConfig(String),

    /// Session has expired.
    #[error("Session expired")]
    SessionExpired,

    /// No active session.
    #[error("No active session")]
    NoSession,

    /// JSON serialization/deserialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// URL parsing error.
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),
}

/// Known GoTrue error codes for programmatic matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthErrorCode {
    InvalidCredentials,
    UserNotFound,
    UserAlreadyExists,
    EmailNotConfirmed,
    PhoneNotConfirmed,
    SessionNotFound,
    RefreshTokenNotFound,
    OtpExpired,
    OtpDisabled,
    WeakPassword,
    SamePassword,
    ValidationFailed,
    OverRequestRateLimit,
    Unknown(String),
}

impl fmt::Display for AuthErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCredentials => write!(f, "invalid_credentials"),
            Self::UserNotFound => write!(f, "user_not_found"),
            Self::UserAlreadyExists => write!(f, "user_already_exists"),
            Self::EmailNotConfirmed => write!(f, "email_not_confirmed"),
            Self::PhoneNotConfirmed => write!(f, "phone_not_confirmed"),
            Self::SessionNotFound => write!(f, "session_not_found"),
            Self::RefreshTokenNotFound => write!(f, "refresh_token_not_found"),
            Self::OtpExpired => write!(f, "otp_expired"),
            Self::OtpDisabled => write!(f, "otp_disabled"),
            Self::WeakPassword => write!(f, "weak_password"),
            Self::SamePassword => write!(f, "same_password"),
            Self::ValidationFailed => write!(f, "validation_failed"),
            Self::OverRequestRateLimit => write!(f, "over_request_rate_limit"),
            Self::Unknown(code) => write!(f, "{}", code),
        }
    }
}

impl std::error::Error for AuthErrorCode {}

impl From<&str> for AuthErrorCode {
    fn from(s: &str) -> Self {
        match s {
            "invalid_credentials" => Self::InvalidCredentials,
            "user_not_found" => Self::UserNotFound,
            "user_already_exists" => Self::UserAlreadyExists,
            "email_not_confirmed" => Self::EmailNotConfirmed,
            "phone_not_confirmed" => Self::PhoneNotConfirmed,
            "session_not_found" => Self::SessionNotFound,
            "refresh_token_not_found" => Self::RefreshTokenNotFound,
            "otp_expired" => Self::OtpExpired,
            "otp_disabled" => Self::OtpDisabled,
            "weak_password" => Self::WeakPassword,
            "same_password" => Self::SamePassword,
            "validation_failed" => Self::ValidationFailed,
            "over_request_rate_limit" => Self::OverRequestRateLimit,
            other => Self::Unknown(other.to_string()),
        }
    }
}

impl From<AuthError> for SupabaseError {
    fn from(err: AuthError) -> Self {
        SupabaseError::Auth(err.to_string())
    }
}
