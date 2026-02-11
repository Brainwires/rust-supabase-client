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

    /// Invalid or malformed JWT token.
    #[error("Invalid token: {0}")]
    InvalidToken(String),
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
    // MFA error codes
    MfaFactorNameConflict,
    MfaFactorNotFound,
    MfaChallengeExpired,
    MfaVerificationFailed,
    MfaVerificationRejected,
    MfaIpAddressMismatch,
    MfaEnrollNotEnabled,
    MfaVerifyNotEnabled,
    // SSO error codes
    SsoProviderNotFound,
    SsoDomainAlreadyExists,
    // Identity error codes
    IdentityAlreadyExists,
    IdentityNotFound,
    ManualLinkingDisabled,
    SingleIdentityNotDeletable,
    // OAuth server error codes
    OAuthClientNotFound,
    OAuthClientAlreadyExists,
    OAuthInvalidGrant,
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
            Self::MfaFactorNameConflict => write!(f, "mfa_factor_name_conflict"),
            Self::MfaFactorNotFound => write!(f, "mfa_factor_not_found"),
            Self::MfaChallengeExpired => write!(f, "mfa_challenge_expired"),
            Self::MfaVerificationFailed => write!(f, "mfa_verification_failed"),
            Self::MfaVerificationRejected => write!(f, "mfa_verification_rejected"),
            Self::MfaIpAddressMismatch => write!(f, "mfa_ip_address_mismatch"),
            Self::MfaEnrollNotEnabled => write!(f, "mfa_enroll_not_enabled"),
            Self::MfaVerifyNotEnabled => write!(f, "mfa_verify_not_enabled"),
            Self::SsoProviderNotFound => write!(f, "sso_provider_not_found"),
            Self::SsoDomainAlreadyExists => write!(f, "sso_domain_already_exists"),
            Self::IdentityAlreadyExists => write!(f, "identity_already_exists"),
            Self::IdentityNotFound => write!(f, "identity_not_found"),
            Self::ManualLinkingDisabled => write!(f, "manual_linking_disabled"),
            Self::SingleIdentityNotDeletable => write!(f, "single_identity_not_deletable"),
            Self::OAuthClientNotFound => write!(f, "oauth_client_not_found"),
            Self::OAuthClientAlreadyExists => write!(f, "oauth_client_already_exists"),
            Self::OAuthInvalidGrant => write!(f, "oauth_invalid_grant"),
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
            "mfa_factor_name_conflict" => Self::MfaFactorNameConflict,
            "mfa_factor_not_found" => Self::MfaFactorNotFound,
            "mfa_challenge_expired" => Self::MfaChallengeExpired,
            "mfa_verification_failed" => Self::MfaVerificationFailed,
            "mfa_verification_rejected" => Self::MfaVerificationRejected,
            "mfa_ip_address_mismatch" => Self::MfaIpAddressMismatch,
            "mfa_enroll_not_enabled" => Self::MfaEnrollNotEnabled,
            "mfa_verify_not_enabled" => Self::MfaVerifyNotEnabled,
            "sso_provider_not_found" => Self::SsoProviderNotFound,
            "sso_domain_already_exists" => Self::SsoDomainAlreadyExists,
            "identity_already_exists" => Self::IdentityAlreadyExists,
            "identity_not_found" => Self::IdentityNotFound,
            "manual_linking_disabled" => Self::ManualLinkingDisabled,
            "single_identity_not_deletable" => Self::SingleIdentityNotDeletable,
            "oauth_client_not_found" => Self::OAuthClientNotFound,
            "oauth_client_already_exists" => Self::OAuthClientAlreadyExists,
            "oauth_invalid_grant" => Self::OAuthInvalidGrant,
            other => Self::Unknown(other.to_string()),
        }
    }
}

impl From<AuthError> for SupabaseError {
    fn from(err: AuthError) -> Self {
        SupabaseError::Auth(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mfa_error_codes_roundtrip() {
        let codes = [
            ("mfa_factor_name_conflict", AuthErrorCode::MfaFactorNameConflict),
            ("mfa_factor_not_found", AuthErrorCode::MfaFactorNotFound),
            ("mfa_challenge_expired", AuthErrorCode::MfaChallengeExpired),
            ("mfa_verification_failed", AuthErrorCode::MfaVerificationFailed),
            ("mfa_verification_rejected", AuthErrorCode::MfaVerificationRejected),
            ("mfa_ip_address_mismatch", AuthErrorCode::MfaIpAddressMismatch),
            ("mfa_enroll_not_enabled", AuthErrorCode::MfaEnrollNotEnabled),
            ("mfa_verify_not_enabled", AuthErrorCode::MfaVerifyNotEnabled),
        ];
        for (s, expected) in &codes {
            let parsed: AuthErrorCode = (*s).into();
            assert_eq!(parsed, *expected);
            assert_eq!(parsed.to_string(), *s);
        }
    }

    #[test]
    fn sso_error_codes_roundtrip() {
        let parsed: AuthErrorCode = "sso_provider_not_found".into();
        assert_eq!(parsed, AuthErrorCode::SsoProviderNotFound);
        assert_eq!(parsed.to_string(), "sso_provider_not_found");

        let parsed: AuthErrorCode = "sso_domain_already_exists".into();
        assert_eq!(parsed, AuthErrorCode::SsoDomainAlreadyExists);
    }

    #[test]
    fn identity_error_codes_roundtrip() {
        let codes = [
            ("identity_already_exists", AuthErrorCode::IdentityAlreadyExists),
            ("identity_not_found", AuthErrorCode::IdentityNotFound),
            ("manual_linking_disabled", AuthErrorCode::ManualLinkingDisabled),
            ("single_identity_not_deletable", AuthErrorCode::SingleIdentityNotDeletable),
        ];
        for (s, expected) in &codes {
            let parsed: AuthErrorCode = (*s).into();
            assert_eq!(parsed, *expected);
            assert_eq!(parsed.to_string(), *s);
        }
    }

    #[test]
    fn oauth_error_codes_roundtrip() {
        let codes = [
            ("oauth_client_not_found", AuthErrorCode::OAuthClientNotFound),
            ("oauth_client_already_exists", AuthErrorCode::OAuthClientAlreadyExists),
            ("oauth_invalid_grant", AuthErrorCode::OAuthInvalidGrant),
        ];
        for (s, expected) in &codes {
            let parsed: AuthErrorCode = (*s).into();
            assert_eq!(parsed, *expected);
            assert_eq!(parsed.to_string(), *s);
        }
    }
}
