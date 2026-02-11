use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::types::{FactorType, OtpChannel, OtpType};

/// Parameters for updating the current user.
///
/// Matches the `UserAttributes` parameter in Supabase JS `updateUser()`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct UpdateUserParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// Parameters for verifying an OTP token.
///
/// Matches the `VerifyOtpParams` union type in Supabase JS.
#[derive(Debug, Clone, Serialize)]
pub struct VerifyOtpParams {
    pub token: String,
    #[serde(rename = "type")]
    pub otp_type: OtpType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_hash: Option<String>,
}

/// Parameters for admin user creation.
///
/// Matches `AdminUserAttributes` in Supabase JS `admin.createUser()`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AdminCreateUserParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_confirm: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_confirm: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_metadata: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_metadata: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ban_duration: Option<String>,
}

/// Parameters for admin user update.
///
/// Matches `AdminUserAttributes` in Supabase JS `admin.updateUserById()`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AdminUpdateUserParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_confirm: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_confirm: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_metadata: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_metadata: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ban_duration: Option<String>,
}

/// Parameters for generating a link (admin).
#[derive(Debug, Clone, Serialize)]
pub struct GenerateLinkParams {
    #[serde(rename = "type")]
    pub link_type: GenerateLinkType,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_to: Option<String>,
}

/// Types of links that can be generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GenerateLinkType {
    Signup,
    Invite,
    #[serde(rename = "magiclink")]
    MagicLink,
    Recovery,
    #[serde(rename = "email_change_new")]
    EmailChangeNew,
    #[serde(rename = "email_change_current")]
    EmailChangeCurrent,
}

// ─── MFA Params ───────────────────────────────────────────────

/// Parameters for enrolling a new MFA factor.
///
/// Use `MfaEnrollParams::totp()` or `MfaEnrollParams::phone(number)` to create.
#[derive(Debug, Clone, Serialize)]
pub struct MfaEnrollParams {
    pub factor_type: FactorType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
}

impl MfaEnrollParams {
    /// Create params for enrolling a TOTP factor.
    pub fn totp() -> Self {
        Self {
            factor_type: FactorType::Totp,
            friendly_name: None,
            issuer: None,
            phone: None,
        }
    }

    /// Create params for enrolling a phone factor.
    pub fn phone(number: &str) -> Self {
        Self {
            factor_type: FactorType::Phone,
            friendly_name: None,
            issuer: None,
            phone: Some(number.to_string()),
        }
    }

    /// Set a friendly name for the factor.
    pub fn friendly_name(mut self, name: &str) -> Self {
        self.friendly_name = Some(name.to_string());
        self
    }

    /// Set the TOTP issuer (only for TOTP factors).
    pub fn issuer(mut self, issuer: &str) -> Self {
        self.issuer = Some(issuer.to_string());
        self
    }
}

/// Parameters for verifying an MFA challenge.
#[derive(Debug, Clone, Serialize)]
pub struct MfaVerifyParams {
    pub challenge_id: String,
    pub code: String,
}

impl MfaVerifyParams {
    /// Create new verify params.
    pub fn new(challenge_id: &str, code: &str) -> Self {
        Self {
            challenge_id: challenge_id.to_string(),
            code: code.to_string(),
        }
    }
}

/// Parameters for creating an MFA challenge.
#[derive(Debug, Clone, Default, Serialize)]
pub struct MfaChallengeParams {
    /// Channel for phone factors (sms or whatsapp). Ignored for TOTP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<OtpChannel>,
}

// ─── SSO Params ───────────────────────────────────────────────

/// Parameters for enterprise SAML SSO sign-in.
///
/// Use `SsoSignInParams::domain(d)` or `SsoSignInParams::provider_id(id)` to create.
#[derive(Debug, Clone, Serialize)]
pub struct SsoSignInParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_to: Option<String>,
    /// Always true for REST clients (prevents HTTP redirect).
    pub skip_http_redirect: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_method: Option<String>,
}

impl SsoSignInParams {
    /// Create SSO sign-in params by domain.
    pub fn domain(domain: &str) -> Self {
        Self {
            domain: Some(domain.to_string()),
            provider_id: None,
            redirect_to: None,
            skip_http_redirect: true,
            code_challenge: None,
            code_challenge_method: None,
        }
    }

    /// Create SSO sign-in params by provider ID.
    pub fn provider_id(id: &str) -> Self {
        Self {
            domain: None,
            provider_id: Some(id.to_string()),
            redirect_to: None,
            skip_http_redirect: true,
            code_challenge: None,
            code_challenge_method: None,
        }
    }

    /// Set the redirect URL after SSO sign-in.
    pub fn redirect_to(mut self, url: &str) -> Self {
        self.redirect_to = Some(url.to_string());
        self
    }

    /// Set the PKCE code challenge.
    pub fn code_challenge(mut self, challenge: &str, method: &str) -> Self {
        self.code_challenge = Some(challenge.to_string());
        self.code_challenge_method = Some(method.to_string());
        self
    }
}

// ─── ID Token Params ──────────────────────────────────────────

/// Parameters for signing in with an external OIDC ID token.
///
/// Used for native mobile auth (e.g., Google, Apple Sign-In).
#[derive(Debug, Clone, Serialize)]
pub struct SignInWithIdTokenParams {
    pub provider: String,
    #[serde(rename = "id_token")]
    pub id_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

impl SignInWithIdTokenParams {
    /// Create new params.
    pub fn new(provider: &str, id_token: &str) -> Self {
        Self {
            provider: provider.to_string(),
            id_token: id_token.to_string(),
            access_token: None,
            nonce: None,
        }
    }

    /// Set the nonce for verification.
    pub fn nonce(mut self, nonce: &str) -> Self {
        self.nonce = Some(nonce.to_string());
        self
    }

    /// Set the provider's access token.
    pub fn access_token(mut self, token: &str) -> Self {
        self.access_token = Some(token.to_string());
        self
    }
}

// ─── Resend Params ────────────────────────────────────────────

/// Type of OTP/confirmation to resend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResendType {
    Signup,
    EmailChange,
    Sms,
    PhoneChange,
}

impl std::fmt::Display for ResendType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Signup => write!(f, "signup"),
            Self::EmailChange => write!(f, "email_change"),
            Self::Sms => write!(f, "sms"),
            Self::PhoneChange => write!(f, "phone_change"),
        }
    }
}

/// Parameters for resending an OTP or confirmation.
#[derive(Debug, Clone, Serialize)]
pub struct ResendParams {
    #[serde(rename = "type")]
    pub resend_type: ResendType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
}

impl ResendParams {
    /// Create resend params for email-based OTP types (Signup or EmailChange).
    pub fn email(email: &str, resend_type: ResendType) -> Self {
        Self {
            resend_type,
            email: Some(email.to_string()),
            phone: None,
        }
    }

    /// Create resend params for phone-based OTP types (Sms or PhoneChange).
    pub fn phone(phone: &str, resend_type: ResendType) -> Self {
        Self {
            resend_type,
            email: None,
            phone: Some(phone.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mfa_enroll_params_totp_builder() {
        let params = MfaEnrollParams::totp()
            .friendly_name("My Auth")
            .issuer("MyApp");
        assert_eq!(params.factor_type, FactorType::Totp);
        assert_eq!(params.friendly_name.as_deref(), Some("My Auth"));
        assert_eq!(params.issuer.as_deref(), Some("MyApp"));
        assert!(params.phone.is_none());
    }

    #[test]
    fn mfa_enroll_params_phone_builder() {
        let params = MfaEnrollParams::phone("+1234567890")
            .friendly_name("My Phone");
        assert_eq!(params.factor_type, FactorType::Phone);
        assert_eq!(params.phone.as_deref(), Some("+1234567890"));
        assert_eq!(params.friendly_name.as_deref(), Some("My Phone"));
    }

    #[test]
    fn mfa_enroll_params_totp_serialization() {
        let params = MfaEnrollParams::totp().friendly_name("Test");
        let json = serde_json::to_value(&params).unwrap();
        assert_eq!(json["factor_type"], "totp");
        assert_eq!(json["friendly_name"], "Test");
        assert!(json.get("phone").is_none());
        assert!(json.get("issuer").is_none());
    }

    #[test]
    fn mfa_verify_params_new() {
        let params = MfaVerifyParams::new("challenge-id", "123456");
        assert_eq!(params.challenge_id, "challenge-id");
        assert_eq!(params.code, "123456");
    }

    #[test]
    fn sso_sign_in_params_domain_builder() {
        let params = SsoSignInParams::domain("company.com")
            .redirect_to("https://app.com/callback");
        assert_eq!(params.domain.as_deref(), Some("company.com"));
        assert!(params.provider_id.is_none());
        assert_eq!(params.redirect_to.as_deref(), Some("https://app.com/callback"));
        assert!(params.skip_http_redirect);
    }

    #[test]
    fn sso_sign_in_params_provider_id_builder() {
        let params = SsoSignInParams::provider_id("uuid-123");
        assert!(params.domain.is_none());
        assert_eq!(params.provider_id.as_deref(), Some("uuid-123"));
        assert!(params.skip_http_redirect);
    }

    #[test]
    fn sign_in_with_id_token_params_builder() {
        let params = SignInWithIdTokenParams::new("google", "eyJ...")
            .nonce("random-nonce")
            .access_token("goog-access");
        assert_eq!(params.provider, "google");
        assert_eq!(params.id_token, "eyJ...");
        assert_eq!(params.nonce.as_deref(), Some("random-nonce"));
        assert_eq!(params.access_token.as_deref(), Some("goog-access"));
    }

    #[test]
    fn sign_in_with_id_token_serialization() {
        let params = SignInWithIdTokenParams::new("apple", "token123");
        let json = serde_json::to_value(&params).unwrap();
        assert_eq!(json["provider"], "apple");
        assert_eq!(json["id_token"], "token123");
        assert!(json.get("nonce").is_none());
    }

    #[test]
    fn resend_params_email_builder() {
        let params = ResendParams::email("user@example.com", ResendType::Signup);
        assert_eq!(params.resend_type, ResendType::Signup);
        assert_eq!(params.email.as_deref(), Some("user@example.com"));
        assert!(params.phone.is_none());
    }

    #[test]
    fn resend_params_phone_builder() {
        let params = ResendParams::phone("+1234567890", ResendType::PhoneChange);
        assert_eq!(params.resend_type, ResendType::PhoneChange);
        assert_eq!(params.phone.as_deref(), Some("+1234567890"));
        assert!(params.email.is_none());
    }

    #[test]
    fn resend_type_display() {
        assert_eq!(ResendType::Signup.to_string(), "signup");
        assert_eq!(ResendType::EmailChange.to_string(), "email_change");
        assert_eq!(ResendType::Sms.to_string(), "sms");
        assert_eq!(ResendType::PhoneChange.to_string(), "phone_change");
    }

    #[test]
    fn resend_params_serialization() {
        let params = ResendParams::email("test@example.com", ResendType::Signup);
        let json = serde_json::to_value(&params).unwrap();
        assert_eq!(json["type"], "signup");
        assert_eq!(json["email"], "test@example.com");
        assert!(json.get("phone").is_none());
    }
}
