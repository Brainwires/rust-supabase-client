use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::fmt;

/// A user session returned from sign-in, sign-up, or token refresh.
///
/// Matches the Supabase GoTrue session object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    #[serde(default)]
    pub expires_at: Option<i64>,
    pub token_type: String,
    pub user: User,
}

/// A GoTrue user object.
///
/// Matches the Supabase `User` type from the JS/C# client libraries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    #[serde(default)]
    pub aud: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub email_confirmed_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub phone_confirmed_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub confirmation_sent_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub recovery_sent_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_sign_in_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub user_metadata: Option<JsonValue>,
    #[serde(default)]
    pub app_metadata: Option<JsonValue>,
    #[serde(default)]
    pub identities: Option<Vec<Identity>>,
    #[serde(default)]
    pub factors: Option<Vec<Factor>>,
    #[serde(default)]
    pub is_anonymous: Option<bool>,
}

/// A linked auth provider identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub id: String,
    pub user_id: String,
    #[serde(default)]
    pub identity_data: Option<JsonValue>,
    pub provider: String,
    #[serde(default)]
    pub identity_id: Option<String>,
    #[serde(default)]
    pub last_sign_in_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
}

/// An MFA factor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Factor {
    pub id: String,
    #[serde(default)]
    pub friendly_name: Option<String>,
    pub factor_type: String,
    pub status: String,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub last_challenged_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
}

/// MFA factor type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FactorType {
    Totp,
    Phone,
}

impl fmt::Display for FactorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Totp => write!(f, "totp"),
            Self::Phone => write!(f, "phone"),
        }
    }
}

/// MFA factor status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FactorStatus {
    Unverified,
    Verified,
}

impl fmt::Display for FactorStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unverified => write!(f, "unverified"),
            Self::Verified => write!(f, "verified"),
        }
    }
}

/// Authenticator Assurance Level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticatorAssuranceLevel {
    /// Single-factor authentication (password, OTP, etc.).
    Aal1,
    /// Multi-factor authentication (password + TOTP/phone).
    Aal2,
}

impl fmt::Display for AuthenticatorAssuranceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aal1 => write!(f, "aal1"),
            Self::Aal2 => write!(f, "aal2"),
        }
    }
}

/// Response from MFA enroll.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaEnrollResponse {
    pub id: String,
    #[serde(rename = "type")]
    pub factor_type: String,
    #[serde(default)]
    pub friendly_name: Option<String>,
    #[serde(default)]
    pub totp: Option<MfaTotpInfo>,
    #[serde(default)]
    pub phone: Option<String>,
}

/// TOTP-specific info from MFA enroll.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaTotpInfo {
    pub qr_code: String,
    pub secret: String,
    pub uri: String,
}

/// Response from MFA challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaChallengeResponse {
    pub id: String,
    #[serde(default, rename = "type")]
    pub factor_type: Option<String>,
    #[serde(default)]
    pub expires_at: Option<i64>,
}

/// Response from MFA unenroll.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaUnenrollResponse {
    pub id: String,
}

/// Categorized list of enrolled MFA factors.
#[derive(Debug, Clone)]
pub struct MfaListFactorsResponse {
    pub totp: Vec<Factor>,
    pub phone: Vec<Factor>,
    pub all: Vec<Factor>,
}

/// Authenticator assurance level info.
#[derive(Debug, Clone)]
pub struct AuthenticatorAssuranceLevelInfo {
    pub current_level: Option<AuthenticatorAssuranceLevel>,
    pub next_level: Option<AuthenticatorAssuranceLevel>,
    pub current_authentication_methods: Vec<AmrEntry>,
}

/// Authentication Method Reference entry from the JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmrEntry {
    pub method: String,
    #[serde(default)]
    pub timestamp: Option<i64>,
}

/// Response from SSO sign-in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoSignInResponse {
    pub url: String,
}

/// Response from identity link (returns redirect URL).
#[derive(Debug, Clone)]
pub struct LinkIdentityResponse {
    pub url: String,
}

/// Response from sign-up and some auth operations.
///
/// Mirrors Supabase JS `AuthResponse` — contains an optional session and/or user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    #[serde(default)]
    pub session: Option<Session>,
    #[serde(default)]
    pub user: Option<User>,
}

/// Paginated list of users returned by admin endpoints.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminUserListResponse {
    pub users: Vec<User>,
    #[serde(default)]
    pub aud: Option<String>,
    #[serde(default, rename = "nextPage")]
    pub next_page: Option<u32>,
    #[serde(default, rename = "lastPage")]
    pub last_page: Option<u32>,
    #[serde(default)]
    pub total: Option<u64>,
}

/// Supported OAuth providers.
///
/// Matches the provider strings accepted by Supabase GoTrue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthProvider {
    Apple,
    Azure,
    Bitbucket,
    Discord,
    Facebook,
    Figma,
    Fly,
    GitHub,
    GitLab,
    Google,
    Kakao,
    Keycloak,
    LinkedIn,
    LinkedInOidc,
    Notion,
    Slack,
    SlackOidc,
    Spotify,
    Twitch,
    Twitter,
    WorkOS,
    Zoom,
    Custom(String),
}

impl fmt::Display for OAuthProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Apple => write!(f, "apple"),
            Self::Azure => write!(f, "azure"),
            Self::Bitbucket => write!(f, "bitbucket"),
            Self::Discord => write!(f, "discord"),
            Self::Facebook => write!(f, "facebook"),
            Self::Figma => write!(f, "figma"),
            Self::Fly => write!(f, "fly"),
            Self::GitHub => write!(f, "github"),
            Self::GitLab => write!(f, "gitlab"),
            Self::Google => write!(f, "google"),
            Self::Kakao => write!(f, "kakao"),
            Self::Keycloak => write!(f, "keycloak"),
            Self::LinkedIn => write!(f, "linkedin"),
            Self::LinkedInOidc => write!(f, "linkedin_oidc"),
            Self::Notion => write!(f, "notion"),
            Self::Slack => write!(f, "slack"),
            Self::SlackOidc => write!(f, "slack_oidc"),
            Self::Spotify => write!(f, "spotify"),
            Self::Twitch => write!(f, "twitch"),
            Self::Twitter => write!(f, "twitter"),
            Self::WorkOS => write!(f, "workos"),
            Self::Zoom => write!(f, "zoom"),
            Self::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// OTP delivery channel for phone-based OTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OtpChannel {
    Sms,
    Whatsapp,
}

impl fmt::Display for OtpChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sms => write!(f, "sms"),
            Self::Whatsapp => write!(f, "whatsapp"),
        }
    }
}

/// Scope for sign-out operations.
///
/// Matches `SignOutScope` from Supabase JS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignOutScope {
    /// Sign out from the current session only.
    Local,
    /// Sign out from all other sessions (keep current).
    Others,
    /// Sign out from all sessions including current.
    Global,
}

impl fmt::Display for SignOutScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local => write!(f, "local"),
            Self::Others => write!(f, "others"),
            Self::Global => write!(f, "global"),
        }
    }
}

/// OTP verification type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OtpType {
    Email,
    Sms,
    #[serde(rename = "phone_change")]
    PhoneChange,
    #[serde(rename = "email_change")]
    EmailChange,
    Signup,
    Recovery,
    Invite,
    #[serde(rename = "magiclink")]
    MagicLink,
}

impl fmt::Display for OtpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Email => write!(f, "email"),
            Self::Sms => write!(f, "sms"),
            Self::PhoneChange => write!(f, "phone_change"),
            Self::EmailChange => write!(f, "email_change"),
            Self::Signup => write!(f, "signup"),
            Self::Recovery => write!(f, "recovery"),
            Self::Invite => write!(f, "invite"),
            Self::MagicLink => write!(f, "magiclink"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factor_type_display() {
        assert_eq!(FactorType::Totp.to_string(), "totp");
        assert_eq!(FactorType::Phone.to_string(), "phone");
    }

    #[test]
    fn factor_type_serde_roundtrip() {
        let json = serde_json::to_string(&FactorType::Totp).unwrap();
        assert_eq!(json, "\"totp\"");
        let parsed: FactorType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, FactorType::Totp);
    }

    #[test]
    fn factor_status_display() {
        assert_eq!(FactorStatus::Unverified.to_string(), "unverified");
        assert_eq!(FactorStatus::Verified.to_string(), "verified");
    }

    #[test]
    fn authenticator_assurance_level_display() {
        assert_eq!(AuthenticatorAssuranceLevel::Aal1.to_string(), "aal1");
        assert_eq!(AuthenticatorAssuranceLevel::Aal2.to_string(), "aal2");
    }

    #[test]
    fn mfa_list_factors_categorization() {
        let factors = vec![
            Factor {
                id: "f1".into(),
                friendly_name: Some("My TOTP".into()),
                factor_type: "totp".into(),
                status: "verified".into(),
                phone: None,
                last_challenged_at: None,
                created_at: None,
                updated_at: None,
            },
            Factor {
                id: "f2".into(),
                friendly_name: Some("My Phone".into()),
                factor_type: "phone".into(),
                status: "unverified".into(),
                phone: Some("+1234567890".into()),
                last_challenged_at: None,
                created_at: None,
                updated_at: None,
            },
        ];

        let totp: Vec<_> = factors.iter().filter(|f| f.factor_type == "totp").collect();
        let phone: Vec<_> = factors.iter().filter(|f| f.factor_type == "phone").collect();

        assert_eq!(totp.len(), 1);
        assert_eq!(totp[0].id, "f1");
        assert_eq!(phone.len(), 1);
        assert_eq!(phone[0].id, "f2");
    }

    #[test]
    fn mfa_enroll_response_deserialize() {
        let json = r#"{
            "id": "factor-uuid",
            "type": "totp",
            "friendly_name": "My Authenticator",
            "totp": {
                "qr_code": "data:image/svg+xml;...",
                "secret": "BASE32SECRET",
                "uri": "otpauth://totp/..."
            }
        }"#;
        let resp: MfaEnrollResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, "factor-uuid");
        assert_eq!(resp.factor_type, "totp");
        assert!(resp.totp.is_some());
        let totp = resp.totp.unwrap();
        assert_eq!(totp.secret, "BASE32SECRET");
    }

    #[test]
    fn mfa_challenge_response_deserialize() {
        let json = r#"{"id": "challenge-uuid", "type": "totp", "expires_at": 1700000000}"#;
        let resp: MfaChallengeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, "challenge-uuid");
        assert_eq!(resp.factor_type.as_deref(), Some("totp"));
        assert_eq!(resp.expires_at, Some(1700000000));
    }

    #[test]
    fn sso_sign_in_response_deserialize() {
        let json = r#"{"url": "https://sso.example.com/login"}"#;
        let resp: SsoSignInResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.url, "https://sso.example.com/login");
    }

    #[test]
    fn factor_with_new_fields_deserialize() {
        let json = r#"{
            "id": "f1",
            "factor_type": "phone",
            "status": "verified",
            "phone": "+1234567890",
            "last_challenged_at": "2024-01-01T00:00:00Z"
        }"#;
        let factor: Factor = serde_json::from_str(json).unwrap();
        assert_eq!(factor.phone.as_deref(), Some("+1234567890"));
        assert!(factor.last_challenged_at.is_some());
    }

    #[test]
    fn amr_entry_deserialize() {
        let json = r#"{"method": "totp", "timestamp": 1700000000}"#;
        let entry: AmrEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.method, "totp");
        assert_eq!(entry.timestamp, Some(1700000000));
    }
}
