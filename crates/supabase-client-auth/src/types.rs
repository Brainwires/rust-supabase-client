use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::fmt;
use std::time::Duration;
use tokio::sync::broadcast;

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

// ─── OAuth Server Types ──────────────────────────────────────

/// OAuth client grant type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OAuthClientGrantType {
    #[serde(rename = "authorization_code")]
    AuthorizationCode,
    #[serde(rename = "refresh_token")]
    RefreshToken,
}

/// OAuth client response type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OAuthClientResponseType {
    #[serde(rename = "code")]
    Code,
}

/// OAuth client type (public or confidential).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OAuthClientType {
    Public,
    Confidential,
}

/// OAuth client registration type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OAuthClientRegistrationType {
    Dynamic,
    Manual,
}

/// A registered OAuth client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    pub client_id: String,
    pub client_name: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    pub client_type: OAuthClientType,
    pub token_endpoint_auth_method: String,
    pub registration_type: OAuthClientRegistrationType,
    #[serde(default)]
    pub client_uri: Option<String>,
    #[serde(default)]
    pub logo_uri: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<OAuthClientGrantType>,
    pub response_types: Vec<OAuthClientResponseType>,
    #[serde(default)]
    pub scope: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Paginated list of OAuth clients.
#[derive(Debug, Clone, Deserialize)]
pub struct OAuthClientListResponse {
    pub clients: Vec<OAuthClient>,
    #[serde(default)]
    pub aud: Option<String>,
}

/// OAuth authorization client info (subset shown during consent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthAuthorizationClient {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default)]
    pub logo_uri: Option<String>,
}

/// User info in authorization details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthAuthorizationUser {
    pub id: String,
    #[serde(default)]
    pub email: Option<String>,
}

/// OAuth authorization details (consent screen data).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthAuthorizationDetails {
    pub authorization_id: String,
    pub redirect_uri: String,
    pub client: OAuthAuthorizationClient,
    pub user: OAuthAuthorizationUser,
    #[serde(default)]
    pub scope: Option<String>,
}

/// Redirect response from authorization consent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthRedirect {
    pub redirect_url: String,
}

/// Response from getAuthorizationDetails — either details or a redirect.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OAuthAuthorizationDetailsResponse {
    /// User needs to consent — full details provided.
    Details(OAuthAuthorizationDetails),
    /// User already consented — redirect URL provided.
    Redirect(OAuthRedirect),
}

/// A granted OAuth permission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthGrant {
    pub client: OAuthAuthorizationClient,
    pub scopes: Vec<String>,
    pub granted_at: String,
}

// ─── OAuth Client-Side Flow Types ────────────────────────────

/// PKCE code verifier (random string, 43-128 unreserved characters).
#[derive(Debug, Clone)]
pub struct PkceCodeVerifier(pub(crate) String);

impl PkceCodeVerifier {
    /// Get the verifier string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PkceCodeVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// PKCE code challenge (S256 hash of the verifier, base64url-encoded).
#[derive(Debug, Clone)]
pub struct PkceCodeChallenge(pub(crate) String);

impl PkceCodeChallenge {
    /// Get the challenge string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PkceCodeChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A PKCE verifier/challenge pair for OAuth 2.1 authorization code flow.
#[derive(Debug, Clone)]
pub struct PkcePair {
    pub verifier: PkceCodeVerifier,
    pub challenge: PkceCodeChallenge,
}

/// OAuth token response from the `/oauth/token` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTokenResponse {
    pub access_token: String,
    pub token_type: String,
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
}

/// OpenID Connect discovery document.
///
/// Fetched from `/.well-known/openid-configuration`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenIdConfiguration {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    #[serde(default)]
    pub response_types_supported: Vec<String>,
    #[serde(default)]
    pub response_modes_supported: Vec<String>,
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    #[serde(default)]
    pub subject_types_supported: Vec<String>,
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,
    #[serde(default)]
    pub claims_supported: Vec<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
}

/// JSON Web Key Set response.
///
/// Fetched from the `jwks_uri` in the OIDC discovery document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<Jwk>,
}

/// Individual JSON Web Key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type (e.g., "RSA", "EC").
    pub kty: String,
    /// Key ID.
    #[serde(default)]
    pub kid: Option<String>,
    /// Algorithm (e.g., "RS256", "ES256").
    #[serde(default)]
    pub alg: Option<String>,
    /// Public key use (e.g., "sig").
    #[serde(default, rename = "use")]
    pub use_: Option<String>,
    /// Key operations.
    #[serde(default)]
    pub key_ops: Option<Vec<String>>,
    // RSA fields
    /// RSA modulus.
    #[serde(default)]
    pub n: Option<String>,
    /// RSA exponent.
    #[serde(default)]
    pub e: Option<String>,
    // EC fields
    /// EC curve name (e.g., "P-256").
    #[serde(default)]
    pub crv: Option<String>,
    /// EC x coordinate.
    #[serde(default)]
    pub x: Option<String>,
    /// EC y coordinate.
    #[serde(default)]
    pub y: Option<String>,
    /// Whether this is an extractable key.
    #[serde(default)]
    pub ext: Option<bool>,
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

/// Blockchain type for Web3 wallet authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Web3Chain {
    Ethereum,
    Solana,
}

impl fmt::Display for Web3Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ethereum => write!(f, "ethereum"),
            Self::Solana => write!(f, "solana"),
        }
    }
}

/// Parameters for signing in with a Web3 wallet.
#[derive(Debug, Clone, Serialize)]
pub struct Web3SignInParams {
    pub chain: Web3Chain,
    pub address: String,
    pub message: String,
    pub signature: String,
    pub nonce: String,
}

impl Web3SignInParams {
    pub fn new(
        chain: Web3Chain,
        address: impl Into<String>,
        message: impl Into<String>,
        signature: impl Into<String>,
        nonce: impl Into<String>,
    ) -> Self {
        Self {
            chain,
            address: address.into(),
            message: message.into(),
            signature: signature.into(),
            nonce: nonce.into(),
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

// ─── Auth State Management Types ─────────────────────────────

/// Auth state change event types.
///
/// Emitted when the stored session state changes (sign-in, sign-out, refresh, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthChangeEvent {
    /// Initial session loaded (e.g., from set_session).
    InitialSession,
    /// User signed in (password, OTP, OAuth, anonymous, MFA verify, etc.).
    SignedIn,
    /// User signed out.
    SignedOut,
    /// Access token was refreshed.
    TokenRefreshed,
    /// User attributes were updated.
    UserUpdated,
    /// Password recovery flow initiated.
    PasswordRecovery,
}

impl fmt::Display for AuthChangeEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InitialSession => write!(f, "INITIAL_SESSION"),
            Self::SignedIn => write!(f, "SIGNED_IN"),
            Self::SignedOut => write!(f, "SIGNED_OUT"),
            Self::TokenRefreshed => write!(f, "TOKEN_REFRESHED"),
            Self::UserUpdated => write!(f, "USER_UPDATED"),
            Self::PasswordRecovery => write!(f, "PASSWORD_RECOVERY"),
        }
    }
}

/// An auth state change notification, containing the event type and optional session.
#[derive(Debug, Clone)]
pub struct AuthStateChange {
    pub event: AuthChangeEvent,
    pub session: Option<Session>,
}

/// Subscription handle for auth state change events.
///
/// Created by [`AuthClient::on_auth_state_change()`](crate::AuthClient::on_auth_state_change). Use [`next()`](AuthSubscription::next)
/// to await the next event.
pub struct AuthSubscription {
    pub(crate) rx: broadcast::Receiver<AuthStateChange>,
}

impl AuthSubscription {
    /// Await the next auth state change event.
    ///
    /// Returns `None` if the sender has been dropped (client deallocated).
    /// Skips over lagged messages automatically.
    pub async fn next(&mut self) -> Option<AuthStateChange> {
        loop {
            match self.rx.recv().await {
                Ok(change) => return Some(change),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

impl fmt::Debug for AuthSubscription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthSubscription").finish()
    }
}

/// Configuration for automatic token refresh.
#[derive(Debug, Clone)]
pub struct AutoRefreshConfig {
    /// How often to check if the session needs refreshing (default: 30s).
    pub check_interval: Duration,
    /// How far before expiry to trigger a refresh (default: 60s).
    pub refresh_margin: Duration,
    /// Maximum consecutive refresh failures before signing out (default: 3).
    pub max_retries: u32,
}

impl Default for AutoRefreshConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(30),
            refresh_margin: Duration::from_secs(60),
            max_retries: 3,
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

    // ─── OAuth Server Type Tests ──────────────────────────────

    #[test]
    fn oauth_client_type_serde() {
        let json = serde_json::to_string(&OAuthClientType::Confidential).unwrap();
        assert_eq!(json, "\"confidential\"");
        let parsed: OAuthClientType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, OAuthClientType::Confidential);

        let json = serde_json::to_string(&OAuthClientType::Public).unwrap();
        assert_eq!(json, "\"public\"");
        let parsed: OAuthClientType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, OAuthClientType::Public);
    }

    #[test]
    fn oauth_client_grant_type_serde() {
        let json = serde_json::to_string(&OAuthClientGrantType::AuthorizationCode).unwrap();
        assert_eq!(json, "\"authorization_code\"");
        let parsed: OAuthClientGrantType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, OAuthClientGrantType::AuthorizationCode);

        let json = serde_json::to_string(&OAuthClientGrantType::RefreshToken).unwrap();
        assert_eq!(json, "\"refresh_token\"");
        let parsed: OAuthClientGrantType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, OAuthClientGrantType::RefreshToken);
    }

    #[test]
    fn oauth_client_deserialize() {
        let json = r#"{
            "client_id": "abc-123",
            "client_name": "My App",
            "client_secret": "secret-456",
            "client_type": "confidential",
            "token_endpoint_auth_method": "client_secret_post",
            "registration_type": "manual",
            "client_uri": "https://myapp.com",
            "logo_uri": "https://myapp.com/logo.png",
            "redirect_uris": ["https://myapp.com/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": "openid profile",
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z"
        }"#;
        let client: OAuthClient = serde_json::from_str(json).unwrap();
        assert_eq!(client.client_id, "abc-123");
        assert_eq!(client.client_name, "My App");
        assert_eq!(client.client_secret.as_deref(), Some("secret-456"));
        assert_eq!(client.client_type, OAuthClientType::Confidential);
        assert_eq!(client.registration_type, OAuthClientRegistrationType::Manual);
        assert_eq!(client.redirect_uris.len(), 1);
        assert_eq!(client.grant_types.len(), 2);
        assert_eq!(client.response_types.len(), 1);
        assert_eq!(client.scope.as_deref(), Some("openid profile"));
    }

    #[test]
    fn oauth_client_list_response_deserialize() {
        let json = r#"{
            "clients": [{
                "client_id": "abc",
                "client_name": "App",
                "client_type": "public",
                "token_endpoint_auth_method": "none",
                "registration_type": "dynamic",
                "redirect_uris": [],
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z"
            }],
            "aud": "authenticated"
        }"#;
        let resp: OAuthClientListResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.clients.len(), 1);
        assert_eq!(resp.clients[0].client_id, "abc");
        assert_eq!(resp.aud.as_deref(), Some("authenticated"));
    }

    #[test]
    fn oauth_authorization_details_deserialize() {
        let json = r#"{
            "authorization_id": "auth-123",
            "redirect_uri": "https://myapp.com/callback",
            "client": {
                "id": "client-456",
                "name": "My App",
                "uri": "https://myapp.com",
                "logo_uri": "https://myapp.com/logo.png"
            },
            "user": {
                "id": "user-789",
                "email": "user@example.com"
            },
            "scope": "openid"
        }"#;
        let details: OAuthAuthorizationDetails = serde_json::from_str(json).unwrap();
        assert_eq!(details.authorization_id, "auth-123");
        assert_eq!(details.client.id, "client-456");
        assert_eq!(details.user.id, "user-789");
        assert_eq!(details.scope.as_deref(), Some("openid"));
    }

    #[test]
    fn oauth_authorization_details_response_details_variant() {
        let json = r#"{
            "authorization_id": "auth-123",
            "redirect_uri": "https://myapp.com/callback",
            "client": { "id": "c1", "name": "App" },
            "user": { "id": "u1" }
        }"#;
        let resp: OAuthAuthorizationDetailsResponse = serde_json::from_str(json).unwrap();
        match resp {
            OAuthAuthorizationDetailsResponse::Details(d) => {
                assert_eq!(d.authorization_id, "auth-123");
            }
            _ => panic!("Expected Details variant"),
        }
    }

    #[test]
    fn oauth_authorization_details_response_redirect_variant() {
        let json = r#"{"redirect_url": "https://myapp.com/callback?code=abc"}"#;
        let resp: OAuthAuthorizationDetailsResponse = serde_json::from_str(json).unwrap();
        match resp {
            OAuthAuthorizationDetailsResponse::Redirect(r) => {
                assert_eq!(r.redirect_url, "https://myapp.com/callback?code=abc");
            }
            _ => panic!("Expected Redirect variant"),
        }
    }

    #[test]
    fn oauth_grant_deserialize() {
        let json = r#"{
            "client": { "id": "c1", "name": "My App" },
            "scopes": ["openid", "profile"],
            "granted_at": "2024-01-01T00:00:00Z"
        }"#;
        let grant: OAuthGrant = serde_json::from_str(json).unwrap();
        assert_eq!(grant.client.id, "c1");
        assert_eq!(grant.scopes.len(), 2);
        assert_eq!(grant.scopes[0], "openid");
    }

    #[test]
    fn oauth_redirect_deserialize() {
        let json = r#"{"redirect_url": "https://example.com/auth?code=xyz"}"#;
        let redirect: OAuthRedirect = serde_json::from_str(json).unwrap();
        assert_eq!(redirect.redirect_url, "https://example.com/auth?code=xyz");
    }

    // ─── OAuth Client-Side Flow Type Tests ───────────────────

    #[test]
    fn pkce_code_verifier_display_and_as_str() {
        let verifier = PkceCodeVerifier("test-verifier-string".to_string());
        assert_eq!(verifier.as_str(), "test-verifier-string");
        assert_eq!(verifier.to_string(), "test-verifier-string");
    }

    #[test]
    fn pkce_code_challenge_display_and_as_str() {
        let challenge = PkceCodeChallenge("test-challenge-string".to_string());
        assert_eq!(challenge.as_str(), "test-challenge-string");
        assert_eq!(challenge.to_string(), "test-challenge-string");
    }

    #[test]
    fn oauth_token_response_deserialize() {
        let json = r#"{
            "access_token": "eyJ...",
            "token_type": "bearer",
            "expires_in": 3600,
            "refresh_token": "refresh-abc",
            "scope": "openid profile",
            "id_token": "id-token-xyz"
        }"#;
        let resp: OAuthTokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_token, "eyJ...");
        assert_eq!(resp.token_type, "bearer");
        assert_eq!(resp.expires_in, Some(3600));
        assert_eq!(resp.refresh_token.as_deref(), Some("refresh-abc"));
        assert_eq!(resp.scope.as_deref(), Some("openid profile"));
        assert_eq!(resp.id_token.as_deref(), Some("id-token-xyz"));
    }

    #[test]
    fn oauth_token_response_minimal_deserialize() {
        let json = r#"{
            "access_token": "tok",
            "token_type": "bearer"
        }"#;
        let resp: OAuthTokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_token, "tok");
        assert!(resp.expires_in.is_none());
        assert!(resp.refresh_token.is_none());
        assert!(resp.scope.is_none());
        assert!(resp.id_token.is_none());
    }

    #[test]
    fn openid_configuration_deserialize() {
        let json = r#"{
            "issuer": "http://localhost:64321/auth/v1",
            "authorization_endpoint": "http://localhost:64321/auth/v1/authorize",
            "token_endpoint": "http://localhost:64321/auth/v1/oauth/token",
            "jwks_uri": "http://localhost:64321/auth/v1/.well-known/jwks.json",
            "userinfo_endpoint": "http://localhost:64321/auth/v1/oauth/userinfo",
            "scopes_supported": ["openid"],
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["ES256"],
            "code_challenge_methods_supported": ["S256", "plain"]
        }"#;
        let config: OpenIdConfiguration = serde_json::from_str(json).unwrap();
        assert_eq!(config.issuer, "http://localhost:64321/auth/v1");
        assert!(config.jwks_uri.contains("jwks.json"));
        assert!(config.scopes_supported.contains(&"openid".to_string()));
        assert!(config.code_challenge_methods_supported.contains(&"S256".to_string()));
    }

    #[test]
    fn jwks_response_deserialize() {
        let json = r#"{
            "keys": [{
                "kty": "EC",
                "kid": "key-1",
                "alg": "ES256",
                "use": "sig",
                "crv": "P-256",
                "x": "abc123",
                "y": "def456"
            }]
        }"#;
        let jwks: JwksResponse = serde_json::from_str(json).unwrap();
        assert_eq!(jwks.keys.len(), 1);
        let key = &jwks.keys[0];
        assert_eq!(key.kty, "EC");
        assert_eq!(key.kid.as_deref(), Some("key-1"));
        assert_eq!(key.alg.as_deref(), Some("ES256"));
        assert_eq!(key.use_.as_deref(), Some("sig"));
        assert_eq!(key.crv.as_deref(), Some("P-256"));
        assert_eq!(key.x.as_deref(), Some("abc123"));
        assert_eq!(key.y.as_deref(), Some("def456"));
        // RSA fields should be None
        assert!(key.n.is_none());
        assert!(key.e.is_none());
    }

    #[test]
    fn jwk_rsa_deserialize() {
        let json = r#"{
            "kty": "RSA",
            "kid": "rsa-key",
            "alg": "RS256",
            "use": "sig",
            "n": "modulus-base64",
            "e": "AQAB"
        }"#;
        let key: Jwk = serde_json::from_str(json).unwrap();
        assert_eq!(key.kty, "RSA");
        assert_eq!(key.n.as_deref(), Some("modulus-base64"));
        assert_eq!(key.e.as_deref(), Some("AQAB"));
        // EC fields should be None
        assert!(key.crv.is_none());
        assert!(key.x.is_none());
        assert!(key.y.is_none());
    }

    // ─── Auth State Management Type Tests ────────────────────

    #[test]
    fn auth_change_event_display() {
        assert_eq!(AuthChangeEvent::InitialSession.to_string(), "INITIAL_SESSION");
        assert_eq!(AuthChangeEvent::SignedIn.to_string(), "SIGNED_IN");
        assert_eq!(AuthChangeEvent::SignedOut.to_string(), "SIGNED_OUT");
        assert_eq!(AuthChangeEvent::TokenRefreshed.to_string(), "TOKEN_REFRESHED");
        assert_eq!(AuthChangeEvent::UserUpdated.to_string(), "USER_UPDATED");
        assert_eq!(AuthChangeEvent::PasswordRecovery.to_string(), "PASSWORD_RECOVERY");
    }

    #[test]
    fn auth_change_event_equality() {
        assert_eq!(AuthChangeEvent::SignedIn, AuthChangeEvent::SignedIn);
        assert_ne!(AuthChangeEvent::SignedIn, AuthChangeEvent::SignedOut);
    }

    #[test]
    fn auto_refresh_config_default() {
        let config = AutoRefreshConfig::default();
        assert_eq!(config.check_interval, Duration::from_secs(30));
        assert_eq!(config.refresh_margin, Duration::from_secs(60));
        assert_eq!(config.max_retries, 3);
    }

    #[test]
    fn auto_refresh_config_custom() {
        let config = AutoRefreshConfig {
            check_interval: Duration::from_secs(10),
            refresh_margin: Duration::from_secs(120),
            max_retries: 5,
        };
        assert_eq!(config.check_interval, Duration::from_secs(10));
        assert_eq!(config.refresh_margin, Duration::from_secs(120));
        assert_eq!(config.max_retries, 5);
    }
}
