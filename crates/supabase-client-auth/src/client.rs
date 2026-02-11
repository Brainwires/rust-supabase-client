use base64::Engine;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use serde_json::{json, Value as JsonValue};
use sha2::{Digest, Sha256};
use url::Url;

use crate::admin::AdminClient;
use crate::error::{AuthError, GoTrueErrorResponse};
use crate::params::{
    MfaChallengeParams, MfaEnrollParams, MfaVerifyParams, OAuthAuthorizeUrlParams,
    OAuthTokenExchangeParams, ResendParams, SignInWithIdTokenParams, SsoSignInParams,
    UpdateUserParams, VerifyOtpParams,
};
use crate::types::*;

/// HTTP client for Supabase GoTrue auth API.
///
/// Communicates with GoTrue REST endpoints at `/auth/v1/...`.
///
/// # Example
/// ```ignore
/// use supabase_client_auth::AuthClient;
///
/// let auth = AuthClient::new("https://your-project.supabase.co", "your-anon-key")?;
/// let session = auth.sign_in_with_password_email("user@example.com", "password").await?;
/// ```
#[derive(Debug, Clone)]
pub struct AuthClient {
    http: reqwest::Client,
    base_url: Url,
    api_key: String,
}

impl AuthClient {
    /// Create a new auth client.
    ///
    /// `supabase_url` is the project URL (e.g., `https://your-project.supabase.co`).
    /// `api_key` is the Supabase anon key, sent as the `apikey` header.
    pub fn new(supabase_url: &str, api_key: &str) -> Result<Self, AuthError> {
        let base = supabase_url.trim_end_matches('/');
        let base_url = Url::parse(&format!("{}/auth/v1", base))?;

        let mut default_headers = HeaderMap::new();
        default_headers.insert(
            "apikey",
            HeaderValue::from_str(api_key)
                .map_err(|e| AuthError::InvalidConfig(format!("Invalid API key header: {}", e)))?,
        );
        default_headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );

        let http = reqwest::Client::builder()
            .default_headers(default_headers)
            .build()
            .map_err(AuthError::Http)?;

        Ok(Self {
            http,
            base_url,
            api_key: api_key.to_string(),
        })
    }

    /// Get the base URL for the auth API.
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    // ─── Sign Up ───────────────────────────────────────────────

    /// Sign up a new user with email and password.
    ///
    /// Mirrors `supabase.auth.signUp({ email, password })`.
    pub async fn sign_up_with_email(
        &self,
        email: &str,
        password: &str,
    ) -> Result<AuthResponse, AuthError> {
        self.sign_up_with_email_and_data(email, password, None).await
    }

    /// Sign up a new user with email, password, and custom user metadata.
    ///
    /// Mirrors `supabase.auth.signUp({ email, password, options: { data } })`.
    pub async fn sign_up_with_email_and_data(
        &self,
        email: &str,
        password: &str,
        data: Option<JsonValue>,
    ) -> Result<AuthResponse, AuthError> {
        let mut body = json!({
            "email": email,
            "password": password,
        });
        if let Some(data) = data {
            body["data"] = data;
        }

        let url = self.url("/signup");
        let resp = self.http.post(url).json(&body).send().await?;
        self.handle_auth_response(resp).await
    }

    /// Sign up a new user with phone and password.
    ///
    /// Mirrors `supabase.auth.signUp({ phone, password })`.
    pub async fn sign_up_with_phone(
        &self,
        phone: &str,
        password: &str,
    ) -> Result<AuthResponse, AuthError> {
        let body = json!({
            "phone": phone,
            "password": password,
        });

        let url = self.url("/signup");
        let resp = self.http.post(url).json(&body).send().await?;
        self.handle_auth_response(resp).await
    }

    // ─── Sign In ───────────────────────────────────────────────

    /// Sign in with email and password.
    ///
    /// Mirrors `supabase.auth.signInWithPassword({ email, password })`.
    pub async fn sign_in_with_password_email(
        &self,
        email: &str,
        password: &str,
    ) -> Result<Session, AuthError> {
        let body = json!({
            "email": email,
            "password": password,
        });

        let url = self.url("/token?grant_type=password");
        let resp = self.http.post(url).json(&body).send().await?;
        self.handle_session_response(resp).await
    }

    /// Sign in with phone and password.
    ///
    /// Mirrors `supabase.auth.signInWithPassword({ phone, password })`.
    pub async fn sign_in_with_password_phone(
        &self,
        phone: &str,
        password: &str,
    ) -> Result<Session, AuthError> {
        let body = json!({
            "phone": phone,
            "password": password,
        });

        let url = self.url("/token?grant_type=password");
        let resp = self.http.post(url).json(&body).send().await?;
        self.handle_session_response(resp).await
    }

    /// Send a magic link / OTP to an email address.
    ///
    /// Mirrors `supabase.auth.signInWithOtp({ email })`.
    pub async fn sign_in_with_otp_email(&self, email: &str) -> Result<(), AuthError> {
        let body = json!({
            "email": email,
        });

        let url = self.url("/otp");
        let resp = self.http.post(url).json(&body).send().await?;
        self.handle_empty_response(resp).await
    }

    /// Send an OTP to a phone number.
    ///
    /// Mirrors `supabase.auth.signInWithOtp({ phone, options: { channel } })`.
    pub async fn sign_in_with_otp_phone(
        &self,
        phone: &str,
        channel: OtpChannel,
    ) -> Result<(), AuthError> {
        let body = json!({
            "phone": phone,
            "channel": channel,
        });

        let url = self.url("/otp");
        let resp = self.http.post(url).json(&body).send().await?;
        self.handle_empty_response(resp).await
    }

    /// Verify an OTP token.
    ///
    /// Mirrors `supabase.auth.verifyOtp(params)`.
    pub async fn verify_otp(&self, params: VerifyOtpParams) -> Result<Session, AuthError> {
        let url = self.url("/verify");
        let resp = self.http.post(url).json(&params).send().await?;
        self.handle_session_response(resp).await
    }

    /// Sign in anonymously, creating a new anonymous user.
    ///
    /// Mirrors `supabase.auth.signInAnonymously()`.
    pub async fn sign_in_anonymous(&self) -> Result<Session, AuthError> {
        let url = self.url("/signup");
        let body = json!({});
        let resp = self.http.post(url).json(&body).send().await?;
        self.handle_session_response(resp).await
    }

    // ─── OAuth ─────────────────────────────────────────────────

    /// Build the OAuth sign-in URL for a given provider.
    ///
    /// Returns the URL to redirect the user to. This does not make a network request.
    ///
    /// Mirrors `supabase.auth.signInWithOAuth({ provider, options })`.
    pub fn get_oauth_sign_in_url(
        &self,
        provider: OAuthProvider,
        redirect_to: Option<&str>,
        scopes: Option<&str>,
    ) -> Result<String, AuthError> {
        let mut url = self.url("/authorize");
        url.query_pairs_mut()
            .append_pair("provider", &provider.to_string());

        if let Some(redirect) = redirect_to {
            url.query_pairs_mut()
                .append_pair("redirect_to", redirect);
        }
        if let Some(scopes) = scopes {
            url.query_pairs_mut().append_pair("scopes", scopes);
        }

        Ok(url.to_string())
    }

    /// Exchange an auth code (from PKCE flow) for a session.
    ///
    /// Mirrors `supabase.auth.exchangeCodeForSession(authCode)`.
    pub async fn exchange_code_for_session(
        &self,
        code: &str,
        code_verifier: Option<&str>,
    ) -> Result<Session, AuthError> {
        let mut body = json!({
            "auth_code": code,
        });
        if let Some(verifier) = code_verifier {
            body["code_verifier"] = json!(verifier);
        }

        let url = self.url("/token?grant_type=pkce");
        let resp = self.http.post(url).json(&body).send().await?;
        self.handle_session_response(resp).await
    }

    // ─── Session Management ────────────────────────────────────

    /// Refresh a session using a refresh token.
    ///
    /// Mirrors `supabase.auth.refreshSession()`.
    pub async fn refresh_session(&self, refresh_token: &str) -> Result<Session, AuthError> {
        let body = json!({
            "refresh_token": refresh_token,
        });

        let url = self.url("/token?grant_type=refresh_token");
        let resp = self.http.post(url).json(&body).send().await?;
        self.handle_session_response(resp).await
    }

    // ─── User Management ───────────────────────────────────────

    /// Get the user associated with an access token.
    ///
    /// Makes a network request to GoTrue to validate the token and fetch the user.
    ///
    /// Mirrors `supabase.auth.getUser(jwt?)`.
    pub async fn get_user(&self, access_token: &str) -> Result<User, AuthError> {
        let url = self.url("/user");
        let resp = self
            .http
            .get(url)
            .bearer_auth(access_token)
            .send()
            .await?;
        self.handle_user_response(resp).await
    }

    /// Update the current user's attributes.
    ///
    /// Mirrors `supabase.auth.updateUser(attributes)`.
    pub async fn update_user(
        &self,
        access_token: &str,
        params: UpdateUserParams,
    ) -> Result<User, AuthError> {
        let url = self.url("/user");
        let resp = self
            .http
            .put(url)
            .bearer_auth(access_token)
            .json(&params)
            .send()
            .await?;
        self.handle_user_response(resp).await
    }

    // ─── Sign Out ──────────────────────────────────────────────

    /// Sign out the user (global scope by default).
    ///
    /// Mirrors `supabase.auth.signOut()`.
    pub async fn sign_out(&self, access_token: &str) -> Result<(), AuthError> {
        self.sign_out_with_scope(access_token, SignOutScope::Global)
            .await
    }

    /// Sign out with a specific scope.
    ///
    /// Mirrors `supabase.auth.signOut({ scope })`.
    pub async fn sign_out_with_scope(
        &self,
        access_token: &str,
        scope: SignOutScope,
    ) -> Result<(), AuthError> {
        let url = self.url(&format!("/logout?scope={}", scope));
        let resp = self
            .http
            .post(url)
            .bearer_auth(access_token)
            .send()
            .await?;
        self.handle_empty_response(resp).await
    }

    // ─── Password Recovery ─────────────────────────────────────

    /// Send a password reset email.
    ///
    /// Mirrors `supabase.auth.resetPasswordForEmail(email, options)`.
    pub async fn reset_password_for_email(
        &self,
        email: &str,
        redirect_to: Option<&str>,
    ) -> Result<(), AuthError> {
        let mut body = json!({ "email": email });
        if let Some(redirect) = redirect_to {
            body["redirect_to"] = json!(redirect);
        }

        let url = self.url("/recover");
        let resp = self.http.post(url).json(&body).send().await?;
        self.handle_empty_response(resp).await
    }

    // ─── Admin ─────────────────────────────────────────────────

    /// Create an admin client using the current API key as the service role key.
    ///
    /// The API key must be a `service_role` key for admin operations to work.
    ///
    /// Mirrors `supabase.auth.admin`.
    pub fn admin(&self) -> AdminClient<'_> {
        AdminClient::new(self)
    }

    /// Create an admin client with an explicit service role key.
    pub fn admin_with_key<'a>(&'a self, service_role_key: &'a str) -> AdminClient<'a> {
        AdminClient::with_key(self, service_role_key)
    }

    // ─── MFA ───────────────────────────────────────────────────

    /// Enroll a new MFA factor (TOTP or phone).
    ///
    /// Mirrors `supabase.auth.mfa.enroll()`.
    pub async fn mfa_enroll(
        &self,
        access_token: &str,
        params: MfaEnrollParams,
    ) -> Result<MfaEnrollResponse, AuthError> {
        let url = self.url("/factors");
        let resp = self
            .http
            .post(url)
            .bearer_auth(access_token)
            .json(&params)
            .send()
            .await?;
        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(self.parse_error(status, resp).await);
        }
        let body: MfaEnrollResponse = resp.json().await?;
        Ok(body)
    }

    /// Create a challenge for an enrolled factor.
    ///
    /// Mirrors `supabase.auth.mfa.challenge()`.
    pub async fn mfa_challenge(
        &self,
        access_token: &str,
        factor_id: &str,
    ) -> Result<MfaChallengeResponse, AuthError> {
        self.mfa_challenge_with_params(access_token, factor_id, MfaChallengeParams::default())
            .await
    }

    /// Create a challenge for an enrolled factor with additional params.
    ///
    /// The `params` can specify the channel (sms/whatsapp) for phone factors.
    pub async fn mfa_challenge_with_params(
        &self,
        access_token: &str,
        factor_id: &str,
        params: MfaChallengeParams,
    ) -> Result<MfaChallengeResponse, AuthError> {
        let url = self.url(&format!("/factors/{}/challenge", factor_id));
        let resp = self
            .http
            .post(url)
            .bearer_auth(access_token)
            .json(&params)
            .send()
            .await?;
        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(self.parse_error(status, resp).await);
        }
        let body: MfaChallengeResponse = resp.json().await?;
        Ok(body)
    }

    /// Verify an MFA challenge with a TOTP/SMS code. Returns a new AAL2 session.
    ///
    /// Mirrors `supabase.auth.mfa.verify()`.
    pub async fn mfa_verify(
        &self,
        access_token: &str,
        factor_id: &str,
        params: MfaVerifyParams,
    ) -> Result<Session, AuthError> {
        let url = self.url(&format!("/factors/{}/verify", factor_id));
        let resp = self
            .http
            .post(url)
            .bearer_auth(access_token)
            .json(&params)
            .send()
            .await?;
        self.handle_session_response(resp).await
    }

    /// Combined challenge + verify for TOTP factors (convenience).
    ///
    /// Mirrors `supabase.auth.mfa.challengeAndVerify()`.
    pub async fn mfa_challenge_and_verify(
        &self,
        access_token: &str,
        factor_id: &str,
        code: &str,
    ) -> Result<Session, AuthError> {
        let challenge = self.mfa_challenge(access_token, factor_id).await?;
        self.mfa_verify(
            access_token,
            factor_id,
            MfaVerifyParams::new(&challenge.id, code),
        )
        .await
    }

    /// Unenroll (delete) an MFA factor.
    ///
    /// Mirrors `supabase.auth.mfa.unenroll()`.
    pub async fn mfa_unenroll(
        &self,
        access_token: &str,
        factor_id: &str,
    ) -> Result<MfaUnenrollResponse, AuthError> {
        let url = self.url(&format!("/factors/{}", factor_id));
        let resp = self
            .http
            .delete(url)
            .bearer_auth(access_token)
            .send()
            .await?;
        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(self.parse_error(status, resp).await);
        }
        let body: MfaUnenrollResponse = resp.json().await?;
        Ok(body)
    }

    /// List the user's enrolled MFA factors, categorized by type.
    ///
    /// Fetches the user object and categorizes its factors.
    ///
    /// Mirrors `supabase.auth.mfa.listFactors()`.
    pub async fn mfa_list_factors(
        &self,
        access_token: &str,
    ) -> Result<MfaListFactorsResponse, AuthError> {
        let user = self.get_user(access_token).await?;
        let all = user.factors.unwrap_or_default();
        let totp = all
            .iter()
            .filter(|f| f.factor_type == "totp")
            .cloned()
            .collect();
        let phone = all
            .iter()
            .filter(|f| f.factor_type == "phone")
            .cloned()
            .collect();
        Ok(MfaListFactorsResponse { totp, phone, all })
    }

    /// Get the user's authenticator assurance level.
    ///
    /// Fetches the user object and inspects factors to determine AAL.
    ///
    /// Mirrors `supabase.auth.mfa.getAuthenticatorAssuranceLevel()`.
    pub async fn mfa_get_authenticator_assurance_level(
        &self,
        access_token: &str,
    ) -> Result<AuthenticatorAssuranceLevelInfo, AuthError> {
        let user = self.get_user(access_token).await?;
        let factors = user.factors.unwrap_or_default();

        // Parse AMR claims from the access token (JWT payload)
        let amr = parse_amr_from_jwt(access_token);

        // current_level: aal2 if AMR contains an MFA method, else aal1
        let has_mfa_amr = amr.iter().any(|e| e.method == "totp" || e.method == "phone");
        let current_level = if !amr.is_empty() {
            if has_mfa_amr {
                Some(AuthenticatorAssuranceLevel::Aal2)
            } else {
                Some(AuthenticatorAssuranceLevel::Aal1)
            }
        } else {
            Some(AuthenticatorAssuranceLevel::Aal1)
        };

        // next_level: aal2 if any verified factor exists, else aal1
        let has_verified_factor = factors.iter().any(|f| f.status == "verified");
        let next_level = if has_verified_factor {
            Some(AuthenticatorAssuranceLevel::Aal2)
        } else {
            Some(AuthenticatorAssuranceLevel::Aal1)
        };

        Ok(AuthenticatorAssuranceLevelInfo {
            current_level,
            next_level,
            current_authentication_methods: amr,
        })
    }

    // ─── SSO ───────────────────────────────────────────────────

    /// Sign in with enterprise SAML SSO.
    ///
    /// Mirrors `supabase.auth.signInWithSSO()`.
    pub async fn sign_in_with_sso(
        &self,
        params: SsoSignInParams,
    ) -> Result<SsoSignInResponse, AuthError> {
        let url = self.url("/sso");
        let resp = self.http.post(url).json(&params).send().await?;
        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(self.parse_error(status, resp).await);
        }
        let body: SsoSignInResponse = resp.json().await?;
        Ok(body)
    }

    // ─── ID Token ──────────────────────────────────────────────

    /// Sign in with an external OIDC ID token (e.g., from Google/Apple mobile SDK).
    ///
    /// Mirrors `supabase.auth.signInWithIdToken()`.
    pub async fn sign_in_with_id_token(
        &self,
        params: SignInWithIdTokenParams,
    ) -> Result<Session, AuthError> {
        let url = self.url("/token?grant_type=id_token");
        let resp = self.http.post(url).json(&params).send().await?;
        self.handle_session_response(resp).await
    }

    // ─── Identity Linking ──────────────────────────────────────

    /// Link an OAuth provider identity to the current user.
    ///
    /// Returns a URL to redirect the user to for OAuth authorization.
    ///
    /// Mirrors `supabase.auth.linkIdentity()`.
    pub async fn link_identity(
        &self,
        access_token: &str,
        provider: OAuthProvider,
    ) -> Result<LinkIdentityResponse, AuthError> {
        let mut url = self.url("/user/identities/authorize");
        url.query_pairs_mut()
            .append_pair("provider", &provider.to_string())
            .append_pair("skip_http_redirect", "true");
        let resp = self
            .http
            .get(url)
            .bearer_auth(access_token)
            .send()
            .await?;
        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(self.parse_error(status, resp).await);
        }
        // The response contains a JSON object with a `url` field
        let body: JsonValue = resp.json().await?;
        let redirect_url = body
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        Ok(LinkIdentityResponse { url: redirect_url })
    }

    /// Unlink an identity from the current user.
    ///
    /// Mirrors `supabase.auth.unlinkIdentity()`.
    pub async fn unlink_identity(
        &self,
        access_token: &str,
        identity_id: &str,
    ) -> Result<(), AuthError> {
        let url = self.url(&format!("/user/identities/{}", identity_id));
        let resp = self
            .http
            .delete(url)
            .bearer_auth(access_token)
            .send()
            .await?;
        self.handle_empty_response(resp).await
    }

    // ─── Resend & Reauthenticate ───────────────────────────────

    /// Resend an OTP or confirmation email/SMS.
    ///
    /// Mirrors `supabase.auth.resend()`.
    pub async fn resend(&self, params: ResendParams) -> Result<(), AuthError> {
        let url = self.url("/resend");
        let resp = self.http.post(url).json(&params).send().await?;
        self.handle_empty_response(resp).await
    }

    /// Send a reauthentication nonce to the user's verified email/phone.
    ///
    /// The nonce is used via the `nonce` field in `update_user()`.
    ///
    /// Mirrors `supabase.auth.reauthenticate()`.
    pub async fn reauthenticate(&self, access_token: &str) -> Result<(), AuthError> {
        let url = self.url("/reauthenticate");
        let resp = self
            .http
            .get(url)
            .bearer_auth(access_token)
            .send()
            .await?;
        self.handle_empty_response(resp).await
    }

    // ─── OAuth Server ─────────────────────────────────────────

    /// Get authorization details for an OAuth authorization request.
    ///
    /// Returns either full details (user must consent) or a redirect (already consented).
    ///
    /// Mirrors `supabase.auth.oauth.getAuthorizationDetails()`.
    pub async fn oauth_get_authorization_details(
        &self,
        access_token: &str,
        authorization_id: &str,
    ) -> Result<OAuthAuthorizationDetailsResponse, AuthError> {
        let url = self.url(&format!("/oauth/authorizations/{}", authorization_id));
        let resp = self
            .http
            .get(url)
            .bearer_auth(access_token)
            .send()
            .await?;
        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(self.parse_error(status, resp).await);
        }
        let body: OAuthAuthorizationDetailsResponse = resp.json().await?;
        Ok(body)
    }

    /// Approve an OAuth authorization request.
    ///
    /// Mirrors `supabase.auth.oauth.approveAuthorization()`.
    pub async fn oauth_approve_authorization(
        &self,
        access_token: &str,
        authorization_id: &str,
    ) -> Result<OAuthRedirect, AuthError> {
        self.oauth_consent_action(access_token, authorization_id, "approve")
            .await
    }

    /// Deny an OAuth authorization request.
    ///
    /// Mirrors `supabase.auth.oauth.denyAuthorization()`.
    pub async fn oauth_deny_authorization(
        &self,
        access_token: &str,
        authorization_id: &str,
    ) -> Result<OAuthRedirect, AuthError> {
        self.oauth_consent_action(access_token, authorization_id, "deny")
            .await
    }

    /// List all OAuth grants (permissions) for the current user.
    ///
    /// Mirrors `supabase.auth.oauth.listGrants()`.
    pub async fn oauth_list_grants(
        &self,
        access_token: &str,
    ) -> Result<Vec<OAuthGrant>, AuthError> {
        let url = self.url("/user/oauth/grants");
        let resp = self
            .http
            .get(url)
            .bearer_auth(access_token)
            .send()
            .await?;
        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(self.parse_error(status, resp).await);
        }
        let grants: Vec<OAuthGrant> = resp.json().await?;
        Ok(grants)
    }

    /// Revoke an OAuth grant for a specific client.
    ///
    /// Mirrors `supabase.auth.oauth.revokeGrant()`.
    pub async fn oauth_revoke_grant(
        &self,
        access_token: &str,
        client_id: &str,
    ) -> Result<(), AuthError> {
        let mut url = self.url("/user/oauth/grants");
        url.query_pairs_mut()
            .append_pair("client_id", client_id);
        let resp = self
            .http
            .delete(url)
            .bearer_auth(access_token)
            .send()
            .await?;
        self.handle_empty_response(resp).await
    }

    async fn oauth_consent_action(
        &self,
        access_token: &str,
        authorization_id: &str,
        action: &str,
    ) -> Result<OAuthRedirect, AuthError> {
        let url = self.url(&format!(
            "/oauth/authorizations/{}/consent",
            authorization_id
        ));
        let body = serde_json::json!({ "action": action });
        let resp = self
            .http
            .post(url)
            .bearer_auth(access_token)
            .json(&body)
            .send()
            .await?;
        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(self.parse_error(status, resp).await);
        }
        let redirect: OAuthRedirect = resp.json().await?;
        Ok(redirect)
    }

    // ─── OAuth Client-Side Flow ─────────────────────────────────

    /// Generate a PKCE (Proof Key for Code Exchange) verifier/challenge pair.
    ///
    /// Uses S256 method: the challenge is `BASE64URL(SHA256(verifier))`.
    /// The verifier is 43 URL-safe random characters.
    pub fn generate_pkce_pair() -> PkcePair {
        use rand::Rng;

        // Generate 32 random bytes → 43 base64url chars (no padding)
        let mut rng = rand::rng();
        let random_bytes: [u8; 32] = rng.random();
        let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes);

        // S256: challenge = BASE64URL(SHA256(verifier))
        let hash = Sha256::digest(verifier.as_bytes());
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);

        PkcePair {
            verifier: PkceCodeVerifier(verifier),
            challenge: PkceCodeChallenge(challenge),
        }
    }

    /// Build an OAuth authorization URL for the authorization code flow.
    ///
    /// Returns a URL to redirect the user to. This does not make a network request.
    pub fn build_oauth_authorize_url(&self, params: &OAuthAuthorizeUrlParams) -> String {
        let mut url = self.url("/oauth/authorize");
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("client_id", &params.client_id);
            pairs.append_pair("redirect_uri", &params.redirect_uri);
            pairs.append_pair("response_type", "code");

            if let Some(scope) = &params.scope {
                pairs.append_pair("scope", scope);
            }
            if let Some(state) = &params.state {
                pairs.append_pair("state", state);
            }
            if let Some(challenge) = &params.code_challenge {
                pairs.append_pair("code_challenge", challenge);
                if let Some(method) = &params.code_challenge_method {
                    pairs.append_pair("code_challenge_method", method);
                }
            }
        }
        url.to_string()
    }

    /// Exchange an authorization code for tokens.
    ///
    /// POST to `/oauth/token` with `grant_type=authorization_code`.
    /// Uses `application/x-www-form-urlencoded` as per OAuth 2.1 spec.
    pub async fn oauth_token_exchange(
        &self,
        params: OAuthTokenExchangeParams,
    ) -> Result<OAuthTokenResponse, AuthError> {
        let url = self.url("/oauth/token");
        let mut form: Vec<(&str, String)> = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", params.code.clone()),
            ("redirect_uri", params.redirect_uri.clone()),
            ("client_id", params.client_id.clone()),
        ];
        if let Some(secret) = &params.client_secret {
            form.push(("client_secret", secret.clone()));
        }
        if let Some(verifier) = &params.code_verifier {
            form.push(("code_verifier", verifier.clone()));
        }

        let resp = self.http.post(url).form(&form).send().await?;
        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(self.parse_error(status, resp).await);
        }
        let token_resp: OAuthTokenResponse = resp.json().await?;
        Ok(token_resp)
    }

    /// Refresh an OAuth token.
    ///
    /// POST to `/oauth/token` with `grant_type=refresh_token`.
    pub async fn oauth_token_refresh(
        &self,
        client_id: &str,
        refresh_token: &str,
        client_secret: Option<&str>,
    ) -> Result<OAuthTokenResponse, AuthError> {
        let url = self.url("/oauth/token");
        let mut form: Vec<(&str, String)> = vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", refresh_token.to_string()),
            ("client_id", client_id.to_string()),
        ];
        if let Some(secret) = client_secret {
            form.push(("client_secret", secret.to_string()));
        }

        let resp = self.http.post(url).form(&form).send().await?;
        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(self.parse_error(status, resp).await);
        }
        let token_resp: OAuthTokenResponse = resp.json().await?;
        Ok(token_resp)
    }

    /// Revoke an OAuth token.
    ///
    /// POST to `/oauth/revoke`.
    pub async fn oauth_revoke_token(
        &self,
        token: &str,
        token_type_hint: Option<&str>,
    ) -> Result<(), AuthError> {
        let url = self.url("/oauth/revoke");
        let mut form: Vec<(&str, String)> = vec![("token", token.to_string())];
        if let Some(hint) = token_type_hint {
            form.push(("token_type_hint", hint.to_string()));
        }

        let resp = self.http.post(url).form(&form).send().await?;
        self.handle_empty_response(resp).await
    }

    /// Fetch the OpenID Connect discovery document.
    ///
    /// GET `/.well-known/openid-configuration`.
    pub async fn oauth_get_openid_configuration(
        &self,
    ) -> Result<OpenIdConfiguration, AuthError> {
        let url = self.url("/.well-known/openid-configuration");
        let resp = self.http.get(url).send().await?;
        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(self.parse_error(status, resp).await);
        }
        let config: OpenIdConfiguration = resp.json().await?;
        Ok(config)
    }

    /// Fetch the JSON Web Key Set (JWKS) for token verification.
    ///
    /// GET `/.well-known/jwks.json`.
    pub async fn oauth_get_jwks(&self) -> Result<JwksResponse, AuthError> {
        let url = self.url("/.well-known/jwks.json");
        let resp = self.http.get(url).send().await?;
        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(self.parse_error(status, resp).await);
        }
        let jwks: JwksResponse = resp.json().await?;
        Ok(jwks)
    }

    /// Fetch user info from the OAuth userinfo endpoint.
    ///
    /// GET `/oauth/userinfo` with Bearer token.
    pub async fn oauth_get_userinfo(
        &self,
        access_token: &str,
    ) -> Result<JsonValue, AuthError> {
        let url = self.url("/oauth/userinfo");
        let resp = self
            .http
            .get(url)
            .bearer_auth(access_token)
            .send()
            .await?;
        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(self.parse_error(status, resp).await);
        }
        let userinfo: JsonValue = resp.json().await?;
        Ok(userinfo)
    }

    // ─── Internal Helpers ──────────────────────────────────────

    pub(crate) fn url(&self, path: &str) -> Url {
        let mut url = self.base_url.clone();
        let current = url.path().to_string();
        // path may contain query string (e.g. "/token?grant_type=password")
        if let Some(query_start) = path.find('?') {
            url.set_path(&format!("{}{}", current, &path[..query_start]));
            url.set_query(Some(&path[query_start + 1..]));
        } else {
            url.set_path(&format!("{}{}", current, path));
        }
        url
    }

    pub(crate) fn http(&self) -> &reqwest::Client {
        &self.http
    }

    pub(crate) fn api_key(&self) -> &str {
        &self.api_key
    }

    async fn handle_auth_response(
        &self,
        resp: reqwest::Response,
    ) -> Result<AuthResponse, AuthError> {
        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(self.parse_error(status, resp).await);
        }

        let body: AuthResponse = resp.json().await?;
        Ok(body)
    }

    async fn handle_session_response(
        &self,
        resp: reqwest::Response,
    ) -> Result<Session, AuthError> {
        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(self.parse_error(status, resp).await);
        }

        let session: Session = resp.json().await?;
        Ok(session)
    }

    pub(crate) async fn handle_user_response(
        &self,
        resp: reqwest::Response,
    ) -> Result<User, AuthError> {
        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(self.parse_error(status, resp).await);
        }

        let user: User = resp.json().await?;
        Ok(user)
    }

    pub(crate) async fn handle_empty_response(
        &self,
        resp: reqwest::Response,
    ) -> Result<(), AuthError> {
        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(self.parse_error(status, resp).await);
        }
        Ok(())
    }

    async fn parse_error(&self, status: u16, resp: reqwest::Response) -> AuthError {
        match resp.json::<GoTrueErrorResponse>().await {
            Ok(err_resp) => {
                let error_code = err_resp
                    .error_code
                    .as_deref()
                    .map(|s| s.into());
                AuthError::Api {
                    status,
                    message: err_resp.error_message(),
                    error_code,
                }
            }
            Err(_) => AuthError::Api {
                status,
                message: format!("HTTP {}", status),
                error_code: None,
            },
        }
    }
}

/// Parse AMR (Authentication Methods Reference) claims from a JWT access token.
///
/// The JWT payload contains an `amr` array of `{ method, timestamp }` objects.
/// This is a best-effort parse — returns empty vec on any failure.
fn parse_amr_from_jwt(token: &str) -> Vec<AmrEntry> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Vec::new();
    }

    let payload_b64 = parts[1];
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok();
    let decoded = match decoded {
        Some(d) => d,
        None => return Vec::new(),
    };

    let payload: JsonValue = match serde_json::from_slice(&decoded) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    match payload.get("amr") {
        Some(amr_val) => serde_json::from_value::<Vec<AmrEntry>>(amr_val.clone()).unwrap_or_default(),
        None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oauth_url_google() {
        let client = AuthClient::new("https://example.supabase.co", "test-key").unwrap();
        let url = client
            .get_oauth_sign_in_url(OAuthProvider::Google, None, None)
            .unwrap();
        assert!(url.contains("/auth/v1/authorize"));
        assert!(url.contains("provider=google"));
    }

    #[test]
    fn test_oauth_url_with_redirect_and_scopes() {
        let client = AuthClient::new("https://example.supabase.co", "test-key").unwrap();
        let url = client
            .get_oauth_sign_in_url(
                OAuthProvider::GitHub,
                Some("https://myapp.com/callback"),
                Some("read:user"),
            )
            .unwrap();
        assert!(url.contains("provider=github"));
        assert!(url.contains("redirect_to="));
        assert!(url.contains("scopes="));
    }

    #[test]
    fn test_oauth_url_custom_provider() {
        let client = AuthClient::new("https://example.supabase.co", "test-key").unwrap();
        let url = client
            .get_oauth_sign_in_url(OAuthProvider::Custom("myidp".into()), None, None)
            .unwrap();
        assert!(url.contains("provider=myidp"));
    }

    #[test]
    fn test_url_building() {
        let client = AuthClient::new("https://example.supabase.co", "test-key").unwrap();
        let url = client.url("/signup");
        assert_eq!(url.path(), "/auth/v1/signup");
        assert!(url.query().is_none());

        let url = client.url("/token?grant_type=password");
        assert_eq!(url.path(), "/auth/v1/token");
        assert_eq!(url.query(), Some("grant_type=password"));
    }

    #[test]
    fn test_url_building_trailing_slash() {
        let client = AuthClient::new("https://example.supabase.co/", "test-key").unwrap();
        let url = client.url("/signup");
        assert_eq!(url.path(), "/auth/v1/signup");
    }

    #[test]
    fn test_base_url() {
        let client = AuthClient::new("https://example.supabase.co", "test-key").unwrap();
        assert_eq!(client.base_url().path(), "/auth/v1");
    }

    // ─── PKCE Tests ──────────────────────────────────────────

    #[test]
    fn test_generate_pkce_pair() {
        let pair = AuthClient::generate_pkce_pair();
        // Verifier should be 43 chars (32 bytes base64url no padding)
        assert_eq!(pair.verifier.as_str().len(), 43);
        // Challenge should be 43 chars (32 bytes SHA256 → base64url no padding)
        assert_eq!(pair.challenge.as_str().len(), 43);
        // They should be different
        assert_ne!(pair.verifier.as_str(), pair.challenge.as_str());
    }

    #[test]
    fn test_pkce_pair_is_deterministic_for_same_verifier() {
        // Verify the S256 challenge is correctly computed
        use sha2::{Digest, Sha256};
        let pair = AuthClient::generate_pkce_pair();
        let hash = Sha256::digest(pair.verifier.as_str().as_bytes());
        let expected_challenge =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);
        assert_eq!(pair.challenge.as_str(), expected_challenge);
    }

    #[test]
    fn test_pkce_pairs_are_unique() {
        let pair1 = AuthClient::generate_pkce_pair();
        let pair2 = AuthClient::generate_pkce_pair();
        assert_ne!(pair1.verifier.as_str(), pair2.verifier.as_str());
        assert_ne!(pair1.challenge.as_str(), pair2.challenge.as_str());
    }

    // ─── OAuth Authorize URL Tests ───────────────────────────

    #[test]
    fn test_build_oauth_authorize_url_basic() {
        let client = AuthClient::new("https://example.supabase.co", "test-key").unwrap();
        let params = OAuthAuthorizeUrlParams::new("client-abc", "https://app.com/callback");
        let url = client.build_oauth_authorize_url(&params);
        assert!(url.contains("/auth/v1/oauth/authorize"));
        assert!(url.contains("client_id=client-abc"));
        assert!(url.contains("redirect_uri="));
        assert!(url.contains("response_type=code"));
    }

    #[test]
    fn test_build_oauth_authorize_url_with_scope_and_state() {
        let client = AuthClient::new("https://example.supabase.co", "test-key").unwrap();
        let params = OAuthAuthorizeUrlParams::new("client-abc", "https://app.com/callback")
            .scope("openid profile")
            .state("csrf-token");
        let url = client.build_oauth_authorize_url(&params);
        assert!(url.contains("scope=openid+profile"));
        assert!(url.contains("state=csrf-token"));
    }

    #[test]
    fn test_build_oauth_authorize_url_with_pkce() {
        let client = AuthClient::new("https://example.supabase.co", "test-key").unwrap();
        let pkce = AuthClient::generate_pkce_pair();
        let params = OAuthAuthorizeUrlParams::new("client-abc", "https://app.com/callback")
            .pkce(&pkce.challenge);
        let url = client.build_oauth_authorize_url(&params);
        assert!(url.contains(&format!("code_challenge={}", pkce.challenge.as_str())));
        assert!(url.contains("code_challenge_method=S256"));
    }
}
