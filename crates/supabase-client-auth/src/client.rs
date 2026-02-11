use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use serde_json::{json, Value as JsonValue};
use url::Url;

use crate::admin::AdminClient;
use crate::error::{AuthError, GoTrueErrorResponse};
use crate::params::{UpdateUserParams, VerifyOtpParams};
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
}
