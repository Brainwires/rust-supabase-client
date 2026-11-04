use std::sync::{Arc, Weak};

use base64::Engine;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use serde_json::{json, Value as JsonValue};
use sha2::{Digest, Sha256};
use supabase_client_core::http::{read_error_body, sensitive_header};
use supabase_client_core::{platform, AccessToken};
use tokio::sync::{broadcast, Mutex, RwLock};
use url::Url;

use crate::admin::AdminClient;
use crate::error::{AuthError, AuthErrorCode, GoTrueErrorResponse};
use crate::params::{
    MfaChallengeParams, MfaEnrollParams, MfaVerifyParams, OAuthAuthorizeUrlParams,
    OAuthTokenExchangeParams, ResendParams, SignInWithIdTokenParams, SsoSignInParams,
    UpdateUserParams, VerifyOtpParams,
};
use crate::types::*;

/// Broadcast channel capacity for auth state change events.
const EVENT_CHANNEL_CAPACITY: usize = 64;

/// Auto-refresh task state. Guarded by a std mutex that is never held across
/// an `.await`, so starting and stopping never races or silently drops a handle.
#[derive(Default)]
struct AutoRefreshState {
    /// The configuration the user asked for; `None` once stopped explicitly.
    config: Option<AutoRefreshConfig>,
    handle: Option<platform::SpawnHandle>,
}

struct AuthClientInner {
    http: reqwest::Client,
    base_url: Url,
    api_key: String,
    // Session state management
    session: RwLock<Option<Session>>,
    event_tx: broadcast::Sender<AuthStateChange>,
    auto_refresh: std::sync::Mutex<AutoRefreshState>,
    /// Serializes refreshes of the stored session (single-flight).
    refresh_lock: Mutex<()>,
    /// Shared slot that mirrors the stored session's access token, so other
    /// clients built from the same `SupabaseClient` use the user's JWT.
    token_sink: Option<AccessToken>,
}

impl AuthClientInner {
    fn auto_refresh_state(&self) -> std::sync::MutexGuard<'_, AutoRefreshState> {
        self.auto_refresh
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Abort the background task (if any), keeping the configuration.
    fn abort_auto_refresh_task(&self) {
        if let Some(mut handle) = self.auto_refresh_state().handle.take() {
            abort_handle(&mut handle);
        }
    }

    fn sync_token_sink(&self, session: Option<&Session>) {
        if let Some(sink) = &self.token_sink {
            sink.replace(session.map(|s| s.access_token.clone()));
        }
    }
}

impl Drop for AuthClientInner {
    fn drop(&mut self) {
        // The refresh task only holds a Weak reference, so it cannot keep the
        // client alive; abort it so it does not linger until its next tick.
        self.abort_auto_refresh_task();
    }
}

#[allow(unused_mut)]
fn abort_handle(handle: &mut platform::SpawnHandle) {
    handle.abort();
}

impl std::fmt::Debug for AuthClientInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthClientInner")
            .field("base_url", &self.base_url)
            .field("api_key", &"***")
            .finish()
    }
}

/// HTTP client for Supabase GoTrue auth API.
///
/// Communicates with GoTrue REST endpoints at `/auth/v1/...`.
/// Provides built-in session state management, event broadcasting,
/// and optional automatic token refresh.
///
/// # Example
/// ```ignore
/// use supabase_client_auth::AuthClient;
///
/// let auth = AuthClient::new("https://your-project.supabase.co", "your-anon-key")?;
/// let session = auth.sign_in_with_password_email("user@example.com", "password").await?;
///
/// // Session is automatically stored — retrieve it later:
/// let stored = auth.get_session().await;
///
/// // Subscribe to auth state changes:
/// let mut sub = auth.on_auth_state_change();
/// ```
#[derive(Debug, Clone)]
pub struct AuthClient {
    inner: Arc<AuthClientInner>,
}

impl AuthClient {
    /// Create a new auth client.
    ///
    /// `supabase_url` is the project URL (e.g., `https://your-project.supabase.co`).
    /// `api_key` is the Supabase anon key, sent as the `apikey` header.
    pub fn new(supabase_url: &str, api_key: &str) -> Result<Self, AuthError> {
        Self::build(supabase_url, api_key, None)
    }

    /// Create an auth client that mirrors its session's access token into
    /// `token` (set on sign-in and refresh, cleared on sign-out).
    ///
    /// `SupabaseClient::auth()` uses this with the client's shared token slot,
    /// so the query, storage, functions, GraphQL and realtime clients created
    /// from the same `SupabaseClient` send the signed-in user's JWT.
    pub fn with_token_sink(
        supabase_url: &str,
        api_key: &str,
        token: AccessToken,
    ) -> Result<Self, AuthError> {
        Self::build(supabase_url, api_key, Some(token))
    }

    fn build(
        supabase_url: &str,
        api_key: &str,
        token_sink: Option<AccessToken>,
    ) -> Result<Self, AuthError> {
        let base = supabase_url.trim_end_matches('/');
        let base_url = Url::parse(&format!("{}/auth/v1", base))?;
        if base_url.cannot_be_a_base() {
            return Err(AuthError::InvalidConfig(format!(
                "supabase_url cannot be used as a base URL: {}",
                supabase_url
            )));
        }
        supabase_client_core::keys::warn_if_privileged_on_wasm(api_key, "auth");

        let mut default_headers = HeaderMap::new();
        default_headers.insert(
            "apikey",
            sensitive_header(api_key)
                .map_err(|e| AuthError::InvalidConfig(format!("Invalid API key header: {}", e)))?,
        );
        default_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let builder = reqwest::Client::builder().default_headers(default_headers);
        // reqwest's wasm backend has no connect timeout
        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder.connect_timeout(std::time::Duration::from_secs(10));
        let http = builder.build().map_err(AuthError::Http)?;

        let (event_tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);

        Ok(Self {
            inner: Arc::new(AuthClientInner {
                http,
                base_url,
                api_key: api_key.to_string(),
                session: RwLock::new(None),
                event_tx,
                auto_refresh: std::sync::Mutex::new(AutoRefreshState::default()),
                refresh_lock: Mutex::new(()),
                token_sink,
            }),
        })
    }

    /// Get the base URL for the auth API.
    pub fn base_url(&self) -> &Url {
        &self.inner.base_url
    }

    // ─── Session State Management ─────────────────────────────

    /// Get the currently stored session (no network call).
    ///
    /// Returns `None` if no session has been stored (e.g., user hasn't signed in yet).
    pub async fn get_session(&self) -> Option<Session> {
        self.inner.session.read().await.clone()
    }

    /// Set/replace the stored session and emit `SignedIn`.
    ///
    /// Use this to restore a session from external storage (e.g., persisted tokens).
    /// If `expires_at` is missing it is filled in from `expires_in`.
    pub async fn set_session(&self, session: Session) {
        self.store_session(&session, AuthChangeEvent::SignedIn).await;
    }

    /// Clear the stored session and emit `SignedOut`.
    ///
    /// This is a local operation — it does NOT call GoTrue `/logout`.
    /// Use [`sign_out_current()`](AuthClient::sign_out_current) to also invalidate server-side.
    pub async fn clear_session(&self) {
        self.emit_signed_out().await;
    }

    // ─── Event Subscription ───────────────────────────────────

    /// Subscribe to auth state change events.
    ///
    /// Returns an [`AuthSubscription`] that receives events via [`next()`](AuthSubscription::next).
    /// Multiple subscriptions can be active simultaneously.
    pub fn on_auth_state_change(&self) -> AuthSubscription {
        AuthSubscription {
            rx: self.inner.event_tx.subscribe(),
        }
    }

    // ─── Auto-Refresh ─────────────────────────────────────────

    /// Start automatic token refresh with default configuration.
    ///
    /// Spawns a background task that checks the stored session periodically
    /// and refreshes it before expiry.
    pub fn start_auto_refresh(&self) {
        self.start_auto_refresh_with(AutoRefreshConfig::default());
    }

    /// Start automatic token refresh with custom configuration.
    ///
    /// The task holds only a weak reference to the client and is aborted when
    /// the last clone of the client is dropped. Signing out stops the task;
    /// the next sign-in (or `set_session`) starts it again with the same
    /// configuration until [`stop_auto_refresh`](Self::stop_auto_refresh) is called.
    ///
    /// On native targets this must be called from within a Tokio runtime.
    pub fn start_auto_refresh_with(&self, config: AutoRefreshConfig) {
        let mut state = self.inner.auto_refresh_state();
        if let Some(mut old) = state.handle.take() {
            abort_handle(&mut old);
        }
        state.config = Some(config.clone());
        state.handle = Some(spawn_auto_refresh(&self.inner, config));
    }

    /// Stop automatic token refresh.
    pub fn stop_auto_refresh(&self) {
        let mut state = self.inner.auto_refresh_state();
        state.config = None;
        if let Some(mut handle) = state.handle.take() {
            abort_handle(&mut handle);
        }
    }

    /// Whether the auto-refresh task is currently running.
    pub fn is_auto_refresh_running(&self) -> bool {
        self.inner.auto_refresh_state().handle.is_some()
    }

    /// Restart the auto-refresh task after a sign-in if the user enabled it
    /// and it was stopped by a sign-out.
    fn resume_auto_refresh(&self) {
        let mut state = self.inner.auto_refresh_state();
        if state.handle.is_none() {
            if let Some(config) = state.config.clone() {
                state.handle = Some(spawn_auto_refresh(&self.inner, config));
            }
        }
    }

    // ─── Session-Aware Convenience Methods ────────────────────

    /// Get the user from the stored session (calls GoTrue `/user`).
    ///
    /// Returns `AuthError::NoSession` if no session is stored.
    pub async fn get_session_user(&self) -> Result<User, AuthError> {
        let session = self.inner.session.read().await.clone();
        match session {
            Some(s) => self.get_user(&s.access_token).await,
            None => Err(AuthError::NoSession),
        }
    }

    /// Refresh the stored session using its refresh_token.
    ///
    /// Shares a single-flight lock with the auto-refresh task: concurrent
    /// callers wait for one refresh and get its result instead of spending
    /// the same refresh token twice. If the session is signed out or replaced
    /// while the request is in flight, the refreshed session is discarded.
    ///
    /// Returns `AuthError::NoSession` if no session is stored.
    pub async fn refresh_current_session(&self) -> Result<Session, AuthError> {
        let used = match self.inner.session.read().await.as_ref() {
            Some(s) => s.refresh_token.clone(),
            None => return Err(AuthError::NoSession),
        };
        refresh_stored_session(&self.inner, &used).await
    }

    /// Sign out using the stored session's access_token, then clear session.
    ///
    /// Returns `AuthError::NoSession` if no session is stored.
    pub async fn sign_out_current(&self) -> Result<(), AuthError> {
        self.sign_out_current_with_scope(SignOutScope::Global).await
    }

    /// Sign out with scope using the stored session's access_token.
    ///
    /// Returns `AuthError::NoSession` if no session is stored.
    pub async fn sign_out_current_with_scope(&self, scope: SignOutScope) -> Result<(), AuthError> {
        let session = self.inner.session.read().await.clone();
        match session {
            Some(s) => self.sign_out_with_scope(&s.access_token, scope).await,
            None => Err(AuthError::NoSession),
        }
    }

    // ─── Sign Up ───────────────────────────────────────────────

    /// Sign up a new user with email and password.
    ///
    /// Mirrors `supabase.auth.signUp({ email, password })`.
    /// If the response includes a session, it is stored and `SignedIn` is emitted.
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
    /// If the response includes a session, it is stored and `SignedIn` is emitted.
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

        let url = self.fixed_url(&["signup"]);
        let resp = self.inner.http.post(url).json(&body).send().await?;
        let auth_resp = self.handle_auth_response(resp).await?;
        if let Some(session) = &auth_resp.session {
            self.store_session(session, AuthChangeEvent::SignedIn).await;
        }
        Ok(auth_resp)
    }

    /// Sign up a new user with phone and password.
    ///
    /// Mirrors `supabase.auth.signUp({ phone, password })`.
    /// If the response includes a session, it is stored and `SignedIn` is emitted.
    pub async fn sign_up_with_phone(
        &self,
        phone: &str,
        password: &str,
    ) -> Result<AuthResponse, AuthError> {
        let body = json!({
            "phone": phone,
            "password": password,
        });

        let url = self.fixed_url(&["signup"]);
        let resp = self.inner.http.post(url).json(&body).send().await?;
        let auth_resp = self.handle_auth_response(resp).await?;
        if let Some(session) = &auth_resp.session {
            self.store_session(session, AuthChangeEvent::SignedIn).await;
        }
        Ok(auth_resp)
    }

    // ─── Sign In ───────────────────────────────────────────────

    /// Sign in with email and password.
    ///
    /// Mirrors `supabase.auth.signInWithPassword({ email, password })`.
    /// Stores the session and emits `SignedIn`.
    pub async fn sign_in_with_password_email(
        &self,
        email: &str,
        password: &str,
    ) -> Result<Session, AuthError> {
        let body = json!({
            "email": email,
            "password": password,
        });

        let url = self.fixed_url_with_query(&["token"], &[("grant_type", "password")]);
        let resp = self.inner.http.post(url).json(&body).send().await?;
        let session = self.handle_session_response(resp).await?;
        self.store_session(&session, AuthChangeEvent::SignedIn).await;
        Ok(session)
    }

    /// Sign in with phone and password.
    ///
    /// Mirrors `supabase.auth.signInWithPassword({ phone, password })`.
    /// Stores the session and emits `SignedIn`.
    pub async fn sign_in_with_password_phone(
        &self,
        phone: &str,
        password: &str,
    ) -> Result<Session, AuthError> {
        let body = json!({
            "phone": phone,
            "password": password,
        });

        let url = self.fixed_url_with_query(&["token"], &[("grant_type", "password")]);
        let resp = self.inner.http.post(url).json(&body).send().await?;
        let session = self.handle_session_response(resp).await?;
        self.store_session(&session, AuthChangeEvent::SignedIn).await;
        Ok(session)
    }

    /// Send a magic link / OTP to an email address.
    ///
    /// Mirrors `supabase.auth.signInWithOtp({ email })`.
    pub async fn sign_in_with_otp_email(&self, email: &str) -> Result<(), AuthError> {
        let body = json!({
            "email": email,
        });

        let url = self.fixed_url(&["otp"]);
        let resp = self.inner.http.post(url).json(&body).send().await?;
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

        let url = self.fixed_url(&["otp"]);
        let resp = self.inner.http.post(url).json(&body).send().await?;
        self.handle_empty_response(resp).await
    }

    /// Verify an OTP token.
    ///
    /// Mirrors `supabase.auth.verifyOtp(params)`.
    /// Stores the session and emits `SignedIn`.
    pub async fn verify_otp(&self, params: VerifyOtpParams) -> Result<Session, AuthError> {
        let url = self.fixed_url(&["verify"]);
        let resp = self.inner.http.post(url).json(&params).send().await?;
        let session = self.handle_session_response(resp).await?;
        self.store_session(&session, AuthChangeEvent::SignedIn).await;
        Ok(session)
    }

    /// Sign in anonymously, creating a new anonymous user.
    ///
    /// Mirrors `supabase.auth.signInAnonymously()`.
    /// Stores the session and emits `SignedIn`.
    pub async fn sign_in_anonymous(&self) -> Result<Session, AuthError> {
        let url = self.fixed_url(&["signup"]);
        let body = json!({});
        let resp = self.inner.http.post(url).json(&body).send().await?;
        let session = self.handle_session_response(resp).await?;
        self.store_session(&session, AuthChangeEvent::SignedIn).await;
        Ok(session)
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
        let mut url = self.fixed_url(&["authorize"]);
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
    /// Stores the session and emits `SignedIn`.
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

        let url = self.fixed_url_with_query(&["token"], &[("grant_type", "pkce")]);
        let resp = self.inner.http.post(url).json(&body).send().await?;
        let session = self.handle_session_response(resp).await?;
        self.store_session(&session, AuthChangeEvent::SignedIn).await;
        Ok(session)
    }

    // ─── Session Management ────────────────────────────────────

    /// Refresh a session using a refresh token.
    ///
    /// Mirrors `supabase.auth.refreshSession()`.
    /// Stores the new session and emits `TokenRefreshed`.
    ///
    /// When `refresh_token` belongs to the stored session this goes through
    /// the same single-flight path as
    /// [`refresh_current_session`](Self::refresh_current_session).
    pub async fn refresh_session(&self, refresh_token: &str) -> Result<Session, AuthError> {
        let is_stored = self
            .inner
            .session
            .read()
            .await
            .as_ref()
            .is_some_and(|s| s.refresh_token == refresh_token);
        if is_stored {
            return refresh_stored_session(&self.inner, refresh_token).await;
        }
        let session = refresh_request(&self.inner, refresh_token).await?;
        self.store_session(&session, AuthChangeEvent::TokenRefreshed)
            .await;
        Ok(session)
    }

    // ─── User Management ───────────────────────────────────────

    /// Get the user associated with an access token.
    ///
    /// Makes a network request to GoTrue to validate the token and fetch the user.
    ///
    /// Mirrors `supabase.auth.getUser(jwt?)`.
    pub async fn get_user(&self, access_token: &str) -> Result<User, AuthError> {
        let url = self.fixed_url(&["user"]);
        let resp = self
            .inner
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
    /// Emits `UserUpdated` and updates the user in the stored session (if any).
    pub async fn update_user(
        &self,
        access_token: &str,
        params: UpdateUserParams,
    ) -> Result<User, AuthError> {
        let url = self.fixed_url(&["user"]);
        let resp = self
            .inner
            .http
            .put(url)
            .bearer_auth(access_token)
            .json(&params)
            .send()
            .await?;
        let user = self.handle_user_response(resp).await?;

        // Update the user in the stored session and emit UserUpdated
        let mut guard = self.inner.session.write().await;
        let session_clone = if let Some(session) = guard.as_mut() {
            session.user = user.clone();
            Some(session.clone())
        } else {
            None
        };
        drop(guard);

        let _ = self.inner.event_tx.send(AuthStateChange {
            event: AuthChangeEvent::UserUpdated,
            session: session_clone,
        });

        Ok(user)
    }

    // ─── Sign Out ──────────────────────────────────────────────

    /// Sign out the user (global scope by default).
    ///
    /// Mirrors `supabase.auth.signOut()`.
    /// Clears the stored session and emits `SignedOut`.
    pub async fn sign_out(&self, access_token: &str) -> Result<(), AuthError> {
        self.sign_out_with_scope(access_token, SignOutScope::Global)
            .await
    }

    /// Sign out with a specific scope.
    ///
    /// Mirrors `supabase.auth.signOut({ scope })`.
    /// For `Global` and `Local`, clears the stored session and emits
    /// `SignedOut`; `Others` keeps the current session. A 401, 403 or 404
    /// from GoTrue (token already expired or revoked) is treated as success
    /// and still clears the local session.
    pub async fn sign_out_with_scope(
        &self,
        access_token: &str,
        scope: SignOutScope,
    ) -> Result<(), AuthError> {
        let scope_str = scope.to_string();
        let url = self.fixed_url_with_query(&["logout"], &[("scope", scope_str.as_str())]);
        let resp = self
            .inner
            .http
            .post(url)
            .bearer_auth(access_token)
            .send()
            .await?;
        match self.handle_empty_response(resp).await {
            Ok(()) => {}
            // Like supabase-js: a 401/403/404 means the token is already
            // expired, revoked or unknown, so the session is gone server-side
            // and the local copy must go too.
            Err(AuthError::Api {
                status: 401 | 403 | 404,
                ..
            }) => {}
            Err(e) => return Err(e),
        }
        // `others` signs out every *other* session; this one stays valid.
        if scope != SignOutScope::Others {
            self.emit_signed_out().await;
        }
        Ok(())
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
        let body = json!({ "email": email });
        // GoTrue reads the redirect from the query string, not the body.
        let mut url = self.fixed_url(&["recover"]);
        if let Some(redirect) = redirect_to {
            url.query_pairs_mut().append_pair("redirect_to", redirect);
        }
        let resp = self.inner.http.post(url).json(&body).send().await?;
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
        let url = self.fixed_url(&["factors"]);
        let resp = self
            .inner
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
        let url = self.url_for(&["factors", factor_id, "challenge"])?;
        let resp = self
            .inner
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
    /// Stores the session and emits `SignedIn`.
    pub async fn mfa_verify(
        &self,
        access_token: &str,
        factor_id: &str,
        params: MfaVerifyParams,
    ) -> Result<Session, AuthError> {
        let url = self.url_for(&["factors", factor_id, "verify"])?;
        let resp = self
            .inner
            .http
            .post(url)
            .bearer_auth(access_token)
            .json(&params)
            .send()
            .await?;
        let session = self.handle_session_response(resp).await?;
        self.store_session(&session, AuthChangeEvent::SignedIn).await;
        Ok(session)
    }

    /// Combined challenge + verify for TOTP factors (convenience).
    ///
    /// Mirrors `supabase.auth.mfa.challengeAndVerify()`.
    /// Stores the session and emits `SignedIn`.
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
        let url = self.url_for(&["factors", factor_id])?;
        let resp = self
            .inner
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
        let url = self.fixed_url(&["sso"]);
        let resp = self.inner.http.post(url).json(&params).send().await?;
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
    /// Stores the session and emits `SignedIn`.
    pub async fn sign_in_with_id_token(
        &self,
        params: SignInWithIdTokenParams,
    ) -> Result<Session, AuthError> {
        let url = self.fixed_url_with_query(&["token"], &[("grant_type", "id_token")]);
        let resp = self.inner.http.post(url).json(&params).send().await?;
        let session = self.handle_session_response(resp).await?;
        self.store_session(&session, AuthChangeEvent::SignedIn).await;
        Ok(session)
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
        let mut url = self.fixed_url(&["user", "identities", "authorize"]);
        url.query_pairs_mut()
            .append_pair("provider", &provider.to_string())
            .append_pair("skip_http_redirect", "true");
        let resp = self
            .inner
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
        let url = self.url_for(&["user", "identities", identity_id])?;
        let resp = self
            .inner
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
        let url = self.fixed_url(&["resend"]);
        let resp = self.inner.http.post(url).json(&params).send().await?;
        self.handle_empty_response(resp).await
    }

    /// Send a reauthentication nonce to the user's verified email/phone.
    ///
    /// The nonce is used via the `nonce` field in `update_user()`.
    ///
    /// Mirrors `supabase.auth.reauthenticate()`.
    pub async fn reauthenticate(&self, access_token: &str) -> Result<(), AuthError> {
        let url = self.fixed_url(&["reauthenticate"]);
        let resp = self
            .inner
            .http
            .get(url)
            .bearer_auth(access_token)
            .send()
            .await?;
        self.handle_empty_response(resp).await
    }

    // ─── User Identities ──────────────────────────────────────

    /// Get the identities linked to the current user.
    ///
    /// Convenience method that calls `get_user()` and returns the `identities` field.
    ///
    /// Mirrors `supabase.auth.getUserIdentities()`.
    pub async fn get_user_identities(
        &self,
        access_token: &str,
    ) -> Result<Vec<Identity>, AuthError> {
        let user = self.get_user(access_token).await?;
        Ok(user.identities.unwrap_or_default())
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
        let url = self.url_for(&["oauth", "authorizations", authorization_id])?;
        let resp = self
            .inner
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
        let url = self.fixed_url(&["user", "oauth", "grants"]);
        let resp = self
            .inner
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
        let mut url = self.fixed_url(&["user", "oauth", "grants"]);
        url.query_pairs_mut()
            .append_pair("client_id", client_id);
        let resp = self
            .inner
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
        let url = self.url_for(&["oauth", "authorizations", authorization_id, "consent"])?;
        let body = serde_json::json!({ "action": action });
        let resp = self
            .inner
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
        use rand::RngExt;

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
        let mut url = self.fixed_url(&["oauth", "authorize"]);
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
        let url = self.fixed_url(&["oauth", "token"]);
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

        let resp = self.inner.http.post(url).form(&form).send().await?;
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
        let url = self.fixed_url(&["oauth", "token"]);
        let mut form: Vec<(&str, String)> = vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", refresh_token.to_string()),
            ("client_id", client_id.to_string()),
        ];
        if let Some(secret) = client_secret {
            form.push(("client_secret", secret.to_string()));
        }

        let resp = self.inner.http.post(url).form(&form).send().await?;
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
        let url = self.fixed_url(&["oauth", "revoke"]);
        let mut form: Vec<(&str, String)> = vec![("token", token.to_string())];
        if let Some(hint) = token_type_hint {
            form.push(("token_type_hint", hint.to_string()));
        }

        let resp = self.inner.http.post(url).form(&form).send().await?;
        self.handle_empty_response(resp).await
    }

    /// Fetch the OpenID Connect discovery document.
    ///
    /// GET `/.well-known/openid-configuration`.
    pub async fn oauth_get_openid_configuration(
        &self,
    ) -> Result<OpenIdConfiguration, AuthError> {
        let url = self.fixed_url(&[".well-known", "openid-configuration"]);
        let resp = self.inner.http.get(url).send().await?;
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
        let url = self.fixed_url(&[".well-known", "jwks.json"]);
        let resp = self.inner.http.get(url).send().await?;
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
        let url = self.fixed_url(&["oauth", "userinfo"]);
        let resp = self
            .inner
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

    // ─── JWT Claims ────────────────────────────────────────────

    /// Extract claims from a JWT access token without verifying the signature.
    ///
    /// This is a client-side decode only — it does NOT validate the token.
    /// Useful for reading `sub`, `exp`, `role`, `email`, custom claims, etc.
    ///
    /// Returns the payload as a `serde_json::Value` object.
    pub fn get_claims(token: &str) -> Result<JsonValue, AuthError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::InvalidToken(
                "JWT must have 3 parts separated by '.'".to_string(),
            ));
        }

        let payload_b64 = parts[1];
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|e| AuthError::InvalidToken(format!("Invalid base64 in JWT payload: {}", e)))?;

        serde_json::from_slice(&decoded)
            .map_err(|e| AuthError::InvalidToken(format!("Invalid JSON in JWT payload: {}", e)))
    }

    // ─── Captcha Support ──────────────────────────────────────

    /// Sign up with email, password, optional user data, and optional captcha token.
    ///
    /// This is the full-featured sign-up method that consolidates email sign-up
    /// with all optional parameters. The captcha token is sent as
    /// `gotrue_meta_security.captcha_token` in the request body.
    pub async fn sign_up_with_email_full(
        &self,
        email: &str,
        password: &str,
        data: Option<JsonValue>,
        captcha_token: Option<&str>,
    ) -> Result<AuthResponse, AuthError> {
        let mut body = json!({
            "email": email,
            "password": password,
        });
        if let Some(data) = data {
            body["data"] = data;
        }
        if let Some(token) = captcha_token {
            body["gotrue_meta_security"] = json!({ "captcha_token": token });
        }

        let url = self.fixed_url(&["signup"]);
        let resp = self.inner.http.post(url).json(&body).send().await?;
        let auth_resp = self.handle_auth_response(resp).await?;
        if let Some(session) = &auth_resp.session {
            self.store_session(session, AuthChangeEvent::SignedIn).await;
        }
        Ok(auth_resp)
    }

    /// Sign in with email and password, with an optional captcha token.
    pub async fn sign_in_with_password_email_captcha(
        &self,
        email: &str,
        password: &str,
        captcha_token: Option<&str>,
    ) -> Result<Session, AuthError> {
        let mut body = json!({
            "email": email,
            "password": password,
        });
        if let Some(token) = captcha_token {
            body["gotrue_meta_security"] = json!({ "captcha_token": token });
        }

        let url = self.fixed_url_with_query(&["token"], &[("grant_type", "password")]);
        let resp = self.inner.http.post(url).json(&body).send().await?;
        let session = self.handle_session_response(resp).await?;
        self.store_session(&session, AuthChangeEvent::SignedIn).await;
        Ok(session)
    }

    /// Send a magic link / OTP to an email, with an optional captcha token.
    pub async fn sign_in_with_otp_email_captcha(
        &self,
        email: &str,
        captcha_token: Option<&str>,
    ) -> Result<(), AuthError> {
        let mut body = json!({
            "email": email,
        });
        if let Some(token) = captcha_token {
            body["gotrue_meta_security"] = json!({ "captcha_token": token });
        }

        let url = self.fixed_url(&["otp"]);
        let resp = self.inner.http.post(url).json(&body).send().await?;
        self.handle_empty_response(resp).await
    }

    /// Send an OTP to a phone number, with an optional captcha token.
    pub async fn sign_in_with_otp_phone_captcha(
        &self,
        phone: &str,
        channel: OtpChannel,
        captcha_token: Option<&str>,
    ) -> Result<(), AuthError> {
        let mut body = json!({
            "phone": phone,
            "channel": channel,
        });
        if let Some(token) = captcha_token {
            body["gotrue_meta_security"] = json!({ "captcha_token": token });
        }

        let url = self.fixed_url(&["otp"]);
        let resp = self.inner.http.post(url).json(&body).send().await?;
        self.handle_empty_response(resp).await
    }

    // ─── Web3 Auth ────────────────────────────────────────────

    /// Sign in with a Web3 wallet (Ethereum or Solana).
    ///
    /// POST to `/token?grant_type=web3` with chain, address, message, signature, nonce.
    /// Stores the session and emits `SignedIn`.
    pub async fn sign_in_with_web3(
        &self,
        params: Web3SignInParams,
    ) -> Result<Session, AuthError> {
        let body = json!({
            "chain": params.chain,
            "address": params.address,
            "message": params.message,
            "signature": params.signature,
            "nonce": params.nonce,
        });

        let url = self.fixed_url_with_query(&["token"], &[("grant_type", "web3")]);
        let resp = self.inner.http.post(url).json(&body).send().await?;
        let session = self.handle_session_response(resp).await?;
        self.store_session(&session, AuthChangeEvent::SignedIn).await;
        Ok(session)
    }

    // ─── Internal Helpers ──────────────────────────────────────

    /// Store session and emit an auth state change event.
    async fn store_session(&self, session: &Session, event: AuthChangeEvent) {
        let mut session = session.clone();
        fill_expires_at(&mut session);
        *self.inner.session.write().await = Some(session.clone());
        self.inner.sync_token_sink(Some(&session));
        let _ = self.inner.event_tx.send(AuthStateChange {
            event,
            session: Some(session),
        });
        self.resume_auto_refresh();
    }

    /// Clear session, stop auto-refresh and emit SignedOut.
    async fn emit_signed_out(&self) {
        // Stop the refresh task first so it cannot write a session back.
        self.inner.abort_auto_refresh_task();
        *self.inner.session.write().await = None;
        self.inner.sync_token_sink(None);
        let _ = self.inner.event_tx.send(AuthStateChange {
            event: AuthChangeEvent::SignedOut,
            session: None,
        });
    }

    /// Build `base_url/seg1/seg2/...` from literal segments.
    pub(crate) fn fixed_url(&self, segments: &[&str]) -> Url {
        build_url(&self.inner.base_url, segments)
    }

    /// Build `base_url/seg1/...?k=v&...` from literal segments; the query is
    /// form-encoded.
    pub(crate) fn fixed_url_with_query(&self, segments: &[&str], query: &[(&str, &str)]) -> Url {
        let mut url = self.fixed_url(segments);
        {
            let mut pairs = url.query_pairs_mut();
            for (k, v) in query {
                pairs.append_pair(k, v);
            }
        }
        url
    }

    /// Build a URL whose segments may include caller-supplied ids. Each
    /// segment is percent-encoded (`/`, `?`, `#` cannot change the path or
    /// add a query), and empty, `.` and `..` segments are rejected.
    pub(crate) fn url_for(&self, segments: &[&str]) -> Result<Url, AuthError> {
        for seg in segments {
            if seg.is_empty() || *seg == "." || *seg == ".." {
                return Err(AuthError::InvalidInput(format!(
                    "invalid path parameter {:?}: must be non-empty and not \".\" or \"..\"",
                    seg
                )));
            }
        }
        Ok(self.fixed_url(segments))
    }

    pub(crate) fn http(&self) -> &reqwest::Client {
        &self.inner.http
    }

    pub(crate) fn api_key(&self) -> &str {
        &self.inner.api_key
    }

    async fn handle_auth_response(&self, resp: reqwest::Response) -> Result<AuthResponse, AuthError> {
        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(self.parse_error(status, resp).await);
        }

        let mut body: AuthResponse = resp.json().await?;
        if let Some(session) = body.session.as_mut() {
            fill_expires_at(session);
        }
        Ok(body)
    }

    async fn handle_session_response(&self, resp: reqwest::Response) -> Result<Session, AuthError> {
        handle_session_response(resp).await
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
        parse_gotrue_error(status, resp).await
    }
}

/// Build `base/seg1/seg2/...`, percent-encoding each segment.
fn build_url(base: &Url, segments: &[&str]) -> Url {
    let mut url = base.clone();
    {
        let mut path = url
            .path_segments_mut()
            .expect("base_url is checked to be a base when the client is built");
        path.pop_if_empty();
        for seg in segments {
            path.push(seg);
        }
    }
    url
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// GoTrue does not always send `expires_at`; derive it from `expires_in` so
/// auto-refresh knows when the session expires.
fn fill_expires_at(session: &mut Session) {
    if session.expires_at.is_none() {
        session.expires_at = Some(now_secs() + session.expires_in.max(0));
    }
}

/// Parse a GoTrue error body (at most 64 KiB of it) into `AuthError::Api`.
pub(crate) async fn parse_gotrue_error(status: u16, resp: reqwest::Response) -> AuthError {
    let body = read_error_body(resp).await;
    match serde_json::from_slice::<GoTrueErrorResponse>(&body) {
        Ok(err_resp) => AuthError::Api {
            status,
            message: err_resp.error_message(),
            error_code: err_resp.code_str().as_deref().map(AuthErrorCode::from),
        },
        Err(_) => AuthError::Api {
            status,
            message: format!("HTTP {}", status),
            error_code: None,
        },
    }
}

async fn handle_session_response(resp: reqwest::Response) -> Result<Session, AuthError> {
    let status = resp.status().as_u16();
    if status >= 400 {
        return Err(parse_gotrue_error(status, resp).await);
    }
    let mut session: Session = resp.json().await?;
    fill_expires_at(&mut session);
    Ok(session)
}

/// POST `/token?grant_type=refresh_token`.
async fn refresh_request(inner: &AuthClientInner, refresh_token: &str) -> Result<Session, AuthError> {
    let body = json!({
        "refresh_token": refresh_token,
    });
    let mut url = build_url(&inner.base_url, &["token"]);
    url.query_pairs_mut()
        .append_pair("grant_type", "refresh_token");
    let resp = inner.http.post(url).json(&body).send().await?;
    handle_session_response(resp).await
}

/// Whether a refresh error means the refresh token itself is no good, so
/// retrying cannot help.
pub(crate) fn is_invalid_refresh_token(err: &AuthError) -> bool {
    match err {
        AuthError::Api {
            status,
            error_code,
            message,
        } => {
            let code_says_invalid = matches!(
                error_code,
                Some(AuthErrorCode::RefreshTokenNotFound)
                    | Some(AuthErrorCode::SessionNotFound)
                    | Some(AuthErrorCode::OAuthInvalidGrant)
            ) || matches!(
                error_code,
                Some(AuthErrorCode::Unknown(c))
                    if c == "refresh_token_already_used"
                        || c == "session_expired"
                        || c == "invalid_grant"
                        || c == "user_not_found"
                        || c == "user_banned"
            );
            let message_says_invalid = message.contains("Invalid Refresh Token");
            matches!(status, 400 | 401 | 403 | 404) && (code_says_invalid || message_says_invalid)
        }
        _ => false,
    }
}

/// Refresh the stored session, single-flight.
///
/// `used` is the refresh token the caller saw. If, once the lock is held, the
/// stored session has a different refresh token, someone else already
/// refreshed (or replaced) it and that session is returned as is. The result
/// of the HTTP call is only written back if the stored refresh token still
/// equals `used`, so a sign-out (or `set_session`) during the request wins.
/// On an invalid-refresh-token error the session is cleared, again only if it
/// is still the one that was used.
async fn refresh_stored_session(inner: &AuthClientInner, used: &str) -> Result<Session, AuthError> {
    let _flight = inner.refresh_lock.lock().await;

    match inner.session.read().await.as_ref() {
        None => return Err(AuthError::NoSession),
        Some(s) if s.refresh_token != used => return Ok(s.clone()),
        Some(_) => {}
    }

    match refresh_request(inner, used).await {
        Ok(new_session) => {
            let mut guard = inner.session.write().await;
            match guard.as_ref() {
                Some(s) if s.refresh_token == used => {
                    *guard = Some(new_session.clone());
                    drop(guard);
                    inner.sync_token_sink(Some(&new_session));
                    let _ = inner.event_tx.send(AuthStateChange {
                        event: AuthChangeEvent::TokenRefreshed,
                        session: Some(new_session.clone()),
                    });
                    Ok(new_session)
                }
                // Replaced while the request was in flight: keep the newer one.
                Some(s) => Ok(s.clone()),
                // Signed out while the request was in flight: do not resurrect.
                None => Err(AuthError::NoSession),
            }
        }
        Err(err) => {
            if is_invalid_refresh_token(&err) {
                clear_if_unchanged(inner, used).await;
            }
            Err(err)
        }
    }
}

/// Clear the session and emit `SignedOut`, but only if the stored session
/// still uses `refresh_token`.
async fn clear_if_unchanged(inner: &AuthClientInner, refresh_token: &str) {
    let mut guard = inner.session.write().await;
    if guard
        .as_ref()
        .is_some_and(|s| s.refresh_token == refresh_token)
    {
        *guard = None;
        drop(guard);
        inner.sync_token_sink(None);
        let _ = inner.event_tx.send(AuthStateChange {
            event: AuthChangeEvent::SignedOut,
            session: None,
        });
    }
}

fn spawn_auto_refresh(inner: &Arc<AuthClientInner>, config: AutoRefreshConfig) -> platform::SpawnHandle {
    platform::spawn(auto_refresh_loop(Arc::downgrade(inner), config))
}

/// Background auto-refresh loop.
///
/// Holds only a `Weak` reference so it never keeps the client alive, and
/// exits once the client is dropped. Refreshes go through the same
/// single-flight path as `refresh_current_session`.
async fn auto_refresh_loop(weak: Weak<AuthClientInner>, config: AutoRefreshConfig) {
    let mut retries = 0u32;
    loop {
        platform::sleep(config.check_interval).await;

        let Some(inner) = weak.upgrade() else {
            break;
        };

        let session = inner.session.read().await.clone();
        let Some(session) = session else {
            retries = 0;
            continue;
        };
        if !should_refresh(&session, &config.refresh_margin) {
            continue;
        }

        match refresh_stored_session(&inner, &session.refresh_token).await {
            Ok(_) => retries = 0,
            Err(AuthError::NoSession) => retries = 0,
            Err(err) if is_invalid_refresh_token(&err) => {
                // Already cleared by refresh_stored_session (if unchanged).
                retries = 0;
            }
            Err(_) => {
                retries += 1;
                if retries >= config.max_retries {
                    // Give up on this session, but never wipe a newer one.
                    clear_if_unchanged(&inner, &session.refresh_token).await;
                    retries = 0;
                }
            }
        }
    }
}

/// Check if a session should be refreshed based on its expiry.
fn should_refresh(session: &Session, margin: &std::time::Duration) -> bool {
    session
        .expires_at
        .map(|exp| exp - now_secs() < margin.as_secs() as i64)
        .unwrap_or(false)
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
        let url = client.fixed_url(&["signup"]);
        assert_eq!(url.path(), "/auth/v1/signup");
        assert!(url.query().is_none());

        let url = client.fixed_url_with_query(&["token"], &[("grant_type", "password")]);
        assert_eq!(url.path(), "/auth/v1/token");
        assert_eq!(url.query(), Some("grant_type=password"));

        let url = client.url_for(&["factors", "a/b?c#d", "verify"]).unwrap();
        assert_eq!(url.path(), "/auth/v1/factors/a%2Fb%3Fc%23d/verify");
        assert!(url.query().is_none());
        for bad in ["", ".", ".."] {
            assert!(matches!(
                client.url_for(&["factors", bad]),
                Err(AuthError::InvalidInput(_))
            ));
        }
    }

    #[test]
    fn test_url_building_trailing_slash() {
        let client = AuthClient::new("https://example.supabase.co/", "test-key").unwrap();
        let url = client.fixed_url(&["signup"]);
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

    // ─── Session State Tests ────────────────────────────────

    #[tokio::test]
    async fn test_new_client_has_no_session() {
        let client = AuthClient::new("https://example.supabase.co", "test-key").unwrap();
        assert!(client.get_session().await.is_none());
    }

    #[tokio::test]
    async fn test_set_session_stores() {
        let client = AuthClient::new("https://example.supabase.co", "test-key").unwrap();
        let session = make_test_session();
        client.set_session(session.clone()).await;
        let stored = client.get_session().await.unwrap();
        assert_eq!(stored.access_token, session.access_token);
    }

    #[tokio::test]
    async fn test_clear_session() {
        let client = AuthClient::new("https://example.supabase.co", "test-key").unwrap();
        client.set_session(make_test_session()).await;
        assert!(client.get_session().await.is_some());
        client.clear_session().await;
        assert!(client.get_session().await.is_none());
    }

    #[tokio::test]
    async fn test_event_emitted_on_set_session() {
        let client = AuthClient::new("https://example.supabase.co", "test-key").unwrap();
        let mut sub = client.on_auth_state_change();
        client.set_session(make_test_session()).await;
        let event = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            sub.next(),
        ).await.unwrap().unwrap();
        assert_eq!(event.event, AuthChangeEvent::SignedIn);
        assert!(event.session.is_some());
    }

    #[tokio::test]
    async fn test_event_emitted_on_clear_session() {
        let client = AuthClient::new("https://example.supabase.co", "test-key").unwrap();
        let mut sub = client.on_auth_state_change();
        client.clear_session().await;
        let event = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            sub.next(),
        ).await.unwrap().unwrap();
        assert_eq!(event.event, AuthChangeEvent::SignedOut);
        assert!(event.session.is_none());
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let client = AuthClient::new("https://example.supabase.co", "test-key").unwrap();
        let mut sub1 = client.on_auth_state_change();
        let mut sub2 = client.on_auth_state_change();
        client.set_session(make_test_session()).await;

        let timeout = std::time::Duration::from_millis(100);
        let e1 = tokio::time::timeout(timeout, sub1.next()).await.unwrap().unwrap();
        let e2 = tokio::time::timeout(timeout, sub2.next()).await.unwrap().unwrap();
        assert_eq!(e1.event, AuthChangeEvent::SignedIn);
        assert_eq!(e2.event, AuthChangeEvent::SignedIn);
    }

    #[tokio::test]
    async fn test_no_session_error() {
        let client = AuthClient::new("https://example.supabase.co", "test-key").unwrap();
        let err = client.get_session_user().await.unwrap_err();
        assert!(matches!(err, AuthError::NoSession));
    }

    #[tokio::test]
    async fn test_should_refresh_logic() {
        let margin = std::time::Duration::from_secs(60);

        // Session with expires_at in the past → should refresh
        let mut session = make_test_session();
        session.expires_at = Some(0);
        assert!(should_refresh(&session, &margin));

        // Session with no expires_at → should not refresh
        session.expires_at = None;
        assert!(!should_refresh(&session, &margin));

        // Session expiring far in the future → should not refresh
        let future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64 + 3600;
        session.expires_at = Some(future);
        assert!(!should_refresh(&session, &margin));

        // Session expiring within margin → should refresh
        let soon = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64 + 30;
        session.expires_at = Some(soon);
        assert!(should_refresh(&session, &margin));
    }

    /// Helper to create a test session for unit tests.
    fn make_test_session() -> Session {
        Session {
            access_token: "test-access-token".to_string(),
            refresh_token: "test-refresh-token".to_string(),
            expires_in: 3600,
            expires_at: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64
                    + 3600,
            ),
            token_type: "bearer".to_string(),
            user: User {
                id: "test-user-id".to_string(),
                aud: Some("authenticated".to_string()),
                role: Some("authenticated".to_string()),
                email: Some("test@example.com".to_string()),
                phone: None,
                email_confirmed_at: None,
                phone_confirmed_at: None,
                confirmation_sent_at: None,
                recovery_sent_at: None,
                last_sign_in_at: None,
                created_at: None,
                updated_at: None,
                user_metadata: None,
                app_metadata: None,
                identities: None,
                factors: None,
                is_anonymous: None,
            },
        }
    }

    // ─── get_claims Tests ───────────────────────────────────

    #[test]
    fn test_get_claims_valid_jwt() {
        // Create a minimal JWT: header.payload.signature
        // payload = {"sub":"user-123","email":"test@example.com","role":"authenticated"}
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            r#"{"sub":"user-123","email":"test@example.com","role":"authenticated"}"#
        );
        let token = format!("eyJhbGciOiJIUzI1NiJ9.{}.fake-signature", payload);
        let claims = AuthClient::get_claims(&token).unwrap();
        assert_eq!(claims["sub"], "user-123");
        assert_eq!(claims["email"], "test@example.com");
        assert_eq!(claims["role"], "authenticated");
    }

    #[test]
    fn test_get_claims_invalid_format() {
        let err = AuthClient::get_claims("not-a-jwt").unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)));
    }

    #[test]
    fn test_get_claims_invalid_base64() {
        let err = AuthClient::get_claims("a.!!!invalid!!!.c").unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)));
    }

    #[test]
    fn test_get_claims_invalid_json() {
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("not json");
        let token = format!("a.{}.c", payload);
        let err = AuthClient::get_claims(&token).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)));
    }

    // ─── Web3 Type Tests ────────────────────────────────────

    #[test]
    fn test_web3_chain_serialization() {
        assert_eq!(serde_json::to_string(&Web3Chain::Ethereum).unwrap(), "\"ethereum\"");
        assert_eq!(serde_json::to_string(&Web3Chain::Solana).unwrap(), "\"solana\"");
    }

    #[test]
    fn test_web3_chain_display() {
        assert_eq!(Web3Chain::Ethereum.to_string(), "ethereum");
        assert_eq!(Web3Chain::Solana.to_string(), "solana");
    }

    #[test]
    fn test_web3_sign_in_params() {
        let params = Web3SignInParams::new(
            Web3Chain::Ethereum,
            "0x1234567890abcdef",
            "Sign this message",
            "0xsignature",
            "random-nonce",
        );
        assert_eq!(params.chain, Web3Chain::Ethereum);
        assert_eq!(params.address, "0x1234567890abcdef");
        let json = serde_json::to_value(&params).unwrap();
        assert_eq!(json["chain"], "ethereum");
        assert_eq!(json["address"], "0x1234567890abcdef");
    }

    // ─── Captcha Body Structure Tests ───────────────────────

    #[test]
    fn test_captcha_body_structure() {
        let mut body = json!({
            "email": "test@example.com",
            "password": "pass",
        });
        let token = "captcha-abc-123";
        body["gotrue_meta_security"] = json!({ "captcha_token": token });

        assert_eq!(body["gotrue_meta_security"]["captcha_token"], "captcha-abc-123");
        assert_eq!(body["email"], "test@example.com");
    }

    // ─── Wiremock Tests ──────────────────────────────────────

    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Helper: create an AuthClient pointing at the given mock server.
    fn mock_auth(server: &MockServer) -> AuthClient {
        AuthClient::new(&server.uri(), "test-anon-key").unwrap()
    }

    /// Helper: build a valid session JSON response body.
    fn session_json() -> serde_json::Value {
        json!({
            "access_token": "mock-access-token",
            "refresh_token": "mock-refresh-token",
            "expires_in": 3600,
            "expires_at": 9999999999i64,
            "token_type": "bearer",
            "user": {
                "id": "user-123",
                "aud": "authenticated",
                "role": "authenticated",
                "email": "test@example.com"
            }
        })
    }

    // ─── Sign-Up Error ──────────────────────────────────────

    #[tokio::test]
    async fn wiremock_sign_up_422_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/signup"))
            .respond_with(
                ResponseTemplate::new(422)
                    .set_body_json(json!({
                        "msg": "Password should be at least 6 characters",
                        "error_code": "weak_password"
                    })),
            )
            .mount(&server)
            .await;

        let auth = mock_auth(&server);
        let err = auth.sign_up_with_email("user@test.com", "short").await.unwrap_err();
        match err {
            AuthError::Api { status, message, error_code } => {
                assert_eq!(status, 422);
                assert_eq!(message, "Password should be at least 6 characters");
                assert_eq!(error_code, Some(crate::error::AuthErrorCode::WeakPassword));
            }
            other => panic!("Expected Api error, got: {:?}", other),
        }
    }

    // ─── Sign-In Error ──────────────────────────────────────

    #[tokio::test]
    async fn wiremock_sign_in_invalid_credentials() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/token"))
            .and(query_param("grant_type", "password"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(json!({
                        "msg": "Invalid login credentials",
                        "error_code": "invalid_credentials"
                    })),
            )
            .mount(&server)
            .await;

        let auth = mock_auth(&server);
        let err = auth
            .sign_in_with_password_email("wrong@test.com", "badpass")
            .await
            .unwrap_err();
        match err {
            AuthError::Api { status, message, error_code } => {
                assert_eq!(status, 400);
                assert_eq!(message, "Invalid login credentials");
                assert_eq!(
                    error_code,
                    Some(crate::error::AuthErrorCode::InvalidCredentials)
                );
            }
            other => panic!("Expected Api error, got: {:?}", other),
        }
    }

    // ─── Token Refresh Error ────────────────────────────────

    #[tokio::test]
    async fn wiremock_token_refresh_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/token"))
            .and(query_param("grant_type", "refresh_token"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(json!({
                        "msg": "Invalid Refresh Token: Already Used",
                        "error_code": "refresh_token_not_found"
                    })),
            )
            .mount(&server)
            .await;

        let auth = mock_auth(&server);
        let err = auth.refresh_session("expired-token").await.unwrap_err();
        match err {
            AuthError::Api { status, message, error_code } => {
                assert_eq!(status, 400);
                assert!(message.contains("Already Used"));
                assert_eq!(
                    error_code,
                    Some(crate::error::AuthErrorCode::RefreshTokenNotFound)
                );
            }
            other => panic!("Expected Api error, got: {:?}", other),
        }
    }

    // ─── Password Reset Error ───────────────────────────────

    #[tokio::test]
    async fn wiremock_password_reset_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/recover"))
            .respond_with(
                ResponseTemplate::new(429)
                    .set_body_json(json!({
                        "msg": "Rate limit exceeded",
                        "error_code": "over_request_rate_limit"
                    })),
            )
            .mount(&server)
            .await;

        let auth = mock_auth(&server);
        let err = auth
            .reset_password_for_email("user@test.com", None)
            .await
            .unwrap_err();
        match err {
            AuthError::Api { status, message, error_code } => {
                assert_eq!(status, 429);
                assert_eq!(message, "Rate limit exceeded");
                assert_eq!(
                    error_code,
                    Some(crate::error::AuthErrorCode::OverRequestRateLimit)
                );
            }
            other => panic!("Expected Api error, got: {:?}", other),
        }
    }

    // ─── Verify OTP Error ───────────────────────────────────

    #[tokio::test]
    async fn wiremock_verify_otp_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/verify"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_json(json!({
                        "msg": "Token has expired or is invalid",
                        "error_code": "otp_expired"
                    })),
            )
            .mount(&server)
            .await;

        let auth = mock_auth(&server);
        let params = crate::params::VerifyOtpParams {
            token: "999999".to_string(),
            otp_type: OtpType::Email,
            email: Some("user@test.com".to_string()),
            phone: None,
            token_hash: None,
        };
        let err = auth.verify_otp(params).await.unwrap_err();
        match err {
            AuthError::Api { status, message, error_code } => {
                assert_eq!(status, 403);
                assert!(message.contains("expired"));
                assert_eq!(
                    error_code,
                    Some(crate::error::AuthErrorCode::OtpExpired)
                );
            }
            other => panic!("Expected Api error, got: {:?}", other),
        }
    }

    // ─── Admin API Error ────────────────────────────────────

    #[tokio::test]
    async fn wiremock_admin_list_users_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/auth/v1/admin/users"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_json(json!({
                        "msg": "Invalid API key"
                    })),
            )
            .mount(&server)
            .await;

        let auth = mock_auth(&server);
        let admin = auth.admin();
        let err = admin.list_users(None, None).await.unwrap_err();
        match err {
            AuthError::Api { status, message, .. } => {
                assert_eq!(status, 401);
                assert_eq!(message, "Invalid API key");
            }
            other => panic!("Expected Api error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn wiremock_admin_delete_user_error() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/auth/v1/admin/users/nonexistent-id"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(json!({
                        "msg": "User not found",
                        "error_code": "user_not_found"
                    })),
            )
            .mount(&server)
            .await;

        let auth = mock_auth(&server);
        let admin = auth.admin();
        let err = admin.delete_user("nonexistent-id").await.unwrap_err();
        match err {
            AuthError::Api { status, message, .. } => {
                assert_eq!(status, 404);
                assert_eq!(message, "User not found");
            }
            other => panic!("Expected Api error, got: {:?}", other),
        }
    }

    // ─── SSO Error ──────────────────────────────────────────

    #[tokio::test]
    async fn wiremock_sso_sign_in_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/sso"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(json!({
                        "msg": "No SSO provider found for domain",
                        "error_code": "sso_provider_not_found"
                    })),
            )
            .mount(&server)
            .await;

        let auth = mock_auth(&server);
        let params = crate::params::SsoSignInParams::domain("unknown.com");
        let err = auth.sign_in_with_sso(params).await.unwrap_err();
        match err {
            AuthError::Api { status, message, error_code } => {
                assert_eq!(status, 404);
                assert!(message.contains("SSO provider"));
                assert_eq!(
                    error_code,
                    Some(crate::error::AuthErrorCode::SsoProviderNotFound)
                );
            }
            other => panic!("Expected Api error, got: {:?}", other),
        }
    }

    // ─── Identity Link Error ────────────────────────────────

    #[tokio::test]
    async fn wiremock_link_identity_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/auth/v1/user/identities/authorize"))
            .respond_with(
                ResponseTemplate::new(422)
                    .set_body_json(json!({
                        "msg": "Identity already exists",
                        "error_code": "identity_already_exists"
                    })),
            )
            .mount(&server)
            .await;

        let auth = mock_auth(&server);
        let err = auth
            .link_identity("access-token", OAuthProvider::Google)
            .await
            .unwrap_err();
        match err {
            AuthError::Api { status, message, error_code } => {
                assert_eq!(status, 422);
                assert!(message.contains("Identity already exists"));
                assert_eq!(
                    error_code,
                    Some(crate::error::AuthErrorCode::IdentityAlreadyExists)
                );
            }
            other => panic!("Expected Api error, got: {:?}", other),
        }
    }

    // ─── Identity Unlink Error ──────────────────────────────

    #[tokio::test]
    async fn wiremock_unlink_identity_error() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/auth/v1/user/identities/identity-123"))
            .respond_with(
                ResponseTemplate::new(422)
                    .set_body_json(json!({
                        "msg": "Unlinking this identity is not allowed",
                        "error_code": "single_identity_not_deletable"
                    })),
            )
            .mount(&server)
            .await;

        let auth = mock_auth(&server);
        let err = auth
            .unlink_identity("access-token", "identity-123")
            .await
            .unwrap_err();
        match err {
            AuthError::Api { status, message, error_code } => {
                assert_eq!(status, 422);
                assert!(message.contains("not allowed"));
                assert_eq!(
                    error_code,
                    Some(crate::error::AuthErrorCode::SingleIdentityNotDeletable)
                );
            }
            other => panic!("Expected Api error, got: {:?}", other),
        }
    }

    // ─── Sign-In Success ────────────────────────────────────

    #[tokio::test]
    async fn wiremock_sign_in_success_stores_session() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/token"))
            .and(query_param("grant_type", "password"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(session_json()),
            )
            .mount(&server)
            .await;

        let auth = mock_auth(&server);
        let session = auth
            .sign_in_with_password_email("test@example.com", "password123")
            .await
            .unwrap();
        assert_eq!(session.access_token, "mock-access-token");
        assert_eq!(session.user.id, "user-123");

        // Verify session is stored
        let stored = auth.get_session().await.unwrap();
        assert_eq!(stored.access_token, "mock-access-token");
    }

    // ─── Sign-Out Error ─────────────────────────────────────

    #[tokio::test]
    async fn wiremock_sign_out_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/logout"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(json!({
                        "msg": "Bad request"
                    })),
            )
            .mount(&server)
            .await;

        // 401/403/404 are treated as "already signed out" (see
        // regression_sign_out_401_clears_stale_session); other errors surface.
        let auth = mock_auth(&server);
        let err = auth.sign_out("bad-token").await.unwrap_err();
        match err {
            AuthError::Api { status, .. } => {
                assert_eq!(status, 400);
            }
            other => panic!("Expected Api error, got: {:?}", other),
        }
    }

    // ─── Non-JSON error response fallback ───────────────────

    #[tokio::test]
    async fn wiremock_sign_in_non_json_error_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/token"))
            .and(query_param("grant_type", "password"))
            .respond_with(
                ResponseTemplate::new(500).set_body_string("Internal Server Error"),
            )
            .mount(&server)
            .await;

        let auth = mock_auth(&server);
        let err = auth
            .sign_in_with_password_email("user@test.com", "pass")
            .await
            .unwrap_err();
        match err {
            AuthError::Api { status, message, error_code } => {
                assert_eq!(status, 500);
                assert_eq!(message, "HTTP 500");
                assert!(error_code.is_none());
            }
            other => panic!("Expected Api error, got: {:?}", other),
        }
    }

    // ─── Regression tests (security audit) ───────────────────

    use std::time::Duration;
    use wiremock::matchers::any;

    async fn catch_all() -> MockServer {
        let s = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&s)
            .await;
        s
    }

    fn poc_session_json(access: &str, refresh: &str, expires_at: Option<i64>) -> serde_json::Value {
        let mut v = json!({
            "access_token": access, "refresh_token": refresh, "expires_in": 3600,
            "token_type": "bearer", "user": {"id": "u1"}
        });
        if let Some(e) = expires_at {
            v["expires_at"] = json!(e);
        }
        v
    }

    fn poc_session(access: &str, refresh: &str, expires_at: Option<i64>) -> Session {
        serde_json::from_value(poc_session_json(access, refresh, expires_at)).unwrap()
    }

    fn fast_refresh() -> AutoRefreshConfig {
        AutoRefreshConfig {
            check_interval: Duration::from_millis(20),
            refresh_margin: Duration::from_secs(60),
            max_retries: 3,
        }
    }

    #[tokio::test]
    async fn regression_admin_user_id_traversal_is_rejected() {
        let s = catch_all().await;
        let a = AuthClient::new(&s.uri(), "SERVICE_ROLE_KEY").unwrap();
        let admin = a.admin();
        let evil = "../../../../rest/v1/profiles?id=not.is.null";
        // `/` is encoded, so a traversal string stays one segment under /admin/users/.
        let _ = admin.delete_user(evil).await;
        for r in s.received_requests().await.unwrap() {
            assert!(
                r.url.path().starts_with("/auth/v1/admin/users/"),
                "escaped: {}",
                r.url
            );
            assert!(r.url.query().is_none(), "query injected: {}", r.url);
        }
        for bad in ["..", ".", ""] {
            assert!(matches!(admin.delete_user(bad).await, Err(AuthError::InvalidInput(_))));
            assert!(matches!(admin.get_user_by_id(bad).await, Err(AuthError::InvalidInput(_))));
            assert!(matches!(admin.mfa_list_factors(bad).await, Err(AuthError::InvalidInput(_))));
            assert!(matches!(
                admin.mfa_delete_factor("u", bad).await,
                Err(AuthError::InvalidInput(_))
            ));
            assert!(matches!(admin.oauth_get_client(bad).await, Err(AuthError::InvalidInput(_))));
            assert!(matches!(
                admin.oauth_delete_client(bad).await,
                Err(AuthError::InvalidInput(_))
            ));
            assert!(matches!(
                a.mfa_unenroll("jwt", bad).await,
                Err(AuthError::InvalidInput(_))
            ));
            assert!(matches!(
                a.unlink_identity("jwt", bad).await,
                Err(AuthError::InvalidInput(_))
            ));
            assert!(matches!(
                a.oauth_get_authorization_details("jwt", bad).await,
                Err(AuthError::InvalidInput(_))
            ));
        }
    }

    #[tokio::test]
    async fn regression_admin_user_id_is_one_encoded_segment() {
        let s = catch_all().await;
        let a = AuthClient::new(&s.uri(), "SERVICE_ROLE_KEY").unwrap();
        let _ = a.admin().delete_user("../../x?y=1#z").await;
        let reqs = s.received_requests().await.unwrap();
        let r = reqs.last().unwrap();
        assert_eq!(r.url.path(), "/auth/v1/admin/users/..%2F..%2Fx%3Fy=1%23z");
        assert!(r.url.query().is_none());
    }

    #[test]
    fn regression_admin_debug_redacts_service_role_key() {
        let a = AuthClient::new("https://x.supabase.co", "ANON").unwrap();
        let admin = a.admin_with_key("SERVICE-ROLE-SECRET");
        let dbg = format!("{:?}", admin);
        assert!(!dbg.contains("SERVICE-ROLE-SECRET"), "{}", dbg);
        assert!(!dbg.contains("ANON"), "{}", dbg);
    }

    #[tokio::test]
    async fn regression_signup_autoconfirm_session_is_stored() {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/signup"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(poc_session_json("AT", "RT", Some(9999999999))),
            )
            .mount(&s)
            .await;
        let a = AuthClient::new(&s.uri(), "anon").unwrap();
        let r = a.sign_up_with_email("a@b.c", "pw123456").await.unwrap();
        assert_eq!(r.session.as_ref().unwrap().access_token, "AT");
        assert_eq!(r.user.as_ref().unwrap().id, "u1");
        assert_eq!(a.get_session().await.unwrap().access_token, "AT");
    }

    #[tokio::test]
    async fn regression_signup_confirm_required_returns_user() {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/signup"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"id": "u1", "aud": "authenticated", "email": "a@b.c"}),
            ))
            .mount(&s)
            .await;
        let a = AuthClient::new(&s.uri(), "anon").unwrap();
        let r = a.sign_up_with_email("a@b.c", "pw123456").await.unwrap();
        assert!(r.session.is_none());
        assert_eq!(r.user.unwrap().email.as_deref(), Some("a@b.c"));
        assert!(a.get_session().await.is_none());
    }

    #[tokio::test]
    async fn regression_auto_refresh_does_not_resurrect_after_sign_out() {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(poc_session_json("AT2", "RT2", Some(9999999999)))
                    .set_delay(Duration::from_millis(400)),
            )
            .mount(&s)
            .await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/logout"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&s)
            .await;
        let a = AuthClient::new(&s.uri(), "anon").unwrap();
        a.set_session(poc_session("AT1", "RT1", Some(0))).await;
        a.start_auto_refresh_with(AutoRefreshConfig {
            check_interval: Duration::from_millis(50),
            refresh_margin: Duration::from_secs(60),
            max_retries: 3,
        });
        tokio::time::sleep(Duration::from_millis(150)).await; // refresh now in flight
        a.sign_out_current().await.unwrap();
        assert!(a.get_session().await.is_none());
        assert!(!a.is_auto_refresh_running());
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert!(
            a.get_session().await.is_none(),
            "session resurrected after sign-out"
        );
    }

    #[tokio::test]
    async fn regression_manual_refresh_does_not_resurrect_after_sign_out() {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(poc_session_json("AT2", "RT2", Some(9999999999)))
                    .set_delay(Duration::from_millis(300)),
            )
            .mount(&s)
            .await;
        let a = AuthClient::new(&s.uri(), "anon").unwrap();
        a.set_session(poc_session("AT1", "RT1", Some(9999999999))).await;
        let a2 = a.clone();
        let refresh = tokio::spawn(async move { a2.refresh_current_session().await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        a.clear_session().await;
        let res = refresh.await.unwrap();
        assert!(matches!(res, Err(AuthError::NoSession)), "{:?}", res.map(|s| s.access_token));
        assert!(a.get_session().await.is_none());
    }

    #[tokio::test]
    async fn concurrent_refreshes_are_single_flight() {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(poc_session_json("AT2", "RT2", Some(9999999999)))
                    .set_delay(Duration::from_millis(100)),
            )
            .mount(&s)
            .await;
        let a = AuthClient::new(&s.uri(), "anon").unwrap();
        a.set_session(poc_session("AT1", "RT1", Some(9999999999))).await;
        let (r1, r2, r3) = tokio::join!(
            a.refresh_current_session(),
            a.refresh_current_session(),
            a.refresh_session("RT1"),
        );
        assert_eq!(r1.unwrap().access_token, "AT2");
        assert_eq!(r2.unwrap().access_token, "AT2");
        assert_eq!(r3.unwrap().access_token, "AT2");
        assert_eq!(s.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn invalid_refresh_token_clears_session_without_retrying() {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "code": 400,
                "error_code": "refresh_token_not_found",
                "msg": "Invalid Refresh Token: Refresh Token Not Found"
            })))
            .mount(&s)
            .await;
        let a = AuthClient::new(&s.uri(), "anon").unwrap();
        a.set_session(poc_session("AT1", "RT1", Some(9999999999))).await;
        let err = a.refresh_current_session().await.unwrap_err();
        match &err {
            AuthError::Api {
                status,
                message,
                error_code,
            } => {
                assert_eq!(*status, 400);
                assert!(message.contains("Refresh Token Not Found"), "{}", message);
                assert_eq!(*error_code, Some(AuthErrorCode::RefreshTokenNotFound));
            }
            other => panic!("{:?}", other),
        }
        assert!(a.get_session().await.is_none());

        // The auto-refresh loop does not retry an invalid token either.
        a.set_session(poc_session("AT1", "RT1", Some(0))).await;
        a.start_auto_refresh_with(AutoRefreshConfig {
            check_interval: Duration::from_millis(20),
            refresh_margin: Duration::from_secs(60),
            max_retries: 100,
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(a.get_session().await.is_none());
        assert_eq!(s.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn transient_failures_do_not_wipe_newer_session() {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/token"))
            .respond_with(ResponseTemplate::new(503).set_delay(Duration::from_millis(30)))
            .mount(&s)
            .await;
        let a = AuthClient::new(&s.uri(), "anon").unwrap();
        a.set_session(poc_session("AT1", "RT1", Some(0))).await;
        a.start_auto_refresh_with(AutoRefreshConfig {
            check_interval: Duration::from_millis(10),
            refresh_margin: Duration::from_secs(60),
            max_retries: 3,
        });
        tokio::time::sleep(Duration::from_millis(25)).await;
        // A new sign-in replaces the session while refreshes keep failing.
        a.set_session(poc_session("NEW", "NEW-RT", Some(9999999999))).await;
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(a.get_session().await.unwrap().access_token, "NEW");
    }

    #[tokio::test]
    async fn regression_sign_out_others_keeps_current_session() {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/logout"))
            .and(query_param("scope", "others"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&s)
            .await;
        let a = AuthClient::new(&s.uri(), "anon").unwrap();
        a.set_session(poc_session("AT", "RT", Some(9999999999))).await;
        a.sign_out_current_with_scope(SignOutScope::Others)
            .await
            .unwrap();
        assert!(a.get_session().await.is_some());
    }

    #[tokio::test]
    async fn regression_sign_out_401_clears_stale_session() {
        for status in [401u16, 403, 404] {
            let s = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/auth/v1/logout"))
                .respond_with(ResponseTemplate::new(status).set_body_json(json!({"msg":"invalid JWT"})))
                .mount(&s)
                .await;
            let a = AuthClient::new(&s.uri(), "anon").unwrap();
            let mut sub = a.on_auth_state_change();
            a.set_session(poc_session("AT", "RT", Some(0))).await;
            a.sign_out_current().await.unwrap();
            assert!(a.get_session().await.is_none(), "status {status}");
            let _ = sub.next().await; // SignedIn
            assert_eq!(sub.next().await.unwrap().event, AuthChangeEvent::SignedOut);
        }
    }

    #[tokio::test]
    async fn sign_out_500_keeps_session_and_errors() {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/logout"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&s)
            .await;
        let a = AuthClient::new(&s.uri(), "anon").unwrap();
        a.set_session(poc_session("AT", "RT", Some(9999999999))).await;
        assert!(a.sign_out_current().await.is_err());
        assert!(a.get_session().await.is_some());
    }

    #[tokio::test]
    async fn regression_missing_expires_at_still_refreshes() {
        let s = catch_all().await;
        let a = AuthClient::new(&s.uri(), "anon").unwrap();
        let mut v = poc_session_json("AT", "RT", None);
        v["expires_in"] = json!(0);
        a.set_session(serde_json::from_value(v).unwrap()).await;
        assert!(a.get_session().await.unwrap().expires_at.is_some());
        a.start_auto_refresh_with(fast_refresh());
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!s.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn regression_auto_refresh_stops_when_client_dropped() {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(poc_session_json("AT", "RT", Some(0))))
            .mount(&s)
            .await;
        {
            let a = AuthClient::new(&s.uri(), "anon").unwrap();
            a.set_session(poc_session("AT", "RT", Some(0))).await;
            a.start_auto_refresh_with(fast_refresh());
        } // client dropped here
        let before = s.received_requests().await.unwrap().len();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let after = s.received_requests().await.unwrap().len();
        assert_eq!(before, after, "background task keeps refreshing after client drop");
    }

    #[tokio::test]
    async fn auto_refresh_resumes_after_sign_in() {
        let a = AuthClient::new("http://127.0.0.1:9", "anon").unwrap();
        a.start_auto_refresh();
        assert!(a.is_auto_refresh_running());
        a.clear_session().await;
        assert!(!a.is_auto_refresh_running());
        a.set_session(poc_session("AT", "RT", Some(9999999999))).await;
        assert!(a.is_auto_refresh_running());
        a.stop_auto_refresh();
        a.clear_session().await;
        a.set_session(poc_session("AT", "RT", Some(9999999999))).await;
        assert!(!a.is_auto_refresh_running());
    }

    #[tokio::test]
    async fn regression_redirect_to_is_a_query_param() {
        let s = catch_all().await;
        let a = AuthClient::new(&s.uri(), "anon").unwrap();
        a.reset_password_for_email("a@b.c", Some("https://app/reset?x=1"))
            .await
            .unwrap();
        let _ = a
            .admin()
            .invite_user_by_email("a@b.c", Some("https://app/welcome"))
            .await;
        let reqs = s.received_requests().await.unwrap();
        assert_eq!(reqs[0].url.path(), "/auth/v1/recover");
        let q: Vec<(String, String)> = reqs[0].url.query_pairs().into_owned().collect();
        assert_eq!(q, vec![("redirect_to".into(), "https://app/reset?x=1".into())]);
        let body: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(body, json!({"email": "a@b.c"}));
        assert_eq!(reqs[1].url.path(), "/auth/v1/invite");
        let q: Vec<(String, String)> = reqs[1].url.query_pairs().into_owned().collect();
        assert_eq!(q, vec![("redirect_to".into(), "https://app/welcome".into())]);
    }

    #[tokio::test]
    async fn token_sink_follows_session() {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(session_json()))
            .mount(&s)
            .await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/logout"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&s)
            .await;
        let slot = AccessToken::new();
        let a = AuthClient::with_token_sink(&s.uri(), "anon", slot.clone()).unwrap();
        a.sign_in_with_password_email("a@b.c", "pw").await.unwrap();
        assert_eq!(slot.get().as_deref(), Some("mock-access-token"));
        a.sign_out_current().await.unwrap();
        assert!(slot.get().is_none());
    }

    #[test]
    fn apikey_header_is_sensitive() {
        let a = AuthClient::new("https://x.supabase.co", "ANON-KEY-SECRET").unwrap();
        let dbg = format!("{:?} {:?}", a, a.http());
        assert!(!dbg.contains("ANON-KEY-SECRET"), "{}", dbg);
    }
}
