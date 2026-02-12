//! WASM/TypeScript bindings for the Supabase client SDK.
//!
//! Build with `wasm-pack build crates/supabase-client-wasm --target web --out-dir ../../pkg`.

use wasm_bindgen::prelude::*;
use serde_json::Value as JsonValue;

use supabase_client_sdk::prelude::*;

// ── Error conversion ─────────────────────────────────────────────────────────

fn to_js_err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

fn to_js_value(val: &impl serde::Serialize) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(val).map_err(to_js_err)
}

/// Convert a JSON value (expected to be an object) into a Row.
fn json_to_row(json: JsonValue) -> Result<Row, JsValue> {
    match json {
        JsonValue::Object(map) => {
            let mut row = Row::new();
            for (k, v) in map {
                row.set(k, v);
            }
            Ok(row)
        }
        _ => Err(JsValue::from_str("expected a JSON object")),
    }
}

// ── WasmSupabaseClient ───────────────────────────────────────────────────────

/// Main Supabase client for WASM/JavaScript usage.
#[wasm_bindgen]
pub struct WasmSupabaseClient {
    inner: SupabaseClient,
    url: String,
    key: String,
}

#[wasm_bindgen]
impl WasmSupabaseClient {
    /// Create a new Supabase client.
    ///
    /// @param url - The Supabase project URL (e.g., `https://your-project.supabase.co`)
    /// @param key - The Supabase anon key
    #[wasm_bindgen(constructor)]
    pub fn new(url: &str, key: &str) -> Result<WasmSupabaseClient, JsValue> {
        let config = SupabaseConfig::new(url, key);
        let inner = SupabaseClient::new(config).map_err(to_js_err)?;
        Ok(WasmSupabaseClient {
            inner,
            url: url.to_string(),
            key: key.to_string(),
        })
    }

    /// Execute a SELECT query on a table. Returns JSON results.
    pub async fn from_select(&self, table: &str, columns: &str) -> Result<JsValue, JsValue> {
        let response = self.inner.from(table).select(columns).execute().await;
        let rows = response.into_result().map_err(to_js_err)?;
        to_js_value(&rows)
    }

    /// Execute an INSERT query. `data` should be a JSON object (single row).
    pub async fn from_insert(&self, table: &str, data: JsValue) -> Result<JsValue, JsValue> {
        let json: JsonValue = serde_wasm_bindgen::from_value(data)?;
        let row = json_to_row(json)?;
        let response = self.inner.from(table).insert(row).execute().await;
        let result = response.into_result().map_err(to_js_err)?;
        to_js_value(&result)
    }

    /// Execute an UPDATE query with eq filter. `data` should be a JSON object.
    pub async fn from_update(
        &self,
        table: &str,
        data: JsValue,
        column: &str,
        value: &str,
    ) -> Result<JsValue, JsValue> {
        let json: JsonValue = serde_wasm_bindgen::from_value(data)?;
        let row = json_to_row(json)?;
        let response = self
            .inner
            .from(table)
            .update(row)
            .eq(column, value)
            .execute()
            .await;
        let result = response.into_result().map_err(to_js_err)?;
        to_js_value(&result)
    }

    /// Execute a DELETE query with eq filter.
    pub async fn from_delete(
        &self,
        table: &str,
        column: &str,
        value: &str,
    ) -> Result<JsValue, JsValue> {
        let response = self
            .inner
            .from(table)
            .delete()
            .eq(column, value)
            .execute()
            .await;
        let result = response.into_result().map_err(to_js_err)?;
        to_js_value(&result)
    }

    /// Create an auth client.
    pub fn auth(&self) -> Result<WasmAuthClient, JsValue> {
        let auth = AuthClient::new(&self.url, &self.key).map_err(to_js_err)?;
        Ok(WasmAuthClient { inner: auth })
    }

    /// Create a realtime client.
    pub fn realtime(&self) -> Result<WasmRealtimeClient, JsValue> {
        let rt = RealtimeClient::new(&self.url, &self.key).map_err(to_js_err)?;
        Ok(WasmRealtimeClient { inner: rt })
    }

    /// Create a storage client.
    pub fn storage(&self) -> Result<WasmStorageClient, JsValue> {
        let storage = supabase_client_sdk::supabase_client_storage::StorageClient::new(
            &self.url,
            &self.key,
        ).map_err(to_js_err)?;
        Ok(WasmStorageClient { inner: storage })
    }

    /// Create a functions client.
    pub fn functions(&self) -> Result<WasmFunctionsClient, JsValue> {
        let functions = supabase_client_sdk::supabase_client_functions::FunctionsClient::new(
            &self.url,
            &self.key,
        ).map_err(to_js_err)?;
        Ok(WasmFunctionsClient { inner: functions })
    }
}

// ── WasmAuthClient ───────────────────────────────────────────────────────────

/// Auth client for WASM/JavaScript usage.
#[wasm_bindgen]
pub struct WasmAuthClient {
    inner: AuthClient,
}

#[wasm_bindgen]
impl WasmAuthClient {
    /// Sign up with email and password. Returns the auth response as JSON.
    pub async fn sign_up(&self, email: &str, password: &str) -> Result<JsValue, JsValue> {
        let resp = self.inner.sign_up_with_email(email, password).await.map_err(to_js_err)?;
        to_js_value(&resp)
    }

    /// Sign in with email and password. Returns the session as JSON.
    pub async fn sign_in_with_password(&self, email: &str, password: &str) -> Result<JsValue, JsValue> {
        let session = self.inner.sign_in_with_password_email(email, password).await.map_err(to_js_err)?;
        to_js_value(&session)
    }

    /// Sign in anonymously. Returns the session as JSON.
    pub async fn sign_in_anonymous(&self) -> Result<JsValue, JsValue> {
        let session = self.inner.sign_in_anonymous().await.map_err(to_js_err)?;
        to_js_value(&session)
    }

    /// Send a magic link / OTP to an email address.
    pub async fn sign_in_with_otp(&self, email: &str) -> Result<(), JsValue> {
        self.inner.sign_in_with_otp_email(email).await.map_err(to_js_err)
    }

    /// Get the current session as JSON (or null).
    pub async fn get_session(&self) -> Result<JsValue, JsValue> {
        match self.inner.get_session().await {
            Some(session) => to_js_value(&session),
            None => Ok(JsValue::NULL),
        }
    }

    /// Refresh the current session. Returns new session as JSON.
    pub async fn refresh_session(&self) -> Result<JsValue, JsValue> {
        let session = self.inner.refresh_current_session().await.map_err(to_js_err)?;
        to_js_value(&session)
    }

    /// Sign out the current user.
    pub async fn sign_out(&self) -> Result<(), JsValue> {
        self.inner.sign_out_current().await.map_err(to_js_err)
    }

    /// Get the user for a given access token. Returns user as JSON.
    pub async fn get_user(&self, access_token: &str) -> Result<JsValue, JsValue> {
        let user = self.inner.get_user(access_token).await.map_err(to_js_err)?;
        to_js_value(&user)
    }

    /// Send a password reset email.
    pub async fn reset_password_for_email(&self, email: &str) -> Result<(), JsValue> {
        self.inner.reset_password_for_email(email, None).await.map_err(to_js_err)
    }

    /// Get an OAuth sign-in URL for a given provider.
    pub fn get_oauth_url(&self, provider: &str) -> Result<String, JsValue> {
        let provider = match provider {
            "google" => supabase_client_sdk::supabase_client_auth::OAuthProvider::Google,
            "github" => supabase_client_sdk::supabase_client_auth::OAuthProvider::GitHub,
            "apple" => supabase_client_sdk::supabase_client_auth::OAuthProvider::Apple,
            "facebook" => supabase_client_sdk::supabase_client_auth::OAuthProvider::Facebook,
            "twitter" => supabase_client_sdk::supabase_client_auth::OAuthProvider::Twitter,
            "discord" => supabase_client_sdk::supabase_client_auth::OAuthProvider::Discord,
            other => supabase_client_sdk::supabase_client_auth::OAuthProvider::Custom(other.to_string()),
        };
        self.inner.get_oauth_sign_in_url(provider, None, None).map_err(to_js_err)
    }
}

// ── WasmRealtimeClient ───────────────────────────────────────────────────────

/// Realtime client for WASM/JavaScript usage.
#[wasm_bindgen]
pub struct WasmRealtimeClient {
    inner: RealtimeClient,
}

#[wasm_bindgen]
impl WasmRealtimeClient {
    /// Connect to the Supabase Realtime server.
    pub async fn connect(&self) -> Result<(), JsValue> {
        self.inner.connect().await.map_err(to_js_err)
    }

    /// Disconnect from the Realtime server.
    pub async fn disconnect(&self) -> Result<(), JsValue> {
        self.inner.disconnect().await.map_err(to_js_err)
    }

    /// Check if connected.
    pub fn is_connected(&self) -> bool {
        self.inner.is_connected()
    }
}

// ── WasmStorageClient ────────────────────────────────────────────────────────

/// Storage client for WASM/JavaScript usage.
#[wasm_bindgen]
pub struct WasmStorageClient {
    inner: supabase_client_sdk::supabase_client_storage::StorageClient,
}

#[wasm_bindgen]
impl WasmStorageClient {
    /// List all storage buckets. Returns JSON array.
    pub async fn list_buckets(&self) -> Result<JsValue, JsValue> {
        let buckets = self.inner.list_buckets().await.map_err(to_js_err)?;
        to_js_value(&buckets)
    }

    /// Get a bucket by ID. Returns JSON object.
    pub async fn get_bucket(&self, id: &str) -> Result<JsValue, JsValue> {
        let bucket = self.inner.get_bucket(id).await.map_err(to_js_err)?;
        to_js_value(&bucket)
    }
}

// ── WasmFunctionsClient ──────────────────────────────────────────────────────

/// Edge Functions client for WASM/JavaScript usage.
#[wasm_bindgen]
pub struct WasmFunctionsClient {
    inner: supabase_client_sdk::supabase_client_functions::FunctionsClient,
}

#[wasm_bindgen]
impl WasmFunctionsClient {
    /// Invoke an edge function with a JSON body. Returns the response body as JSON.
    pub async fn invoke(&self, function_name: &str, body: JsValue) -> Result<JsValue, JsValue> {
        let json: JsonValue = serde_wasm_bindgen::from_value(body)?;
        let options = InvokeOptions::default().body(json);
        let response = self.inner
            .invoke(function_name, options)
            .await
            .map_err(to_js_err)?;
        let result: JsonValue = response.json().map_err(to_js_err)?;
        to_js_value(&result)
    }
}
