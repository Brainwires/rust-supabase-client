//! Inspect Supabase API keys.
//!
//! Used to stop a privileged key (a legacy `service_role` JWT or a new-style
//! `sb_secret_...` key) from being shipped to a browser in a wasm32 build,
//! where anyone can read it.

use base64::Engine;

/// What kind of key a string looks like. Nothing here verifies a signature;
/// this only reads the unverified claims to catch configuration mistakes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyKind {
    /// A legacy JWT key whose `role` claim is `service_role`, or a new-style
    /// `sb_secret_...` key. Bypasses row-level security.
    Privileged,
    /// A legacy `anon` JWT, a new-style `sb_publishable_...` key, or a user JWT.
    Public,
    /// Not recognisable as a Supabase key (for example a placeholder in tests).
    Unknown,
}

/// Classify an API key or JWT.
pub fn classify_key(key: &str) -> KeyKind {
    if key.starts_with("sb_secret_") {
        return KeyKind::Privileged;
    }
    if key.starts_with("sb_publishable_") {
        return KeyKind::Public;
    }
    match jwt_role(key) {
        Some(role) if role == "service_role" || role == "supabase_admin" => KeyKind::Privileged,
        Some(_) => KeyKind::Public,
        None => KeyKind::Unknown,
    }
}

/// Read the unverified `role` claim from a JWT, if `token` is one.
pub fn jwt_role(token: &str) -> Option<String> {
    let mut parts = token.split('.');
    let (_header, payload, _sig) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    value.get("role")?.as_str().map(str::to_owned)
}

/// Error message used when a privileged key is refused on wasm32.
pub const PRIVILEGED_KEY_ON_WASM: &str =
    "refusing to use a service_role/secret key in a wasm32 build: it would be readable by \
     anyone who loads the page. Use the anon/publishable key, or construct the client with \
     SupabaseClient::new_allowing_privileged_key if this build never runs in a browser";

/// On wasm32, log a warning when `key` is privileged. Sub-clients constructed
/// directly (not through `SupabaseClient`) call this, since they have no
/// config flag to refuse with.
pub fn warn_if_privileged_on_wasm(key: &str, client: &str) {
    #[cfg(target_arch = "wasm32")]
    if classify_key(key) == KeyKind::Privileged {
        tracing::warn!(client, "{}", PRIVILEGED_KEY_ON_WASM);
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (key, client);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt(payload: &str) -> String {
        let p = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
        format!("eyJhbGciOiJIUzI1NiJ9.{}.sig", p)
    }

    #[test]
    fn classifies_service_role_jwt() {
        assert_eq!(
            classify_key(&jwt(r#"{"role":"service_role"}"#)),
            KeyKind::Privileged
        );
    }

    #[test]
    fn classifies_anon_jwt() {
        assert_eq!(classify_key(&jwt(r#"{"role":"anon"}"#)), KeyKind::Public);
    }

    #[test]
    fn classifies_new_style_keys() {
        assert_eq!(classify_key("sb_secret_abc"), KeyKind::Privileged);
        assert_eq!(classify_key("sb_publishable_abc"), KeyKind::Public);
    }

    #[test]
    fn unknown_for_placeholders() {
        assert_eq!(classify_key("test-key"), KeyKind::Unknown);
        assert_eq!(classify_key("a.b.c"), KeyKind::Unknown);
        assert_eq!(classify_key("a.b.c.d"), KeyKind::Unknown);
    }
}
