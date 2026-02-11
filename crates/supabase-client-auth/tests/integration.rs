//! Integration tests for supabase-client-auth.
//!
//! These tests require a running local Supabase instance started via `supabase start`.
//! Configuration is read from environment variables or falls back to defaults matching
//! the local dev instance in this project's supabase/ directory.
//!
//! Run with: cargo test -p supabase-client-auth -- --test-threads=1

use supabase_client_auth::{
    AdminClient, AuthClient, AuthError, OAuthProvider, SignOutScope,
    AdminCreateUserParams, AdminUpdateUserParams, UpdateUserParams,
    User,
};

/// Default local Supabase URL (from `supabase start` output).
fn supabase_url() -> String {
    std::env::var("SUPABASE_URL").unwrap_or_else(|_| "http://127.0.0.1:64321".to_string())
}

/// Default local anon key.
fn anon_key() -> String {
    std::env::var("SUPABASE_ANON_KEY").unwrap_or_else(|_| {
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0".to_string()
    })
}

/// Default local service_role key.
fn service_role_key() -> String {
    std::env::var("SUPABASE_SERVICE_ROLE_KEY").unwrap_or_else(|_| {
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU".to_string()
    })
}

fn auth_client() -> AuthClient {
    AuthClient::new(&supabase_url(), &anon_key()).expect("Failed to create AuthClient")
}

fn admin_auth_client() -> AuthClient {
    AuthClient::new(&supabase_url(), &service_role_key()).expect("Failed to create admin AuthClient")
}

/// Generate a unique test email to avoid collisions between test runs.
fn test_email(suffix: &str) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    format!("test-{}+{}@example.com", suffix, ts)
}

/// Helper: create a user via admin and return their ID, cleaning up after test.
async fn create_test_user(admin: &AdminClient<'_>, email: &str, password: &str) -> User {
    admin
        .create_user(AdminCreateUserParams {
            email: Some(email.to_string()),
            password: Some(password.to_string()),
            email_confirm: Some(true),
            ..Default::default()
        })
        .await
        .expect("Admin create_user failed")
}

/// Helper: delete a user, ignoring errors (best-effort cleanup).
async fn cleanup_user(admin: &AdminClient<'_>, user_id: &str) {
    let _ = admin.delete_user(user_id).await;
}

// ─── Unit Tests (no server needed) ────────────────────────────

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn auth_client_new_ok() {
        let client = AuthClient::new("https://example.supabase.co", "test-key");
        assert!(client.is_ok());
    }

    #[test]
    fn auth_client_base_url() {
        let client = AuthClient::new("https://example.supabase.co", "test-key").unwrap();
        assert_eq!(client.base_url().path(), "/auth/v1");
    }

    #[test]
    fn oauth_url_google() {
        let client = AuthClient::new("https://example.supabase.co", "test-key").unwrap();
        let url = client
            .get_oauth_sign_in_url(OAuthProvider::Google, None, None)
            .unwrap();
        assert!(url.contains("/auth/v1/authorize"));
        assert!(url.contains("provider=google"));
    }

    #[test]
    fn oauth_url_with_redirect_and_scopes() {
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
    fn oauth_url_custom_provider() {
        let client = AuthClient::new("https://example.supabase.co", "test-key").unwrap();
        let url = client
            .get_oauth_sign_in_url(OAuthProvider::Custom("myidp".into()), None, None)
            .unwrap();
        assert!(url.contains("provider=myidp"));
    }

    #[test]
    fn auth_error_display() {
        let err = AuthError::InvalidConfig("missing url".into());
        assert!(err.to_string().contains("missing url"));

        let err = AuthError::SessionExpired;
        assert_eq!(err.to_string(), "Session expired");

        let err = AuthError::NoSession;
        assert_eq!(err.to_string(), "No active session");
    }

    #[test]
    fn auth_error_into_supabase_error() {
        use supabase_client_core::SupabaseError;
        let auth_err = AuthError::InvalidConfig("test".into());
        let sup_err: SupabaseError = auth_err.into();
        match sup_err {
            SupabaseError::Auth(msg) => assert!(msg.contains("test")),
            _ => panic!("Expected SupabaseError::Auth"),
        }
    }

    #[test]
    fn sign_out_scope_display() {
        assert_eq!(SignOutScope::Local.to_string(), "local");
        assert_eq!(SignOutScope::Others.to_string(), "others");
        assert_eq!(SignOutScope::Global.to_string(), "global");
    }
}

// ─── Integration Tests (require running Supabase) ─────────────

#[cfg(test)]
mod integration {
    use super::*;
    use serde_json::json;

    // ─── Sign Up ───────────────────────────────────────────

    #[tokio::test]
    async fn sign_up_with_email() {
        let auth = auth_client();
        let admin = admin_auth_client();
        let email = test_email("signup");

        let resp = auth.sign_up_with_email(&email, "password123456").await;
        assert!(resp.is_ok(), "sign_up_with_email failed: {:?}", resp.err());

        let auth_resp = resp.unwrap();
        // With email confirmations disabled, we should get a session
        assert!(auth_resp.session.is_some() || auth_resp.user.is_some());

        // Cleanup
        if let Some(session) = &auth_resp.session {
            cleanup_user(&admin.admin(), &session.user.id).await;
        } else if let Some(user) = &auth_resp.user {
            cleanup_user(&admin.admin(), &user.id).await;
        }
    }

    #[tokio::test]
    async fn sign_up_with_email_and_metadata() {
        let auth = auth_client();
        let admin = admin_auth_client();
        let email = test_email("signup-meta");

        let metadata = json!({"display_name": "Test User", "role": "tester"});
        let resp = auth
            .sign_up_with_email_and_data(&email, "password123456", Some(metadata))
            .await;
        assert!(resp.is_ok(), "sign_up_with_email_and_data failed: {:?}", resp.err());

        let auth_resp = resp.unwrap();
        // Verify metadata was set
        if let Some(session) = &auth_resp.session {
            let user_meta = session.user.user_metadata.as_ref();
            assert!(user_meta.is_some());
            assert_eq!(
                user_meta.unwrap().get("display_name").and_then(|v| v.as_str()),
                Some("Test User")
            );
            cleanup_user(&admin.admin(), &session.user.id).await;
        } else if let Some(user) = &auth_resp.user {
            cleanup_user(&admin.admin(), &user.id).await;
        }
    }

    // ─── Sign In ───────────────────────────────────────────

    #[tokio::test]
    async fn sign_in_with_password_email() {
        let auth = auth_client();
        let admin = admin_auth_client();
        let email = test_email("signin");
        let password = "password123456";

        // Create user via admin (auto-confirm email)
        let user = create_test_user(&admin.admin(), &email, password).await;

        // Sign in
        let session = auth.sign_in_with_password_email(&email, password).await;
        assert!(session.is_ok(), "sign_in failed: {:?}", session.err());

        let session = session.unwrap();
        assert!(!session.access_token.is_empty());
        assert!(!session.refresh_token.is_empty());
        assert!(session.expires_in > 0);
        assert_eq!(session.user.email.as_deref(), Some(email.as_str()));

        cleanup_user(&admin.admin(), &user.id).await;
    }

    #[tokio::test]
    async fn sign_in_invalid_credentials() {
        let auth = auth_client();

        let result = auth
            .sign_in_with_password_email("nonexistent@example.com", "wrongpassword")
            .await;
        assert!(result.is_err());

        match result.unwrap_err() {
            AuthError::Api { status, .. } => {
                assert!(status == 400 || status == 401, "Expected 400 or 401, got {}", status);
            }
            other => panic!("Expected AuthError::Api, got {:?}", other),
        }
    }

    // ─── Get User ──────────────────────────────────────────

    #[tokio::test]
    async fn get_user() {
        let auth = auth_client();
        let admin = admin_auth_client();
        let email = test_email("getuser");
        let password = "password123456";

        let user = create_test_user(&admin.admin(), &email, password).await;
        let session = auth.sign_in_with_password_email(&email, password).await.unwrap();

        let fetched_user = auth.get_user(&session.access_token).await;
        assert!(fetched_user.is_ok(), "get_user failed: {:?}", fetched_user.err());

        let fetched_user = fetched_user.unwrap();
        assert_eq!(fetched_user.id, user.id);
        assert_eq!(fetched_user.email.as_deref(), Some(email.as_str()));

        cleanup_user(&admin.admin(), &user.id).await;
    }

    // ─── Update User ───────────────────────────────────────

    #[tokio::test]
    async fn update_user_metadata() {
        let auth = auth_client();
        let admin = admin_auth_client();
        let email = test_email("updateuser");
        let password = "password123456";

        let user = create_test_user(&admin.admin(), &email, password).await;
        let session = auth.sign_in_with_password_email(&email, password).await.unwrap();

        let updated = auth
            .update_user(
                &session.access_token,
                UpdateUserParams {
                    data: Some(json!({"favorite_color": "blue"})),
                    ..Default::default()
                },
            )
            .await;
        assert!(updated.is_ok(), "update_user failed: {:?}", updated.err());

        let updated = updated.unwrap();
        let meta = updated.user_metadata.as_ref().unwrap();
        assert_eq!(
            meta.get("favorite_color").and_then(|v| v.as_str()),
            Some("blue")
        );

        cleanup_user(&admin.admin(), &user.id).await;
    }

    // ─── Refresh Session ───────────────────────────────────

    #[tokio::test]
    async fn refresh_session() {
        let auth = auth_client();
        let admin = admin_auth_client();
        let email = test_email("refresh");
        let password = "password123456";

        let user = create_test_user(&admin.admin(), &email, password).await;
        let session = auth.sign_in_with_password_email(&email, password).await.unwrap();

        let new_session = auth.refresh_session(&session.refresh_token).await;
        assert!(new_session.is_ok(), "refresh_session failed: {:?}", new_session.err());

        let new_session = new_session.unwrap();
        assert!(!new_session.access_token.is_empty());
        assert!(!new_session.refresh_token.is_empty());

        cleanup_user(&admin.admin(), &user.id).await;
    }

    // ─── Sign Out ──────────────────────────────────────────

    #[tokio::test]
    async fn sign_out() {
        let auth = auth_client();
        let admin = admin_auth_client();
        let email = test_email("signout");
        let password = "password123456";

        let user = create_test_user(&admin.admin(), &email, password).await;
        let session = auth.sign_in_with_password_email(&email, password).await.unwrap();

        let result = auth.sign_out(&session.access_token).await;
        assert!(result.is_ok(), "sign_out failed: {:?}", result.err());

        cleanup_user(&admin.admin(), &user.id).await;
    }

    #[tokio::test]
    async fn sign_out_with_local_scope() {
        let auth = auth_client();
        let admin = admin_auth_client();
        let email = test_email("signout-local");
        let password = "password123456";

        let user = create_test_user(&admin.admin(), &email, password).await;
        let session = auth.sign_in_with_password_email(&email, password).await.unwrap();

        let result = auth
            .sign_out_with_scope(&session.access_token, SignOutScope::Local)
            .await;
        assert!(result.is_ok(), "sign_out local failed: {:?}", result.err());

        cleanup_user(&admin.admin(), &user.id).await;
    }

    // ─── Password Recovery ─────────────────────────────────

    #[tokio::test]
    async fn reset_password_for_email() {
        let auth = auth_client();
        let admin = admin_auth_client();
        let email = test_email("reset");
        let password = "password123456";

        let user = create_test_user(&admin.admin(), &email, password).await;

        // Should succeed (sends email via inbucket locally)
        let result = auth.reset_password_for_email(&email, None).await;
        assert!(result.is_ok(), "reset_password failed: {:?}", result.err());

        cleanup_user(&admin.admin(), &user.id).await;
    }

    // ─── Anonymous Sign In ─────────────────────────────────

    #[tokio::test]
    async fn sign_in_anonymous() {
        let auth = auth_client();
        let admin = admin_auth_client();

        let session = auth.sign_in_anonymous().await;
        assert!(session.is_ok(), "sign_in_anonymous failed: {:?}", session.err());

        let session = session.unwrap();
        assert!(!session.access_token.is_empty());
        assert!(session.user.is_anonymous.unwrap_or(false));

        cleanup_user(&admin.admin(), &session.user.id).await;
    }

    // ─── Admin: List Users ─────────────────────────────────

    #[tokio::test]
    async fn admin_list_users() {
        let admin = admin_auth_client();

        let result = admin.admin().list_users(None, None).await;
        assert!(result.is_ok(), "admin list_users failed: {:?}", result.err());

        let list = result.unwrap();
        // Verify we got a valid response
        let _ = list.users.len();
    }

    // ─── Admin: Create, Get, Update, Delete ────────────────

    #[tokio::test]
    async fn admin_crud_user() {
        let admin_client = admin_auth_client();
        let admin = admin_client.admin();
        let email = test_email("admin-crud");

        // Create
        let user = admin
            .create_user(AdminCreateUserParams {
                email: Some(email.clone()),
                password: Some("admin-test-pass123".to_string()),
                email_confirm: Some(true),
                user_metadata: Some(json!({"role": "admin-test"})),
                ..Default::default()
            })
            .await;
        assert!(user.is_ok(), "admin create_user failed: {:?}", user.err());
        let user = user.unwrap();
        assert_eq!(user.email.as_deref(), Some(email.as_str()));

        // Get by ID
        let fetched = admin.get_user_by_id(&user.id).await;
        assert!(fetched.is_ok(), "admin get_user_by_id failed: {:?}", fetched.err());
        let fetched = fetched.unwrap();
        assert_eq!(fetched.id, user.id);

        // Update
        let updated = admin
            .update_user_by_id(
                &user.id,
                AdminUpdateUserParams {
                    user_metadata: Some(json!({"role": "updated"})),
                    ..Default::default()
                },
            )
            .await;
        assert!(updated.is_ok(), "admin update_user_by_id failed: {:?}", updated.err());
        let updated = updated.unwrap();
        let meta = updated.user_metadata.as_ref().unwrap();
        assert_eq!(meta.get("role").and_then(|v| v.as_str()), Some("updated"));

        // Delete
        let deleted = admin.delete_user(&user.id).await;
        assert!(deleted.is_ok(), "admin delete_user failed: {:?}", deleted.err());

        // Verify deleted — get should fail
        let get_after_delete = admin.get_user_by_id(&user.id).await;
        assert!(get_after_delete.is_err());
    }

    // ─── Admin: List with pagination ───────────────────────

    #[tokio::test]
    async fn admin_list_users_paginated() {
        let admin_client = admin_auth_client();
        let admin = admin_client.admin();

        // Create a few users
        let mut user_ids = Vec::new();
        for i in 0..3 {
            let email = test_email(&format!("admin-list-{}", i));
            let user = create_test_user(&admin, &email, "password123456").await;
            user_ids.push(user.id);
        }

        // List with pagination
        let result = admin.list_users(Some(1), Some(2)).await;
        assert!(result.is_ok(), "admin list_users paginated failed: {:?}", result.err());

        // Cleanup
        for id in &user_ids {
            cleanup_user(&admin, id).await;
        }
    }

    // ─── Full Flow: Sign up → Sign in → Get User → Update → Refresh → Sign out ───

    #[tokio::test]
    async fn full_auth_flow() {
        let auth = auth_client();
        let admin = admin_auth_client();
        let email = test_email("full-flow");
        let password = "password123456";

        // 1. Sign up
        let signup = auth.sign_up_with_email(&email, password).await;
        assert!(signup.is_ok(), "signup failed: {:?}", signup.err());
        let signup = signup.unwrap();

        let user_id = signup
            .session
            .as_ref()
            .map(|s| s.user.id.clone())
            .or_else(|| signup.user.as_ref().map(|u| u.id.clone()))
            .expect("No user in signup response");

        // 2. Sign in
        let session = auth.sign_in_with_password_email(&email, password).await;
        assert!(session.is_ok(), "signin failed: {:?}", session.err());
        let session = session.unwrap();

        // 3. Get user
        let user = auth.get_user(&session.access_token).await;
        assert!(user.is_ok(), "get_user failed: {:?}", user.err());
        let user = user.unwrap();
        assert_eq!(user.email.as_deref(), Some(email.as_str()));

        // 4. Update user metadata
        let updated = auth
            .update_user(
                &session.access_token,
                UpdateUserParams {
                    data: Some(json!({"test_key": "test_value"})),
                    ..Default::default()
                },
            )
            .await;
        assert!(updated.is_ok(), "update_user failed: {:?}", updated.err());

        // 5. Refresh session
        let refreshed = auth.refresh_session(&session.refresh_token).await;
        assert!(refreshed.is_ok(), "refresh failed: {:?}", refreshed.err());

        // 6. Sign out
        let signout = auth
            .sign_out(&refreshed.unwrap().access_token)
            .await;
        assert!(signout.is_ok(), "signout failed: {:?}", signout.err());

        // Cleanup
        cleanup_user(&admin.admin(), &user_id).await;
    }
}
