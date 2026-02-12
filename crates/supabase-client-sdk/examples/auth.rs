//! Authentication example: sign-up, sign-in, sessions, and admin operations.
//!
//! Run with: cargo run --example auth -p supabase-client-sdk --features auth
//!
//! Requires: `supabase start` in the project root.

use supabase_client_sdk::prelude::*;

const DEFAULT_URL: &str = "http://127.0.0.1:64321";
const DEFAULT_KEY: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU";
const ANON_KEY: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a client with the anon key (for user-facing auth)
    let url = std::env::var("SUPABASE_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    let anon = std::env::var("SUPABASE_ANON_KEY").unwrap_or_else(|_| ANON_KEY.to_string());
    let service = std::env::var("SUPABASE_SERVICE_ROLE_KEY").unwrap_or_else(|_| DEFAULT_KEY.to_string());

    let config = SupabaseConfig::new(&url, &anon);
    let client = SupabaseClient::new(config)?;
    let auth = client.auth()?;

    // Use admin client to clean up any existing test user
    let service_config = SupabaseConfig::new(&url, &service);
    let service_client = SupabaseClient::new(service_config)?;
    let service_auth = service_client.auth()?;
    let admin = service_auth.admin();

    // Clean up previous test user if exists
    let email = "example-test@example.com";
    let password = "test-password-123!";
    if let Ok(users) = admin.list_users(None, None).await {
        for user in &users.users {
            if user.email.as_deref() == Some(email) {
                let _ = admin.delete_user(&user.id).await;
            }
        }
    }

    // ── Sign up a new user ──
    println!("=== Sign up ===");
    let signup = auth.sign_up_with_email(email, password).await?;
    println!(
        "  User created: {} (email: {:?})",
        signup.user.as_ref().map(|u| u.id.as_str()).unwrap_or("?"),
        signup.user.as_ref().and_then(|u| u.email.as_deref()),
    );

    // ── Sign in with password ──
    println!("\n=== Sign in ===");
    let session = auth.sign_in_with_password_email(email, password).await?;
    println!("  Signed in! Token type: {}", session.token_type);
    println!("  Access token: {}...", &session.access_token[..20]);
    println!("  User ID: {}", session.user.id);

    // ── Session management ──
    println!("\n=== Session state ===");
    let stored = auth.get_session().await;
    println!(
        "  Session stored: {}",
        stored.is_some(),
    );

    // ── JWT claims extraction ──
    println!("\n=== JWT claims ===");
    let claims = AuthClient::get_claims(&session.access_token)?;
    println!("  Role: {}", claims.get("role").unwrap_or(&serde_json::Value::Null));
    println!("  Issuer: {}", claims.get("iss").unwrap_or(&serde_json::Value::Null));

    // ── Get current user ──
    println!("\n=== Get user ===");
    let user = auth.get_user(&session.access_token).await?;
    println!("  Email: {:?}", user.email);
    println!("  Role: {:?}", user.role);

    // ── Auth state change events ──
    println!("\n=== Auth state events ===");
    let mut sub = auth.on_auth_state_change();
    // Sign out triggers an event
    auth.sign_out_current().await?;
    println!("  Signed out");

    // Check if event was emitted (non-blocking)
    match tokio::time::timeout(std::time::Duration::from_millis(100), sub.next()).await {
        Ok(Some(event)) => println!("  Event received: {:?}", event.event),
        _ => println!("  (no event within timeout)"),
    }

    // ── Admin operations ──
    println!("\n=== Admin: list users ===");
    let users = admin.list_users(None, None).await?;
    println!("  Total users: {}", users.users.len());

    // Clean up: delete the test user
    if let Some(user) = users.users.iter().find(|u| u.email.as_deref() == Some(email)) {
        admin.delete_user(&user.id).await?;
        println!("  Cleaned up test user");
    }

    println!("\nDone!");
    Ok(())
}
