//! Full SDK demo: all features (query, auth, realtime, storage, functions) in one example.
//!
//! Run with: cargo run --example full_client -p supabase-client-sdk --features full
//!
//! Requires:
//!   1. `supabase start` in the project root
//!   2. `supabase functions serve` (in a separate terminal, for the functions section)

use serde_json::json;
use supabase_client_sdk::prelude::*;

const DEFAULT_URL: &str = "http://127.0.0.1:64321";
const DEFAULT_KEY: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU";
const ANON_KEY: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("SUPABASE_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    let service_key =
        std::env::var("SUPABASE_SERVICE_ROLE_KEY").unwrap_or_else(|_| DEFAULT_KEY.to_string());
    let anon_key = std::env::var("SUPABASE_ANON_KEY").unwrap_or_else(|_| ANON_KEY.to_string());

    // Service-role client (for admin operations, queries, storage)
    let config = SupabaseConfig::new(&url, &service_key);
    let client = SupabaseClient::new(config)?;

    // Anon client (for user-facing auth)
    let anon_config = SupabaseConfig::new(&url, &anon_key);
    let anon_client = SupabaseClient::new(anon_config)?;

    // ── 1. Query Builder ───────────────────────────────────────
    println!("═══ Query Builder ═══");

    // Reset test data
    client.rpc("reset_test_data", json!({}))?.execute().await;

    let resp = client
        .from("cities")
        .select("name, population")
        .order("population", OrderDirection::Descending)
        .limit(3)
        .execute()
        .await;
    println!("Top 3 cities by population:");
    for row in resp.into_result()? {
        println!(
            "  {} — {}",
            row.get_as::<String>("name").unwrap(),
            row.get_as::<i64>("population").unwrap_or(0),
        );
    }

    let resp = client
        .from("cities")
        .select("*")
        .count()
        .head()
        .execute()
        .await;
    println!("Total cities: {}", resp.count.unwrap_or(0));

    // ── 2. Auth ────────────────────────────────────────────────
    println!("\n═══ Auth ═══");

    let auth = anon_client.auth()?;
    let service_auth = client.auth()?;
    let admin = service_auth.admin();

    // Clean up previous test user
    let email = "full-client-example@test.local";
    if let Ok(resp) = admin.list_users(None, None).await {
        for u in resp.users {
            if u.email.as_deref() == Some(email) {
                let _ = admin.delete_user(&u.id).await;
            }
        }
    }

    let sign_up = auth.sign_up_with_email(email, "test-password-123").await?;
    println!("Signed up user: {}", sign_up.user.as_ref().map(|u| u.id.as_str()).unwrap_or("?"));

    let session = auth
        .sign_in_with_password_email(email, "test-password-123")
        .await?;
    println!("Session token: {}...", &session.access_token[..20]);

    let claims = AuthClient::get_claims(&session.access_token)?;
    println!("JWT role: {}", claims["role"]);

    auth.sign_out_current().await?;
    println!("Signed out.");

    // Clean up
    if let Some(user) = sign_up.user.as_ref() {
        let _ = admin.delete_user(&user.id).await;
    }

    // ── 3. Realtime ────────────────────────────────────────────
    println!("\n═══ Realtime ═══");

    let realtime = client.realtime()?;
    realtime.connect().await?;
    println!("Connected: {}", realtime.is_connected());

    // Broadcast self-send
    let (tx, rx) = tokio::sync::oneshot::channel::<serde_json::Value>();
    let tx = std::sync::Mutex::new(Some(tx));

    let channel = realtime
        .channel("full-example")
        .broadcast_self(true)
        .on_broadcast("ping", move |payload| {
            if let Some(tx) = tx.lock().unwrap().take() {
                let _ = tx.send(payload);
            }
        })
        .subscribe(|status, _err| {
            println!("  Channel status: {:?}", status);
        })
        .await?;

    // Small delay to let the subscription settle
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    channel
        .send_broadcast("ping", json!({"msg": "hello from full_client"}))
        .await?;

    match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
        Ok(Ok(payload)) => println!("Broadcast received: {}", payload),
        _ => println!("  (broadcast timed out — this is normal in some environments)"),
    }

    realtime.remove_all_channels().await?;
    realtime.disconnect().await?;
    println!("Disconnected.");

    // ── 4. Storage ─────────────────────────────────────────────
    println!("\n═══ Storage ═══");

    let storage = client.storage()?;
    let bucket_name = "full-client-example";

    // Clean up from previous runs
    let _ = storage.empty_bucket(bucket_name).await;
    let _ = storage.delete_bucket(bucket_name).await;

    storage
        .create_bucket(bucket_name, BucketOptions::new().public(true))
        .await?;
    println!("Created bucket: {}", bucket_name);

    let buckets = storage.list_buckets().await?;
    println!(
        "Buckets: {}",
        buckets
            .iter()
            .map(|b| b.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let file_api = storage.from(bucket_name);
    file_api
        .upload(
            "hello.txt",
            b"Hello from the full SDK example!".to_vec(),
            FileOptions::new().content_type("text/plain"),
        )
        .await?;
    println!("Uploaded hello.txt");

    let data = file_api.download("hello.txt").await?;
    println!("Downloaded: {} bytes", data.len());

    let public_url = file_api.get_public_url("hello.txt");
    println!("Public URL: {}", public_url);

    // Clean up
    file_api.remove(vec!["hello.txt"]).await?;
    storage.empty_bucket(bucket_name).await?;
    storage.delete_bucket(bucket_name).await?;
    println!("Cleaned up bucket.");

    // ── 5. Edge Functions ──────────────────────────────────────
    println!("\n═══ Edge Functions ═══");

    let functions = client.functions()?;
    let resp = functions
        .invoke(
            "hello",
            InvokeOptions::new().body(json!({"name": "Full Client Example"})),
        )
        .await;
    match resp {
        Ok(r) => {
            println!("Status: {}", r.status());
            let body: serde_json::Value = r.json()?;
            println!("Response: {}", body);
        }
        Err(e) => println!(
            "Edge function error (is `supabase functions serve` running?): {}",
            e
        ),
    }

    // Reset test data
    client.rpc("reset_test_data", json!({}))?.execute().await;

    println!("\n═══ Done! ═══");
    Ok(())
}
