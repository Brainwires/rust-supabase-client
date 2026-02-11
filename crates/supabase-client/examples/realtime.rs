//! Realtime subscriptions: broadcast, presence, and postgres changes.
//!
//! Run with: cargo run --example realtime -p supabase-client --features realtime
//!
//! Requires: `supabase start` in the project root.

use serde_json::json;
use supabase_client::prelude::*;

const DEFAULT_URL: &str = "http://127.0.0.1:64321";
const DEFAULT_KEY: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("SUPABASE_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    let key = std::env::var("SUPABASE_SERVICE_ROLE_KEY").unwrap_or_else(|_| DEFAULT_KEY.to_string());
    let config = SupabaseConfig::new(&url, &key);
    let client = SupabaseClient::new(config)?;
    let realtime = client.realtime()?;

    // ── Connect to the Realtime server ──
    println!("=== Connecting to Realtime ===");
    realtime.connect().await?;
    println!("  Connected!");

    // ── Broadcast: send and receive messages ──
    println!("\n=== Broadcast (self-send) ===");
    let (tx, rx) = tokio::sync::oneshot::channel::<serde_json::Value>();
    let tx = std::sync::Mutex::new(Some(tx));

    let channel = realtime
        .channel("example-broadcast")
        .broadcast_self(true)
        .on_broadcast("greeting", move |payload| {
            if let Some(tx) = tx.lock().unwrap().take() {
                let _ = tx.send(payload);
            }
        })
        .subscribe(|status, err| {
            println!("  Broadcast channel status: {:?} (err: {:?})", status, err);
        })
        .await?;

    // Wait a moment for the channel to be ready
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Send a broadcast message
    channel
        .send_broadcast("greeting", json!({"message": "Hello from Rust!"}))
        .await?;
    println!("  Sent broadcast");

    // Receive the self-sent message
    match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
        Ok(Ok(payload)) => println!("  Received: {}", payload),
        _ => println!("  (no broadcast received within timeout)"),
    }

    // Clean up the broadcast channel
    realtime.remove_channel(&channel).await?;

    // ── Postgres Changes: listen for database changes ──
    println!("\n=== Postgres Changes listener ===");
    let (insert_tx, insert_rx) = tokio::sync::oneshot::channel::<String>();
    let insert_tx = std::sync::Mutex::new(Some(insert_tx));

    let _pg_channel = realtime
        .channel("example-db-changes")
        .on_postgres_changes(
            PostgresChangesEvent::Insert,
            PostgresChangesFilter::new("public", "realtime_test"),
            move |payload| {
                let name = payload
                    .record
                    .as_ref()
                    .and_then(|r| r.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                if let Some(tx) = insert_tx.lock().unwrap().take() {
                    let _ = tx.send(name);
                }
            },
        )
        .subscribe(|status, err| {
            println!("  DB changes channel status: {:?} (err: {:?})", status, err);
        })
        .await?;

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    println!("  Listening for INSERT on realtime_test...");
    println!("  (Insert a row into realtime_test via psql to trigger the callback)");

    // Wait briefly for a change — in practice you'd keep this running
    match tokio::time::timeout(std::time::Duration::from_secs(2), insert_rx).await {
        Ok(Ok(name)) => println!("  INSERT detected: {}", name),
        _ => println!("  (no INSERT detected within 2s — that's ok for a demo)"),
    }

    // ── Presence: track who's online ──
    println!("\n=== Presence ===");
    let presence_channel = realtime
        .channel("example-presence")
        .presence_key("user-123")
        .on_presence_sync(|state| {
            println!("  Presence sync: {} users online", state.len());
        })
        .subscribe(|status, err| {
            println!("  Presence channel status: {:?} (err: {:?})", status, err);
        })
        .await?;

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Track presence
    presence_channel
        .track(json!({"name": "Rust Example", "online_at": "now"}))
        .await?;
    println!("  Tracked presence for user-123");

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // ── Clean up ──
    println!("\n=== Cleanup ===");
    realtime.remove_all_channels().await?;
    realtime.disconnect().await?;
    println!("  Disconnected");

    println!("\nDone!");
    Ok(())
}
