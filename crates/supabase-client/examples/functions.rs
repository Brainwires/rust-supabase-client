//! Edge Functions invocation example.
//!
//! Run with: cargo run --example functions -p supabase-client --features functions
//!
//! Requires:
//!   1. `supabase start` in the project root
//!   2. `supabase functions serve` (in a separate terminal)

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
    let functions = client.functions()?;

    // ── Invoke with JSON body ──
    println!("=== Invoke 'hello' with JSON body ===");
    let resp = functions
        .invoke(
            "hello",
            InvokeOptions::new().body(json!({"name": "Rust SDK"})),
        )
        .await;
    match resp {
        Ok(r) => {
            println!("  Status: {}", r.status());
            let body: serde_json::Value = r.json()?;
            println!("  Response: {}", body);
        }
        Err(e) => println!("  Error (is `supabase functions serve` running?): {}", e),
    }

    // ── Invoke with custom HTTP method ──
    println!("\n=== Invoke 'echo-method' with GET ===");
    let resp = functions
        .invoke(
            "echo-method",
            InvokeOptions::new().method(HttpMethod::Get),
        )
        .await;
    match resp {
        Ok(r) => {
            println!("  Status: {}", r.status());
            let text = r.text()?;
            println!("  Response: {}", text);
        }
        Err(e) => println!("  Error: {}", e),
    }

    // ── Invoke with custom headers ──
    println!("\n=== Invoke 'echo-headers' with custom header ===");
    let resp = functions
        .invoke(
            "echo-headers",
            InvokeOptions::new()
                .header("X-Custom-Header", "hello-from-rust"),
        )
        .await;
    match resp {
        Ok(r) => {
            println!("  Status: {}", r.status());
            let body: serde_json::Value = r.json()?;
            println!("  Response: {}", body);
        }
        Err(e) => println!("  Error: {}", e),
    }

    // ── Invoke with binary body ──
    println!("\n=== Invoke 'echo-binary' with binary body ===");
    let binary_data = vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]; // "Hello" in ASCII
    let resp = functions
        .invoke(
            "echo-binary",
            InvokeOptions::new().body_bytes(binary_data),
        )
        .await;
    match resp {
        Ok(r) => {
            println!("  Status: {}", r.status());
            println!("  Content-Type: {:?}", r.content_type());
            println!("  Body length: {} bytes", r.bytes().len());
        }
        Err(e) => println!("  Error: {}", e),
    }

    // ── Invoke with auth override ──
    println!("\n=== Invoke with custom auth ===");
    let resp = functions
        .invoke(
            "hello",
            InvokeOptions::new()
                .body(json!({"name": "Custom Auth"}))
                .authorization("Bearer custom-token-here"),
        )
        .await;
    match resp {
        Ok(r) => println!("  Status: {}", r.status()),
        Err(e) => println!("  Error: {}", e),
    }

    println!("\nDone!");
    Ok(())
}
