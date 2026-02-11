//! Advanced query features: CSV, count options, RPC, explain, head, upsert options.
//!
//! Run with: cargo run --example advanced_queries -p supabase-client
//!
//! Requires: `supabase start` in the project root.

use serde_json::json;
use supabase_client::prelude::*;

const DEFAULT_URL: &str = "http://127.0.0.1:64321";
const DEFAULT_KEY: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU";

fn create_client() -> SupabaseClient {
    let url = std::env::var("SUPABASE_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    let key = std::env::var("SUPABASE_SERVICE_ROLE_KEY").unwrap_or_else(|_| DEFAULT_KEY.to_string());
    let config = SupabaseConfig::new(url, key);
    SupabaseClient::new(config).expect("Failed to create client")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = create_client();

    // Reset test data
    client.rpc("reset_test_data", json!({}))?.execute().await;

    // ── CSV output format ──
    println!("=== CSV format ===");
    let csv = client
        .from("cities")
        .select("name, population")
        .order("name", OrderDirection::Ascending)
        .csv()
        .execute()
        .await?;
    println!("{}", csv);

    // ── Count options ──
    println!("=== Exact count ===");
    let resp = client
        .from("cities")
        .select("*")
        .count()
        .execute()
        .await;
    println!("  Exact count: {:?}", resp.count);

    println!("\n=== Planned count (approximate, from query planner) ===");
    let resp = client
        .from("cities")
        .select("*")
        .count_option(CountOption::Planned)
        .execute()
        .await;
    println!("  Planned count: {:?}", resp.count);

    println!("\n=== Estimated count (from statistics) ===");
    let resp = client
        .from("cities")
        .select("*")
        .count_option(CountOption::Estimated)
        .execute()
        .await;
    println!("  Estimated count: {:?}", resp.count);

    // ── RPC calls ──
    println!("\n=== RPC: add_numbers(3, 7) ===");
    let resp = client
        .rpc("add_numbers", json!({"a": 3, "b": 7}))?
        .execute()
        .await;
    let rows = resp.into_result()?;
    println!("  Result: {}", rows[0].get_as::<i64>("add_numbers").unwrap());

    // ── RPC with rollback (dry-run mode) ──
    println!("\n=== RPC with rollback ===");
    let resp = client
        .rpc("add_numbers", json!({"a": 10, "b": 20}))?
        .rollback()
        .execute()
        .await;
    let rows = resp.into_result()?;
    println!("  Result (rolled back): {}", rows[0].get_as::<i64>("add_numbers").unwrap());

    // ── EXPLAIN query plan ──
    println!("\n=== EXPLAIN (default: ANALYZE + JSON) ===");
    let resp = client
        .from("cities")
        .select("*")
        .explain()
        .execute()
        .await;
    if resp.is_ok() {
        let rows = resp.into_result()?;
        if !rows.is_empty() {
            let plan = serde_json::to_string(&rows[0])?;
            println!("  Query plan received ({} bytes)", plan.len());
        }
    } else {
        println!("  (explain may not be available on this PostgREST version)");
    }

    // ── EXPLAIN with custom options ──
    println!("\n=== EXPLAIN with custom options ===");
    let opts = ExplainOptions {
        analyze: false,
        verbose: true,
        format: ExplainFormat::Text,
    };
    let resp = client
        .from("cities")
        .select("*")
        .explain_with(opts)
        .execute()
        .await;
    if resp.is_ok() {
        println!("  Custom explain plan received");
    } else {
        println!("  (explain may not be available on this PostgREST version)");
    }

    // ── HEAD (count-only mode) ──
    println!("\n=== HEAD (count-only mode) ===");
    let resp = client
        .from("cities")
        .select("*")
        .count()
        .head()
        .execute()
        .await;
    println!("  Count via HEAD: {:?}", resp.count);

    // ── Upsert with ignore_duplicates ──
    println!("\n=== Upsert with ignore_duplicates (ON CONFLICT DO NOTHING) ===");
    let nz = client
        .from("countries")
        .select("id")
        .eq("name", "New Zealand")
        .single()
        .execute()
        .await;
    let nz_id = nz.into_single()?.get_as::<i64>("id").unwrap();

    let resp = client
        .from("cities")
        .upsert(row![
            ("name", "Auckland"),
            ("country_id", nz_id),
            ("population", 9999_i64),
            ("is_capital", false)
        ])
        .ignore_duplicates()
        .select()
        .execute()
        .await;
    println!("  Upsert result rows: {}", resp.data.len());

    // Reset data
    client.rpc("reset_test_data", json!({}))?.execute().await;

    println!("\nDone!");
    Ok(())
}
