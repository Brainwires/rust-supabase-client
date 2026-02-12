//! Basic query builder usage against a local Supabase instance.
//!
//! Run with: cargo run --example query_basics -p supabase-client-sdk
//!
//! Requires: `supabase start` in the project root.

use serde_json::json;
use supabase_client_sdk::prelude::*;

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

    // Reset test data to a known state
    client.rpc("reset_test_data", json!({}))?.execute().await;

    // ── SELECT all rows ──
    println!("=== SELECT all cities ===");
    let resp = client.from("cities").select("*").execute().await;
    for row in resp.into_result()? {
        println!(
            "  {} (pop: {})",
            row.get_as::<String>("name").unwrap(),
            row.get_as::<i64>("population").unwrap_or(0),
        );
    }

    // ── SELECT with filters ──
    println!("\n=== Cities with population > 1,000,000 ===");
    let resp = client
        .from("cities")
        .select("name, population")
        .gt("population", 1_000_000_i64)
        .order("population", OrderDirection::Descending)
        .execute()
        .await;
    for row in resp.into_result()? {
        println!(
            "  {} — {}",
            row.get_as::<String>("name").unwrap(),
            row.get_as::<i64>("population").unwrap_or(0),
        );
    }

    // ── SELECT with limit and range ──
    println!("\n=== First 2 cities alphabetically ===");
    let resp = client
        .from("cities")
        .select("name")
        .order("name", OrderDirection::Ascending)
        .limit(2)
        .execute()
        .await;
    for row in resp.into_result()? {
        println!("  {}", row.get_as::<String>("name").unwrap());
    }

    // ── SELECT single row ──
    println!("\n=== Single city: Tokyo ===");
    let resp = client
        .from("cities")
        .select("*")
        .eq("name", "Tokyo")
        .single()
        .execute()
        .await;
    let tokyo = resp.into_single()?;
    println!(
        "  {} — capital: {}, pop: {}",
        tokyo.get_as::<String>("name").unwrap(),
        tokyo.get_as::<bool>("is_capital").unwrap_or(false),
        tokyo.get_as::<i64>("population").unwrap_or(0),
    );

    // ── SELECT with count ──
    println!("\n=== Count of capital cities ===");
    let resp = client
        .from("cities")
        .select("*")
        .is("is_capital", IsValue::True)
        .count()
        .execute()
        .await;
    println!("  {} capitals", resp.count.unwrap_or(0));

    // ── SELECT with various filters ──
    println!("\n=== Cities with LIKE filter (%land%) ===");
    let resp = client
        .from("cities")
        .select("name")
        .like("name", "%land%")
        .execute()
        .await;
    for row in resp.into_result()? {
        println!("  {}", row.get_as::<String>("name").unwrap());
    }

    println!("\n=== Cities IN (Tokyo, Sydney) ===");
    let resp = client
        .from("cities")
        .select("name")
        .in_("name", vec!["Tokyo", "Sydney"])
        .execute()
        .await;
    for row in resp.into_result()? {
        println!("  {}", row.get_as::<String>("name").unwrap());
    }

    // ── INSERT a new row ──
    println!("\n=== INSERT a new city ===");
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
        .insert(row![
            ("name", "Christchurch"),
            ("country_id", nz_id),
            ("population", 380000_i64),
            ("is_capital", false)
        ])
        .select()
        .execute()
        .await;
    let inserted = resp.into_result()?;
    println!("  Inserted: {}", inserted[0].get_as::<String>("name").unwrap());

    // ── UPDATE a row ──
    println!("\n=== UPDATE Wellington's name ===");
    let resp = client
        .from("cities")
        .update(row![("name", "Middle Earth")])
        .eq("name", "Wellington")
        .select()
        .execute()
        .await;
    let updated = resp.into_result()?;
    println!("  Updated to: {}", updated[0].get_as::<String>("name").unwrap());

    // ── DELETE a row ──
    println!("\n=== DELETE Christchurch ===");
    let resp = client
        .from("cities")
        .delete()
        .eq("name", "Christchurch")
        .select()
        .execute()
        .await;
    let deleted = resp.into_result()?;
    println!("  Deleted: {}", deleted[0].get_as::<String>("name").unwrap());

    // ── UPSERT ──
    println!("\n=== UPSERT a city ===");
    let resp = client
        .from("cities")
        .upsert(row![
            ("name", "Dunedin"),
            ("country_id", nz_id),
            ("population", 130000_i64),
            ("is_capital", false)
        ])
        .select()
        .execute()
        .await;
    let upserted = resp.into_result()?;
    println!("  Upserted: {}", upserted[0].get_as::<String>("name").unwrap());

    // Reset data back to original state
    client.rpc("reset_test_data", json!({}))?.execute().await;

    println!("\nDone!");
    Ok(())
}
