//! Typed queries using the derive macro.
//!
//! Run with: cargo run --example typed_queries -p supabase-client-sdk
//!
//! Requires: `supabase start` in the project root.

use serde::Deserialize;
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

// Typed struct for the `cities` table.
// The derive macro generates the `Table` trait implementation.
#[derive(Debug, Deserialize, Table)]
#[table(name = "cities")]
struct City {
    #[primary_key(auto_generate)]
    pub id: i32,
    pub name: String,
    pub country_id: i32,
    pub population: Option<i64>,
    pub is_capital: Option<bool>,
}

// Typed struct for deserialization only (no derive macro needed for read-only).
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Country {
    pub id: i32,
    pub name: String,
    pub code: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = create_client();

    // Reset test data
    client.rpc("reset_test_data", json!({}))?.execute().await;

    // ── Typed SELECT — get all cities as City structs ──
    println!("=== Typed SELECT: all cities ===");
    let resp = client
        .from_typed::<City>()
        .select()
        .execute()
        .await;
    for city in resp.into_result()? {
        println!(
            "  {} (pop: {}, capital: {})",
            city.name,
            city.population.unwrap_or(0),
            city.is_capital.unwrap_or(false),
        );
    }

    // ── Typed SELECT with filter ──
    println!("\n=== Typed SELECT: capitals only ===");
    let resp = client
        .from_typed::<City>()
        .select()
        .is("is_capital", IsValue::True)
        .order("name", OrderDirection::Ascending)
        .execute()
        .await;
    for city in resp.into_result()? {
        println!("  {} (pop: {})", city.name, city.population.unwrap_or(0));
    }

    // ── Typed RPC call ──
    println!("\n=== Typed RPC: cities in New Zealand ===");
    let nz = client
        .from("countries")
        .select("id")
        .eq("name", "New Zealand")
        .single()
        .execute()
        .await;
    let nz_id = nz.into_single()?.get_as::<i64>("id").unwrap();

    let resp = client
        .rpc_typed::<City>("get_cities_by_country", json!({"p_country_id": nz_id}))?
        .execute()
        .await;
    for city in resp.into_result()? {
        println!("  {} (pop: {})", city.name, city.population.unwrap_or(0));
    }

    // ── Dynamic query with manual deserialization ──
    println!("\n=== Dynamic query → manual deserialize to Country ===");
    let resp = client
        .from("countries")
        .select("*")
        .order("name", OrderDirection::Ascending)
        .execute()
        .await;
    let json_rows = resp.into_result()?;
    for row in &json_rows {
        // Row implements Serialize, so we can convert it to serde_json::Value
        let val = serde_json::to_value(row)?;
        let country: Country = serde_json::from_value(val)?;
        println!("  {} ({})", country.name, country.code);
    }

    println!("\nDone!");
    Ok(())
}
