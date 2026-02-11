//! Integration tests for the PostgREST REST API backend.
//!
//! These tests require a running local Supabase instance started via `supabase start`.
//! They test the query builder against PostgREST (the default REST backend).
//!
//! The tests use the `cities` and `countries` tables in the local Supabase instance.
//! See supabase/migrations/ for table setup.
//!
//! Run with: cargo test -p supabase-client-query --test rest_integration -- --test-threads=1

use serde::Deserialize;
use serde_json::json;
use supabase_client_core::{SupabaseClient, SupabaseConfig};
use supabase_client_query::{
    CountOption, Filterable, IsValue, Modifiable, OrderDirection, SupabaseClientQueryExt,
};

const SUPABASE_URL: &str = "http://127.0.0.1:64321";
const SERVICE_ROLE_KEY: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU";

fn supabase_url() -> String {
    std::env::var("SUPABASE_URL").unwrap_or_else(|_| SUPABASE_URL.to_string())
}

fn api_key() -> String {
    std::env::var("SUPABASE_SERVICE_ROLE_KEY").unwrap_or_else(|_| SERVICE_ROLE_KEY.to_string())
}

fn create_client() -> SupabaseClient {
    // Use service_role key to bypass RLS for testing
    let config = SupabaseConfig::new(supabase_url(), api_key());
    SupabaseClient::new(config).expect("Failed to create REST client")
}

/// Reset test data atomically via the `reset_test_data` SQL function.
/// This runs as a single transaction, eliminating race conditions
/// and duplicate-key errors when tests run in parallel.
async fn reset_data(client: &SupabaseClient) {
    let resp = client
        .rpc("reset_test_data", json!({}))
        .unwrap()
        .execute()
        .await;
    assert!(resp.is_ok(), "reset_test_data RPC failed: {:?}", resp.error);
}

// ============================================================
// SELECT TESTS
// ============================================================

#[tokio::test]
async fn rest_select_all() {
    let client = create_client();
    reset_data(&client).await;

    let resp = client.from("cities").select("*").execute().await;
    assert!(resp.is_ok(), "select_all failed: {:?}", resp.error);
    let rows = resp.into_result().unwrap();
    assert_eq!(rows.len(), 5);
}

#[tokio::test]
async fn rest_select_specific_columns() {
    let client = create_client();
    reset_data(&client).await;

    let resp = client
        .from("cities")
        .select("name, population")
        .execute()
        .await;
    assert!(resp.is_ok(), "select_columns failed: {:?}", resp.error);
    let rows = resp.into_result().unwrap();
    assert_eq!(rows.len(), 5);
    let first = &rows[0];
    assert!(first.contains("name"));
    assert!(first.contains("population"));
}

#[tokio::test]
async fn rest_select_with_eq_filter() {
    let client = create_client();
    reset_data(&client).await;

    let resp = client
        .from("cities")
        .select("*")
        .eq("name", "Tokyo")
        .execute()
        .await;
    assert!(resp.is_ok(), "eq filter failed: {:?}", resp.error);
    let rows = resp.into_result().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get_as::<String>("name").unwrap(), "Tokyo");
}

#[tokio::test]
async fn rest_select_with_neq_filter() {
    let client = create_client();
    reset_data(&client).await;

    let resp = client
        .from("cities")
        .select("*")
        .neq("name", "Tokyo")
        .execute()
        .await;
    assert!(resp.is_ok(), "neq filter failed: {:?}", resp.error);
    let rows = resp.into_result().unwrap();
    assert_eq!(rows.len(), 4);
}

#[tokio::test]
async fn rest_select_with_gt_filter() {
    let client = create_client();
    reset_data(&client).await;

    let resp = client
        .from("cities")
        .select("*")
        .gt("population", 1000000_i64)
        .execute()
        .await;
    assert!(resp.is_ok(), "gt filter failed: {:?}", resp.error);
    let rows = resp.into_result().unwrap();
    // Auckland (1.6M), Sydney (5.3M), Tokyo (13.9M)
    assert_eq!(rows.len(), 3);
}

#[tokio::test]
async fn rest_select_with_gte_lte_filter() {
    let client = create_client();
    reset_data(&client).await;

    let resp = client
        .from("cities")
        .select("*")
        .gte("population", 453000_i64)
        .lte("population", 5312000_i64)
        .execute()
        .await;
    assert!(resp.is_ok(), "gte/lte filter failed: {:?}", resp.error);
    let rows = resp.into_result().unwrap();
    // Auckland (1.6M), Canberra (453K), Sydney (5.3M)
    assert_eq!(rows.len(), 3);
}

#[tokio::test]
async fn rest_select_with_like_filter() {
    let client = create_client();
    reset_data(&client).await;

    let resp = client
        .from("cities")
        .select("*")
        .like("name", "%land%")
        .execute()
        .await;
    assert!(resp.is_ok(), "like filter failed: {:?}", resp.error);
    let rows = resp.into_result().unwrap();
    // Auckland
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get_as::<String>("name").unwrap(), "Auckland");
}

#[tokio::test]
async fn rest_select_with_ilike_filter() {
    let client = create_client();
    reset_data(&client).await;

    let resp = client
        .from("cities")
        .select("*")
        .ilike("name", "%LAND%")
        .execute()
        .await;
    assert!(resp.is_ok(), "ilike filter failed: {:?}", resp.error);
    let rows = resp.into_result().unwrap();
    assert_eq!(rows.len(), 1);
}

#[tokio::test]
async fn rest_select_with_in_filter() {
    let client = create_client();
    reset_data(&client).await;

    let resp = client
        .from("cities")
        .select("*")
        .in_("name", vec!["Tokyo", "Sydney"])
        .execute()
        .await;
    assert!(resp.is_ok(), "in filter failed: {:?}", resp.error);
    let rows = resp.into_result().unwrap();
    assert_eq!(rows.len(), 2);
}

#[tokio::test]
async fn rest_select_with_is_filter() {
    let client = create_client();
    reset_data(&client).await;

    let resp = client
        .from("cities")
        .select("*")
        .is("is_capital", IsValue::True)
        .execute()
        .await;
    assert!(resp.is_ok(), "is filter failed: {:?}", resp.error);
    let rows = resp.into_result().unwrap();
    // Wellington, Canberra, Tokyo
    assert_eq!(rows.len(), 3);
}

#[tokio::test]
async fn rest_select_with_order() {
    let client = create_client();
    reset_data(&client).await;

    let resp = client
        .from("cities")
        .select("name")
        .order("name", OrderDirection::Ascending)
        .execute()
        .await;
    assert!(resp.is_ok(), "order failed: {:?}", resp.error);
    let rows = resp.into_result().unwrap();
    let names: Vec<String> = rows
        .iter()
        .map(|r| r.get_as::<String>("name").unwrap())
        .collect();
    assert_eq!(
        names,
        vec!["Auckland", "Canberra", "Sydney", "Tokyo", "Wellington"]
    );
}

#[tokio::test]
async fn rest_select_with_order_desc() {
    let client = create_client();
    reset_data(&client).await;

    let resp = client
        .from("cities")
        .select("name")
        .order("name", OrderDirection::Descending)
        .execute()
        .await;
    assert!(resp.is_ok(), "order desc failed: {:?}", resp.error);
    let rows = resp.into_result().unwrap();
    let names: Vec<String> = rows
        .iter()
        .map(|r| r.get_as::<String>("name").unwrap())
        .collect();
    assert_eq!(
        names,
        vec!["Wellington", "Tokyo", "Sydney", "Canberra", "Auckland"]
    );
}

#[tokio::test]
async fn rest_select_with_limit() {
    let client = create_client();
    reset_data(&client).await;

    let resp = client
        .from("cities")
        .select("*")
        .order("name", OrderDirection::Ascending)
        .limit(2)
        .execute()
        .await;
    assert!(resp.is_ok(), "limit failed: {:?}", resp.error);
    let rows = resp.into_result().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get_as::<String>("name").unwrap(), "Auckland");
    assert_eq!(rows[1].get_as::<String>("name").unwrap(), "Canberra");
}

#[tokio::test]
async fn rest_select_with_range() {
    let client = create_client();
    reset_data(&client).await;

    let resp = client
        .from("cities")
        .select("name")
        .order("name", OrderDirection::Ascending)
        .range(1, 3) // rows 2-4 (offset 1, limit 3)
        .execute()
        .await;
    assert!(resp.is_ok(), "range failed: {:?}", resp.error);
    let rows = resp.into_result().unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].get_as::<String>("name").unwrap(), "Canberra");
    assert_eq!(rows[1].get_as::<String>("name").unwrap(), "Sydney");
    assert_eq!(rows[2].get_as::<String>("name").unwrap(), "Tokyo");
}

#[tokio::test]
async fn rest_select_single() {
    let client = create_client();
    reset_data(&client).await;

    let resp = client
        .from("cities")
        .select("*")
        .eq("name", "Tokyo")
        .single()
        .execute()
        .await;
    assert!(resp.is_ok(), "single failed: {:?}", resp.error);
    let city = resp.into_single().unwrap();
    assert_eq!(city.get_as::<String>("name").unwrap(), "Tokyo");
}

#[tokio::test]
async fn rest_select_with_count() {
    let client = create_client();
    reset_data(&client).await;

    let resp = client
        .from("cities")
        .select("*")
        .count()
        .execute()
        .await;
    assert!(resp.is_ok(), "count failed: {:?}", resp.error);
    assert_eq!(resp.count, Some(5));
}

// ============================================================
// INSERT TESTS
// ============================================================

#[tokio::test]
async fn rest_insert_single_row() {
    let client = create_client();
    reset_data(&client).await;

    // Get a country_id first
    let nz = client
        .from("countries")
        .select("id")
        .eq("name", "New Zealand")
        .single()
        .execute()
        .await;
    let nz_id = nz.into_single().unwrap().get_as::<i64>("id").unwrap();

    let resp = client
        .from("cities")
        .insert(supabase_client_core::row![
            ("name", "Christchurch"),
            ("country_id", nz_id),
            ("population", 380000_i64)
        ])
        .select()
        .execute()
        .await;
    assert!(resp.is_ok(), "insert failed: {:?}", resp.error);
    let rows = resp.into_result().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get_as::<String>("name").unwrap(), "Christchurch");
}

#[tokio::test]
async fn rest_insert_many_rows() {
    let client = create_client();
    reset_data(&client).await;

    let nz = client
        .from("countries")
        .select("id")
        .eq("name", "New Zealand")
        .single()
        .execute()
        .await;
    let nz_id = nz.into_single().unwrap().get_as::<i64>("id").unwrap();

    let rows = vec![
        supabase_client_core::row![("name", "Queenstown"), ("country_id", nz_id), ("population", 15000_i64)],
        supabase_client_core::row![("name", "Rotorua"), ("country_id", nz_id), ("population", 58000_i64)],
    ];
    let resp = client.from("cities").insert_many(rows).select().execute().await;
    assert!(resp.is_ok(), "insert_many failed: {:?}", resp.error);
    let data = resp.into_result().unwrap();
    assert_eq!(data.len(), 2);
}

// ============================================================
// UPDATE TESTS
// ============================================================

#[tokio::test]
async fn rest_update_with_filter() {
    let client = create_client();
    reset_data(&client).await;

    let resp = client
        .from("cities")
        .update(supabase_client_core::row![("name", "Middle Earth")])
        .eq("name", "Wellington")
        .select()
        .execute()
        .await;
    assert!(resp.is_ok(), "update failed: {:?}", resp.error);
    let rows = resp.into_result().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get_as::<String>("name").unwrap(), "Middle Earth");
}

// ============================================================
// DELETE TESTS
// ============================================================

#[tokio::test]
async fn rest_delete_with_filter() {
    let client = create_client();
    reset_data(&client).await;

    let resp = client
        .from("cities")
        .delete()
        .eq("name", "Tokyo")
        .select()
        .execute()
        .await;
    assert!(resp.is_ok(), "delete failed: {:?}", resp.error);
    let rows = resp.into_result().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get_as::<String>("name").unwrap(), "Tokyo");

    // Verify deletion
    let check = client.from("cities").select("*").execute().await;
    assert_eq!(check.into_result().unwrap().len(), 4);
}

// ============================================================
// UPSERT TESTS
// ============================================================

#[tokio::test]
async fn rest_upsert_insert_new() {
    let client = create_client();
    reset_data(&client).await;

    let nz = client
        .from("countries")
        .select("id")
        .eq("name", "New Zealand")
        .single()
        .execute()
        .await;
    let nz_id = nz.into_single().unwrap().get_as::<i64>("id").unwrap();

    // Insert a new city via upsert (name is unique if we set it up that way)
    let resp = client
        .from("cities")
        .upsert(supabase_client_core::row![
            ("name", "Dunedin"),
            ("country_id", nz_id),
            ("population", 130000_i64),
            ("is_capital", false)
        ])
        .select()
        .execute()
        .await;
    assert!(resp.is_ok(), "upsert insert failed: {:?}", resp.error);
    let rows = resp.into_result().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get_as::<String>("name").unwrap(), "Dunedin");
}

// ============================================================
// RPC TESTS
// ============================================================

#[tokio::test]
async fn rest_rpc_call() {
    let client = create_client();
    reset_data(&client).await;

    let nz = client
        .from("countries")
        .select("id")
        .eq("name", "New Zealand")
        .single()
        .execute()
        .await;
    let nz_id = nz.into_single().unwrap().get_as::<i64>("id").unwrap();

    let resp = client
        .rpc("get_cities_by_country", json!({"p_country_id": nz_id}))
        .unwrap()
        .execute()
        .await;
    assert!(resp.is_ok(), "rpc failed: {:?}", resp.error);
    let rows = resp.into_result().unwrap();
    assert_eq!(rows.len(), 2); // Auckland and Wellington
}

#[tokio::test]
async fn rest_rpc_scalar() {
    let client = create_client();

    let resp = client
        .rpc("add_numbers", json!({"a": 3, "b": 7}))
        .unwrap()
        .execute()
        .await;
    assert!(resp.is_ok(), "rpc scalar failed: {:?}", resp.error);
    let rows = resp.into_result().unwrap();
    assert_eq!(rows.len(), 1);
    // PostgREST returns bare scalar `10`; parser wraps it as {"add_numbers": 10}
    assert_eq!(rows[0].get_as::<i64>("add_numbers").unwrap(), 10);
}

// ============================================================
// TYPED QUERY TESTS (Deserialize only, no sqlx::FromRow needed)
// ============================================================

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CityRest {
    pub name: String,
    pub population: Option<i64>,
    pub is_capital: Option<bool>,
}

#[tokio::test]
async fn rest_typed_rpc() {
    let client = create_client();
    reset_data(&client).await;

    let nz = client
        .from("countries")
        .select("id")
        .eq("name", "New Zealand")
        .single()
        .execute()
        .await;
    let nz_id = nz.into_single().unwrap().get_as::<i64>("id").unwrap();

    let resp = client
        .rpc_typed::<CityRest>("get_cities_by_country", json!({"p_country_id": nz_id}))
        .unwrap()
        .execute()
        .await;
    assert!(resp.is_ok(), "typed rpc failed: {:?}", resp.error);
    let cities = resp.into_result().unwrap();
    assert_eq!(cities.len(), 2);
    assert!(cities.iter().any(|c| c.name == "Auckland"));
    assert!(cities.iter().any(|c| c.name == "Wellington"));
}

// ============================================================
// CSV FORMAT TESTS
// ============================================================

#[tokio::test]
async fn rest_csv_format() {
    let client = create_client();
    reset_data(&client).await;

    let csv = client
        .from("cities")
        .select("name, population")
        .order("name", OrderDirection::Ascending)
        .csv()
        .execute()
        .await;
    assert!(csv.is_ok(), "csv format failed: {:?}", csv.err());
    let csv_text = csv.unwrap();
    let lines: Vec<&str> = csv_text.trim().lines().collect();
    // Should have header row + 5 data rows
    assert_eq!(lines.len(), 6, "Expected 6 lines (header + 5 rows), got {}: {:?}", lines.len(), lines);
    assert!(lines[0].contains("name"), "Header should contain 'name'");
    assert!(lines[0].contains("population"), "Header should contain 'population'");
    assert!(lines[1].contains("Auckland"), "First data row should be Auckland");
}

// ============================================================
// COUNT OPTION TESTS
// ============================================================

#[tokio::test]
async fn rest_count_planned() {
    let client = create_client();
    reset_data(&client).await;

    let resp = client
        .from("cities")
        .select("*")
        .count_option(CountOption::Planned)
        .execute()
        .await;
    assert!(resp.is_ok(), "count planned failed: {:?}", resp.error);
    // Planned count may not be perfectly accurate, but should be > 0
    assert!(resp.count.is_some(), "Planned count should be present");
    assert!(resp.count.unwrap() > 0, "Planned count should be > 0");
}

#[tokio::test]
async fn rest_count_estimated() {
    let client = create_client();
    reset_data(&client).await;

    let resp = client
        .from("cities")
        .select("*")
        .count_option(CountOption::Estimated)
        .execute()
        .await;
    assert!(resp.is_ok(), "count estimated failed: {:?}", resp.error);
    // Estimated count should be present (may be 0 for small tables)
    assert!(resp.count.is_some(), "Estimated count should be present");
}

// ============================================================
// RPC ROLLBACK TEST
// ============================================================

#[tokio::test]
async fn rest_rpc_rollback() {
    let client = create_client();
    reset_data(&client).await;

    // Call add_numbers with rollback — function should still return a result
    // but any side effects would be rolled back (add_numbers has no side effects,
    // but the tx=rollback header should be accepted)
    let resp = client
        .rpc("add_numbers", json!({"a": 10, "b": 20}))
        .unwrap()
        .rollback()
        .execute()
        .await;
    assert!(resp.is_ok(), "rpc rollback failed: {:?}", resp.error);
    let rows = resp.into_result().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get_as::<i64>("add_numbers").unwrap(), 30);
}
