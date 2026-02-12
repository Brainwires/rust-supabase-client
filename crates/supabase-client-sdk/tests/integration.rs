//! Integration tests for supabase-client-sdk against a real PostgreSQL database.
//!
//! These tests require the `direct-sql` feature and a running PostgreSQL instance.
//! Set DATABASE_URL env var or it defaults to the local Supabase dev instance.
//!
//! Run with: cargo test -p supabase-client-sdk --features direct-sql -- --test-threads=1
//!
//! Setup SQL:
//! ```sql
//! CREATE DATABASE supabase_client_test;
//! -- Then in that database:
//! CREATE TABLE countries (id SERIAL PRIMARY KEY, name TEXT NOT NULL UNIQUE, code TEXT NOT NULL);
//! CREATE TABLE cities (
//!     id SERIAL PRIMARY KEY, name TEXT NOT NULL,
//!     country_id INTEGER NOT NULL REFERENCES countries(id),
//!     population BIGINT DEFAULT 0, is_capital BOOLEAN DEFAULT FALSE,
//!     metadata JSONB, created_at TIMESTAMPTZ DEFAULT NOW()
//! );
//! CREATE FUNCTION get_cities_by_country(p_country_id INTEGER) RETURNS SETOF cities ...
//! CREATE FUNCTION add_numbers(a INTEGER, b INTEGER) RETURNS INTEGER ...
//! ```

// These tests require direct-sql feature
#![cfg(feature = "direct-sql")]

use serde::{Deserialize, Serialize};
use supabase_client_sdk::prelude::*;

use supabase_client_sdk::{
    NullsPosition, SqlParam, SupabaseClientQueryExt,
};

const TEST_DB_URL: &str =
    "postgres://postgres:319f76099a3e89d964a09e9d673f695d1b401fd8b500d1f7400a285e846ee246@localhost:15432/supabase_client_test";

const SUPABASE_URL: &str = "http://localhost:64321";
const ANON_KEY: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0";

fn db_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| TEST_DB_URL.to_string())
}

/// Typed struct for the cities table, using the derive macro.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, Table)]
#[table(name = "cities")]
struct City {
    #[primary_key(auto_generate)]
    pub id: i32,
    pub name: String,
    pub country_id: i32,
    #[column(name = "population")]
    pub population: Option<i64>,
    pub is_capital: Option<bool>,
    #[column(skip)]
    pub metadata: Option<serde_json::Value>,
    #[column(skip)]
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Typed struct for countries.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, Table)]
#[table(name = "countries")]
struct Country {
    #[primary_key(auto_generate)]
    pub id: i32,
    pub name: String,
    pub code: String,
}

async fn create_client() -> SupabaseClient {
    let config = SupabaseConfig::new(SUPABASE_URL, ANON_KEY)
        .database_url(db_url());
    SupabaseClient::with_database(config)
        .await
        .expect("Failed to connect to test database")
}

/// Reset test data to a known state using TRUNCATE CASCADE for atomicity.
async fn reset_data(client: &SupabaseClient) {
    let pool = client.pool().expect("pool required for direct-sql tests");
    sqlx::query("TRUNCATE cities, countries RESTART IDENTITY CASCADE")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO countries (name, code) VALUES ('New Zealand', 'NZ'), ('Australia', 'AU'), ('Japan', 'JP')",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO cities (name, country_id, population, is_capital) VALUES \
         ('Auckland', 1, 1657000, FALSE), \
         ('Wellington', 1, 215000, TRUE), \
         ('Sydney', 2, 5312000, FALSE), \
         ('Canberra', 2, 453000, TRUE), \
         ('Tokyo', 3, 13960000, TRUE)",
    )
    .execute(pool)
    .await
    .unwrap();
}

// ============================================================
// DYNAMIC API TESTS
// ============================================================

mod dynamic {
    use super::*;

    #[tokio::test]
    async fn select_all() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client.from("cities").select("*").execute().await;
        assert!(resp.is_ok());
        let rows = resp.into_result().unwrap();
        assert_eq!(rows.len(), 5);
    }

    #[tokio::test]
    async fn select_specific_columns() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .select("name, population")
            .execute()
            .await;
        assert!(resp.is_ok());
        let rows = resp.into_result().unwrap();
        assert_eq!(rows.len(), 5);
        // Each row should have name and population
        let first = &rows[0];
        assert!(first.contains("name"));
        assert!(first.contains("population"));
    }

    #[tokio::test]
    async fn select_with_eq_filter() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .select("*")
            .eq("name", "Tokyo")
            .execute()
            .await;
        let rows = resp.into_result().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get_as::<String>("name").unwrap(), "Tokyo");
    }

    #[tokio::test]
    async fn select_with_neq_filter() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .select("*")
            .neq("name", "Tokyo")
            .execute()
            .await;
        let rows = resp.into_result().unwrap();
        assert_eq!(rows.len(), 4);
    }

    #[tokio::test]
    async fn select_with_gt_filter() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .select("*")
            .gt("population", 1000000_i64)
            .execute()
            .await;
        let rows = resp.into_result().unwrap();
        // Auckland (1.6M), Sydney (5.3M), Tokyo (13.9M)
        assert_eq!(rows.len(), 3);
    }

    #[tokio::test]
    async fn select_with_gte_lte_filter() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .select("*")
            .gte("population", 453000_i64)
            .lte("population", 5312000_i64)
            .execute()
            .await;
        let rows = resp.into_result().unwrap();
        // Auckland (1.6M), Canberra (453K), Sydney (5.3M)
        assert_eq!(rows.len(), 3);
    }

    #[tokio::test]
    async fn select_with_like_filter() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .select("*")
            .like("name", "%land%")
            .execute()
            .await;
        let rows = resp.into_result().unwrap();
        // Auckland
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get_as::<String>("name").unwrap(), "Auckland");
    }

    #[tokio::test]
    async fn select_with_ilike_filter() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .select("*")
            .ilike("name", "%LAND%")
            .execute()
            .await;
        let rows = resp.into_result().unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[tokio::test]
    async fn select_with_in_filter() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .select("*")
            .in_("name", vec!["Tokyo", "Sydney"])
            .execute()
            .await;
        let rows = resp.into_result().unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[tokio::test]
    async fn select_with_is_filter() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .select("*")
            .is("is_capital", IsValue::True)
            .execute()
            .await;
        let rows = resp.into_result().unwrap();
        // Wellington, Canberra, Tokyo
        assert_eq!(rows.len(), 3);
    }

    #[tokio::test]
    async fn select_with_is_null() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .select("*")
            .is("metadata", IsValue::Null)
            .execute()
            .await;
        let rows = resp.into_result().unwrap();
        assert_eq!(rows.len(), 5); // All rows have NULL metadata
    }

    #[tokio::test]
    async fn select_with_order() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .select("name")
            .order("name", OrderDirection::Ascending)
            .execute()
            .await;
        let rows = resp.into_result().unwrap();
        let names: Vec<String> = rows
            .iter()
            .map(|r| r.get_as::<String>("name").unwrap())
            .collect();
        assert_eq!(names, vec!["Auckland", "Canberra", "Sydney", "Tokyo", "Wellington"]);
    }

    #[tokio::test]
    async fn select_with_order_desc() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .select("name")
            .order("name", OrderDirection::Descending)
            .execute()
            .await;
        let rows = resp.into_result().unwrap();
        let names: Vec<String> = rows
            .iter()
            .map(|r| r.get_as::<String>("name").unwrap())
            .collect();
        assert_eq!(names, vec!["Wellington", "Tokyo", "Sydney", "Canberra", "Auckland"]);
    }

    #[tokio::test]
    async fn select_with_limit() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .select("*")
            .order("name", OrderDirection::Ascending)
            .limit(2)
            .execute()
            .await;
        let rows = resp.into_result().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get_as::<String>("name").unwrap(), "Auckland");
        assert_eq!(rows[1].get_as::<String>("name").unwrap(), "Canberra");
    }

    #[tokio::test]
    async fn select_with_range() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .select("name")
            .order("name", OrderDirection::Ascending)
            .range(1, 3) // offset 1, limit 3 (rows 2-4)
            .execute()
            .await;
        let rows = resp.into_result().unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].get_as::<String>("name").unwrap(), "Canberra");
        assert_eq!(rows[1].get_as::<String>("name").unwrap(), "Sydney");
        assert_eq!(rows[2].get_as::<String>("name").unwrap(), "Tokyo");
    }

    #[tokio::test]
    async fn select_single() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .select("*")
            .eq("name", "Tokyo")
            .single()
            .execute()
            .await;
        let city = resp.into_single().unwrap();
        assert_eq!(city.get_as::<String>("name").unwrap(), "Tokyo");
    }

    #[tokio::test]
    async fn select_single_no_rows_error() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .select("*")
            .eq("name", "Nonexistent")
            .single()
            .execute()
            .await;
        assert!(resp.is_err());
        let err = resp.into_single().unwrap_err();
        assert!(matches!(err, SupabaseError::NoRows));
    }

    #[tokio::test]
    async fn select_maybe_single_some() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .select("*")
            .eq("name", "Tokyo")
            .maybe_single()
            .execute()
            .await;
        let city = resp.into_maybe_single().unwrap();
        assert!(city.is_some());
    }

    #[tokio::test]
    async fn select_maybe_single_none() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .select("*")
            .eq("name", "Nonexistent")
            .maybe_single()
            .execute()
            .await;
        let city = resp.into_maybe_single().unwrap();
        assert!(city.is_none());
    }

    #[tokio::test]
    async fn select_with_or_filter() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .select("*")
            .or_filter(|f| f.eq("name", "Tokyo").eq("name", "Sydney"))
            .execute()
            .await;
        let rows = resp.into_result().unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[tokio::test]
    async fn select_with_not_filter() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .select("*")
            .not(|f| f.eq("is_capital", true))
            .execute()
            .await;
        let rows = resp.into_result().unwrap();
        // Auckland and Sydney are not capitals
        assert_eq!(rows.len(), 2);
    }

    #[tokio::test]
    async fn select_with_count() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .select("*")
            .count()
            .execute()
            .await;
        assert!(resp.is_ok());
        assert_eq!(resp.count, Some(5));
    }

    #[tokio::test]
    async fn select_with_order_nulls_first() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .select("name, metadata")
            .order_with_nulls("metadata", OrderDirection::Ascending, NullsPosition::First)
            .execute()
            .await;
        let rows = resp.into_result().unwrap();
        assert_eq!(rows.len(), 5);
    }

    #[tokio::test]
    async fn insert_single_row() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .insert(row![("name", "Christchurch"), ("country_id", 1), ("population", 380000_i64)])
            .select()
            .execute()
            .await;
        assert!(resp.is_ok());
        let rows = resp.into_result().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get_as::<String>("name").unwrap(), "Christchurch");

        // Verify it's in the database
        let check = client
            .from("cities")
            .select("*")
            .eq("name", "Christchurch")
            .execute()
            .await;
        assert_eq!(check.into_result().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn insert_without_returning() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .insert(row![("name", "Hamilton"), ("country_id", 1)])
            .execute()
            .await;
        assert!(resp.is_ok());
        assert_eq!(resp.count, Some(1));
    }

    #[tokio::test]
    async fn insert_many_rows() {
        let client = create_client().await;
        reset_data(&client).await;

        let rows = vec![
            row![("name", "Queenstown"), ("country_id", 1), ("population", 15000_i64)],
            row![("name", "Rotorua"), ("country_id", 1), ("population", 58000_i64)],
        ];
        let resp = client.from("cities").insert_many(rows).select().execute().await;
        assert!(resp.is_ok(), "insert_many failed: {:?}", resp.error);
        let data = resp.into_result().unwrap();
        assert_eq!(data.len(), 2);
    }

    #[tokio::test]
    async fn update_with_filter() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .update(row![("name", "Middle Earth")])
            .eq("name", "Wellington")
            .select()
            .execute()
            .await;
        assert!(resp.is_ok());
        let rows = resp.into_result().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get_as::<String>("name").unwrap(), "Middle Earth");
    }

    #[tokio::test]
    async fn update_without_returning() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .update(row![("population", 250000_i64)])
            .eq("name", "Wellington")
            .execute()
            .await;
        assert!(resp.is_ok());
        assert_eq!(resp.count, Some(1));
    }

    #[tokio::test]
    async fn delete_with_filter() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .delete()
            .eq("name", "Tokyo")
            .select()
            .execute()
            .await;
        assert!(resp.is_ok());
        let rows = resp.into_result().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get_as::<String>("name").unwrap(), "Tokyo");

        // Verify deletion
        let check = client.from("cities").select("*").execute().await;
        assert_eq!(check.into_result().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn delete_without_returning() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .delete()
            .eq("name", "Tokyo")
            .execute()
            .await;
        assert!(resp.is_ok());
        assert_eq!(resp.count, Some(1));
    }

    #[tokio::test]
    async fn upsert_update_existing() {
        let client = create_client().await;
        reset_data(&client).await;

        // Upsert with existing id=1 (Auckland) -> should update
        let resp = client
            .from("cities")
            .upsert(row![("id", 1), ("name", "Auckland Updated"), ("country_id", 1), ("population", 1700000_i64)])
            .on_conflict(&["id"])
            .select()
            .execute()
            .await;
        assert!(resp.is_ok(), "upsert failed: {:?}", resp.error);
        let rows = resp.into_result().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get_as::<String>("name").unwrap(), "Auckland Updated");
        assert_eq!(rows[0].get_as::<i64>("population").unwrap(), 1700000);
    }

    #[tokio::test]
    async fn upsert_insert_new() {
        let client = create_client().await;
        reset_data(&client).await;

        // Upsert with id=100 (doesn't exist) -> should insert
        let resp = client
            .from("cities")
            .upsert(row![("id", 100), ("name", "Dunedin"), ("country_id", 1), ("population", 130000_i64)])
            .on_conflict(&["id"])
            .select()
            .execute()
            .await;
        assert!(resp.is_ok(), "upsert failed: {:?}", resp.error);
        let rows = resp.into_result().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get_as::<String>("name").unwrap(), "Dunedin");
    }

    #[tokio::test]
    async fn rpc_call() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .rpc("get_cities_by_country", serde_json::json!({"p_country_id": 1}))
            .unwrap()
            .execute()
            .await;
        assert!(resp.is_ok());
        let rows = resp.into_result().unwrap();
        assert_eq!(rows.len(), 2); // Auckland and Wellington
    }

    #[tokio::test]
    async fn rpc_scalar() {
        let client = create_client().await;

        let resp = client
            .rpc("add_numbers", serde_json::json!({"a": 3, "b": 7}))
            .unwrap()
            .execute()
            .await;
        assert!(resp.is_ok());
        let rows = resp.into_result().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get_as::<i64>("add_numbers").unwrap(), 10);
    }

    #[tokio::test]
    async fn multiple_filters_combined() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from("cities")
            .select("*")
            .eq("country_id", 1_i32)
            .gt("population", 200000_i64)
            .order("population", OrderDirection::Descending)
            .execute()
            .await;
        let rows = resp.into_result().unwrap();
        assert_eq!(rows.len(), 2); // Auckland (1.6M) and Wellington (215K)
        assert_eq!(rows[0].get_as::<String>("name").unwrap(), "Auckland");
        assert_eq!(rows[1].get_as::<String>("name").unwrap(), "Wellington");
    }
}

// ============================================================
// TYPED API TESTS
// ============================================================

mod typed {
    use super::*;

    #[tokio::test]
    async fn select_all_typed() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from_typed::<City>()
            .select()
            .execute()
            .await;
        assert!(resp.is_ok());
        let cities = resp.into_result().unwrap();
        assert_eq!(cities.len(), 5);
        assert!(cities.iter().any(|c| c.name == "Tokyo"));
    }

    #[tokio::test]
    async fn select_with_filter_typed() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from_typed::<City>()
            .select()
            .eq("name", "Auckland")
            .execute()
            .await;
        let cities = resp.into_result().unwrap();
        assert_eq!(cities.len(), 1);
        assert_eq!(cities[0].name, "Auckland");
        assert_eq!(cities[0].country_id, 1);
        assert_eq!(cities[0].population, Some(1657000));
    }

    #[tokio::test]
    async fn select_with_order_limit_typed() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from_typed::<City>()
            .select()
            .order("population", OrderDirection::Descending)
            .limit(3)
            .execute()
            .await;
        let cities = resp.into_result().unwrap();
        assert_eq!(cities.len(), 3);
        assert_eq!(cities[0].name, "Tokyo");
        assert_eq!(cities[1].name, "Sydney");
        assert_eq!(cities[2].name, "Auckland");
    }

    #[tokio::test]
    async fn select_single_typed() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from_typed::<City>()
            .select()
            .eq("name", "Sydney")
            .single()
            .execute()
            .await;
        let city = resp.into_single().unwrap();
        assert_eq!(city.name, "Sydney");
        assert_eq!(city.is_capital, Some(false));
    }

    #[tokio::test]
    async fn insert_typed() {
        let client = create_client().await;
        reset_data(&client).await;

        let new_city = City {
            id: 0, // auto-generated
            name: "Hamilton".to_string(),
            country_id: 1,
            population: Some(170000),
            is_capital: Some(false),
            metadata: None,
            created_at: None,
        };

        let resp = client
            .from_typed::<City>()
            .insert(&new_city)
            .select()
            .execute()
            .await;
        assert!(resp.is_ok());
        let cities = resp.into_result().unwrap();
        assert_eq!(cities.len(), 1);
        assert_eq!(cities[0].name, "Hamilton");
        assert!(cities[0].id > 0);
    }

    #[tokio::test]
    async fn select_countries_typed() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from_typed::<Country>()
            .select()
            .order("name", OrderDirection::Ascending)
            .execute()
            .await;
        let countries = resp.into_result().unwrap();
        assert_eq!(countries.len(), 3);
        assert_eq!(countries[0].name, "Australia");
        assert_eq!(countries[0].code, "AU");
    }

    #[tokio::test]
    async fn delete_typed() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .from_typed::<City>()
            .delete()
            .eq("name", "Tokyo")
            .select()
            .execute()
            .await;
        assert!(resp.is_ok());
        let deleted = resp.into_result().unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].name, "Tokyo");

        // Verify
        let check = client.from_typed::<City>().select().execute().await;
        assert_eq!(check.into_result().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn typed_rpc() {
        let client = create_client().await;
        reset_data(&client).await;

        let resp = client
            .rpc_typed::<City>("get_cities_by_country", serde_json::json!({"p_country_id": 2}))
            .unwrap()
            .execute()
            .await;
        assert!(resp.is_ok());
        let cities = resp.into_result().unwrap();
        assert_eq!(cities.len(), 2); // Sydney and Canberra
        assert!(cities.iter().any(|c| c.name == "Sydney"));
        assert!(cities.iter().any(|c| c.name == "Canberra"));
    }
}

// ============================================================
// DERIVE MACRO TESTS
// ============================================================

mod derive_tests {
    use super::*;

    #[test]
    fn table_name() {
        assert_eq!(City::table_name(), "cities");
        assert_eq!(Country::table_name(), "countries");
    }

    #[test]
    fn schema_name() {
        assert_eq!(City::schema_name(), "public");
        assert_eq!(Country::schema_name(), "public");
    }

    #[test]
    fn primary_key_columns() {
        assert_eq!(City::primary_key_columns(), &["id"]);
        assert_eq!(Country::primary_key_columns(), &["id"]);
    }

    #[test]
    fn column_names() {
        let cols = City::column_names();
        assert!(cols.contains(&"id"));
        assert!(cols.contains(&"name"));
        assert!(cols.contains(&"country_id"));
        assert!(cols.contains(&"population"));
        assert!(cols.contains(&"is_capital"));
        // metadata and created_at are skipped
        assert!(!cols.contains(&"metadata"));
        assert!(!cols.contains(&"created_at"));
    }

    #[test]
    fn insertable_columns() {
        let cols = City::insertable_columns();
        // id is auto_generate, so not insertable
        assert!(!cols.contains(&"id"));
        assert!(cols.contains(&"name"));
        assert!(cols.contains(&"country_id"));
    }

    #[test]
    fn field_to_column() {
        assert_eq!(City::field_to_column("name"), Some("name"));
        assert_eq!(City::field_to_column("population"), Some("population"));
        assert_eq!(City::field_to_column("nonexistent"), None);
    }

    #[test]
    fn column_to_field() {
        assert_eq!(City::column_to_field("name"), Some("name"));
        assert_eq!(City::column_to_field("population"), Some("population"));
        assert_eq!(City::column_to_field("nonexistent"), None);
    }

    #[test]
    fn bind_insert() {
        let city = City {
            id: 0,
            name: "Test".to_string(),
            country_id: 1,
            population: Some(100),
            is_capital: Some(true),
            metadata: None,
            created_at: None,
        };
        let params = city.bind_insert();
        assert_eq!(params.len(), City::insertable_columns().len());
    }

    #[test]
    fn bind_primary_key() {
        let city = City {
            id: 42,
            name: "Test".to_string(),
            country_id: 1,
            population: None,
            is_capital: None,
            metadata: None,
            created_at: None,
        };
        let params = city.bind_primary_key();
        assert_eq!(params.len(), 1);
        match &params[0] {
            SqlParam::I32(v) => assert_eq!(*v, 42),
            _ => panic!("Expected I32 for primary key"),
        }
    }
}

// ============================================================
// RESPONSE TESTS
// ============================================================

mod response_tests {
    use super::*;

    #[test]
    fn response_ok() {
        let resp = SupabaseResponse::ok(vec![1, 2, 3]);
        assert!(resp.is_ok());
        assert!(!resp.is_err());
        assert_eq!(resp.first(), Some(&1));
        assert_eq!(resp.into_result().unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn response_error() {
        let resp = SupabaseResponse::<i32>::error(SupabaseError::NoRows);
        assert!(resp.is_err());
        assert!(resp.into_result().is_err());
    }

    #[test]
    fn response_into_single() {
        let resp = SupabaseResponse::ok(vec![42]);
        assert_eq!(resp.into_single().unwrap(), 42);
    }

    #[test]
    fn response_into_single_empty() {
        let resp = SupabaseResponse::<i32>::ok(vec![]);
        assert!(matches!(resp.into_single(), Err(SupabaseError::NoRows)));
    }

    #[test]
    fn response_into_single_multiple() {
        let resp = SupabaseResponse::ok(vec![1, 2]);
        assert!(matches!(resp.into_single(), Err(SupabaseError::MultipleRows(2))));
    }

    #[test]
    fn response_into_maybe_single() {
        let resp = SupabaseResponse::ok(vec![42]);
        assert_eq!(resp.into_maybe_single().unwrap(), Some(42));

        let resp = SupabaseResponse::<i32>::ok(vec![]);
        assert_eq!(resp.into_maybe_single().unwrap(), None);
    }
}

// ============================================================
// SQL GENERATION TESTS (additional edge cases)
// ============================================================

mod sql_gen {
    use supabase_client_sdk::{
        FilterCondition, FilterOperator, SqlOperation, SqlParts, validate_column_name,
    };

    #[test]
    fn reject_sql_injection_in_column() {
        assert!(validate_column_name("name").is_ok());
        assert!(validate_column_name("my_column").is_ok());
        assert!(validate_column_name("col123").is_ok());

        // Injection attempts
        assert!(validate_column_name("name\"").is_err());
        assert!(validate_column_name("name; DROP TABLE").is_err());
        assert!(validate_column_name("name--comment").is_err());
        assert!(validate_column_name("").is_err());
    }

    #[test]
    fn build_complex_where() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        // name = $1 AND population > $2
        parts.filters.push(FilterCondition::Comparison {
            column: "name".to_string(),
            operator: FilterOperator::Eq,
            param_index: 1,
        });
        parts.filters.push(FilterCondition::Comparison {
            column: "population".to_string(),
            operator: FilterOperator::Gt,
            param_index: 2,
        });
        let sql = parts.build_sql().unwrap();
        assert_eq!(
            sql,
            "SELECT * FROM \"public\".\"cities\" WHERE \"name\" = $1 AND \"population\" > $2"
        );
    }
}
