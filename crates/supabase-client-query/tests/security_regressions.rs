//! Regression tests for the security audit findings. They use a local
//! wiremock server (no Supabase instance needed).

use std::sync::Arc;

use serde_json::json;
use supabase_client_query::*;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn rest(base: &str, schema: &str) -> QueryBackend {
    QueryBackend::Rest {
        http: reqwest::Client::new(),
        base_url: Arc::from(base),
        api_key: Arc::from("anon"),
        access_token: None,
        schema: schema.to_string(),
    }
}

async fn catch_all(server: &MockServer, status: u16) {
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(status).set_body_json(json!([])))
        .mount(server)
        .await;
}

/// H1: an invalid column name used to drop the filter, sending an
/// unfiltered DELETE for the whole table.
#[tokio::test]
async fn invalid_filter_column_never_sends_unfiltered_delete() {
    let server = MockServer::start().await;
    catch_all(&server, 204).await;
    let qb = QueryBuilder::new(
        rest(&server.uri(), "public"),
        "public".into(),
        "orders".into(),
    );
    let resp = qb.delete().eq("id\"", 42).execute().await;
    assert!(resp.error.is_some(), "invalid filter must be an error");
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn invalid_filter_column_never_sends_unfiltered_update() {
    let server = MockServer::start().await;
    catch_all(&server, 204).await;
    let mut row = supabase_client_core::Row::new();
    row.set("status", json!("cancelled"));
    let qb = QueryBuilder::new(
        rest(&server.uri(), "public"),
        "public".into(),
        "orders".into(),
    );
    let resp = qb
        .update(row)
        .eq("customer_id", 7)
        .neq("bad;col", 1)
        .execute()
        .await;
    assert!(resp.error.is_some());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn invalid_order_column_is_an_error() {
    let server = MockServer::start().await;
    catch_all(&server, 200).await;
    let qb = QueryBuilder::new(
        rest(&server.uri(), "public"),
        "public".into(),
        "orders".into(),
    );
    let resp = qb
        .select("*")
        .order("x\"", OrderDirection::Ascending)
        .execute()
        .await;
    assert!(resp.error.is_some());
    assert!(server.received_requests().await.unwrap().is_empty());
}

/// M2: POST RPC in a non-public schema must send Content-Profile, and
/// rollback() must ask for strict handling so it cannot silently commit.
#[tokio::test]
async fn rpc_non_public_schema_uses_content_profile_and_strict_rollback() {
    let server = MockServer::start().await;
    catch_all(&server, 200).await;
    let rpc = RpcBuilder::new(
        rest(&server.uri(), "api"),
        "api".into(),
        "do_it".into(),
        json!({}),
    )
    .unwrap()
    .rollback();
    let _ = rpc.execute().await;
    let reqs = server.received_requests().await.unwrap();
    let r = &reqs[0];
    let hv = |n: &str| r.headers.get(n).map(|v| v.to_str().unwrap().to_string());
    assert_eq!(r.method.as_str(), "POST");
    assert_eq!(hv("content-profile").as_deref(), Some("api"));
    assert_eq!(hv("accept-profile"), None);
    assert_eq!(hv("prefer").as_deref(), Some("tx=rollback,handling=strict"));
}

/// Issue #6 / M5: a user access token goes in Authorization, the API key
/// stays in apikey.
#[tokio::test]
async fn access_token_is_sent_as_bearer_with_apikey() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/v1/todos"))
        .and(header("apikey", "anon"))
        .and(header("authorization", "Bearer user-jwt"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{"id": 1}])))
        .expect(1)
        .mount(&server)
        .await;
    let resp = QueryBuilder::new(
        rest(&server.uri(), "public"),
        "public".into(),
        "todos".into(),
    )
    .access_token("user-jwt")
    .select("*")
    .execute()
    .await;
    assert!(resp.error.is_none(), "{:?}", resp.error);
    assert_eq!(resp.data.len(), 1);
}

#[tokio::test]
async fn access_token_applies_to_rpc_csv_and_geojson() {
    let server = MockServer::start().await;
    Mock::given(header("authorization", "Bearer user-jwt"))
        .and(header("apikey", "anon"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(3)
        .mount(&server)
        .await;
    let backend = rest(&server.uri(), "public").with_access_token("user-jwt");
    let rpc = RpcBuilder::new(backend.clone(), "public".into(), "f".into(), json!({})).unwrap();
    assert!(rpc.execute().await.error.is_none());
    let qb = QueryBuilder::new(backend.clone(), "public".into(), "t".into());
    assert!(qb.select("*").csv().execute().await.is_ok());
    let qb = QueryBuilder::new(backend, "public".into(), "t".into());
    assert!(qb.select("*").geojson().execute().await.is_ok());
}

#[tokio::test]
async fn without_access_token_api_key_is_the_bearer() {
    let server = MockServer::start().await;
    Mock::given(header("authorization", "Bearer anon"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(1)
        .mount(&server)
        .await;
    let resp = QueryBuilder::new(rest(&server.uri(), "public"), "public".into(), "t".into())
        .select("*")
        .execute()
        .await;
    assert!(resp.error.is_none());
}

#[cfg(feature = "direct-sql")]
mod direct_sql {
    use supabase_client_query::*;

    /// H2: the text search config was interpolated inside '...'.
    #[test]
    fn text_search_config_cannot_inject_sql() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "docs");
        parts.filters.push(FilterCondition::TextSearch {
            column: "body".into(),
            query_param_index: 1,
            config: Some("english', $1) OR true OR to_tsquery('english".into()),
            search_type: TextSearchType::Plain,
        });
        assert!(parts.build_sql().is_err());

        parts.filters[0] = FilterCondition::TextSearch {
            column: "body".into(),
            query_param_index: 1,
            config: Some("english".into()),
            search_type: TextSearchType::Plain,
        };
        assert_eq!(
            parts.build_sql().unwrap(),
            r#"SELECT * FROM "public"."docs" WHERE "body" @@ plainto_tsquery('english'::regconfig, $1)"#
        );
    }

    /// H2: conflict columns / constraint were not validated.
    #[test]
    fn conflict_columns_cannot_inject_sql() {
        let mut parts = SqlParts::new(SqlOperation::Upsert, "public", "users");
        parts.set_clauses.push(("id".into(), 1));
        parts.set_clauses.push(("name".into(), 2));
        parts.conflict_columns = vec![r#"id") DO UPDATE SET "role" = 'admin' --"#.into()];
        assert!(parts.build_sql().is_err());

        parts.conflict_columns.clear();
        parts.conflict_constraint = Some(r#"pk" DO NOTHING; DROP TABLE users; --"#.into());
        assert!(parts.build_sql().is_err());
    }

    /// H2: select / returning pieces containing `(`, `*`, `"` or spaces
    /// were pasted into the SQL verbatim.
    #[test]
    fn select_and_returning_expressions_are_rejected() {
        for cols in [
            "id, (SELECT password FROM auth.users LIMIT 1)",
            "id, name AS n",
            "count(*)",
            "\"a\" FROM secrets --\"",
            "x\"",
        ] {
            let mut parts = SqlParts::new(SqlOperation::Select, "public", "t");
            parts.select_columns = Some(cols.into());
            assert!(parts.build_sql().is_err(), "select {cols:?} accepted");

            let mut parts = SqlParts::new(SqlOperation::Delete, "public", "t");
            parts.returning = Some(cols.into());
            assert!(parts.build_sql().is_err(), "returning {cols:?} accepted");
        }
    }

    #[test]
    fn plain_select_and_returning_lists_still_work() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "t");
        parts.select_columns = Some(r#""id", name"#.into());
        assert_eq!(
            parts.build_sql().unwrap(),
            r#"SELECT "id", "name" FROM "public"."t""#
        );
        let mut parts = SqlParts::new(SqlOperation::Delete, "public", "t");
        parts.returning = Some("*".into());
        assert_eq!(
            parts.build_sql().unwrap(),
            r#"DELETE FROM "public"."t" RETURNING *"#
        );
    }

    #[test]
    fn invalid_filter_fails_sql_generation() {
        let mut parts = SqlParts::new(SqlOperation::Delete, "public", "t");
        parts
            .filters
            .push(FilterCondition::Invalid("bad column".into()));
        assert!(parts.build_sql().is_err());
    }
}
