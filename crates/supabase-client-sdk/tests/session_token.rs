//! Issue #6: the auth session's JWT is used by the other clients created
//! from the same `SupabaseClient`. Runs against a wiremock server, no
//! Supabase stack needed.

#![cfg(all(
    feature = "auth",
    feature = "query",
    feature = "storage",
    feature = "functions",
    feature = "graphql"
))]

use serde_json::json;
use supabase_client_sdk::prelude::*;
use supabase_client_sdk::supabase_client_graphql::SupabaseClientGraphqlExt;
use wiremock::matchers::{any, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn session_body() -> serde_json::Value {
    json!({
        "access_token": "USER-JWT",
        "refresh_token": "rt",
        "expires_in": 3600,
        "expires_at": 9999999999i64,
        "token_type": "bearer",
        "user": {"id": "u1"}
    })
}

#[tokio::test]
async fn auth_session_token_flows_to_query_storage_functions_and_graphql() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/auth/v1/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(session_body()))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/auth/v1/logout"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/graphql/v1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {}})))
        .mount(&server)
        .await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let client = SupabaseClient::new(SupabaseConfig::new(server.uri(), "ANON-KEY")).unwrap();
    // Created before sign-in on purpose: they follow the shared slot.
    let storage = client.storage().unwrap();
    let functions = client.functions().unwrap();
    let graphql = client.graphql().unwrap();
    let auth = client.auth().unwrap();

    // Query builders take the token when they are created.
    let query = || async {
        let resp = client.from("todos").select("*").execute().await;
        assert!(resp.error.is_none(), "{:?}", resp.error);
    };

    query().await;
    storage.list_buckets().await.unwrap();

    auth.sign_in_with_password_email("a@b.c", "pw")
        .await
        .unwrap();
    assert_eq!(client.access_token().as_deref(), Some("USER-JWT"));
    query().await;
    storage.list_buckets().await.unwrap();
    functions
        .invoke("hello", InvokeOptions::new())
        .await
        .unwrap();
    graphql
        .execute::<serde_json::Value>("query { __typename }", None, None)
        .await
        .unwrap();

    auth.sign_out_current().await.unwrap();
    query().await;
    storage.list_buckets().await.unwrap();

    let reqs = server.received_requests().await.unwrap();
    let seen: Vec<(String, String, String)> = reqs
        .iter()
        .filter(|r| !r.url.path().starts_with("/auth/"))
        .map(|r| {
            (
                r.url.path().to_string(),
                r.headers["authorization"].to_str().unwrap().to_string(),
                r.headers["apikey"].to_str().unwrap().to_string(),
            )
        })
        .collect();
    let row = |p: &str, bearer: &str| {
        (
            p.to_string(),
            format!("Bearer {bearer}"),
            "ANON-KEY".to_string(),
        )
    };
    assert_eq!(
        seen,
        vec![
            // Signed out: the anon key is the bearer.
            row("/rest/v1/todos", "ANON-KEY"),
            row("/storage/v1/bucket", "ANON-KEY"),
            // Signed in: the session JWT, apikey still the anon key.
            row("/rest/v1/todos", "USER-JWT"),
            row("/storage/v1/bucket", "USER-JWT"),
            row("/functions/v1/hello", "USER-JWT"),
            row("/graphql/v1", "USER-JWT"),
            // Signed out again.
            row("/rest/v1/todos", "ANON-KEY"),
            row("/storage/v1/bucket", "ANON-KEY"),
        ]
    );
}

#[test]
fn derive_path_is_reexported() {
    // `#[derive(Table)]` output refers to these paths when only the sdk is a
    // dependency.
    #[allow(unused_imports)]
    use supabase_client_sdk::__query::{IntoSqlParam, SqlParam, Table};
    let _: SqlParam = IntoSqlParam::into_sql_param(1i32);
}
