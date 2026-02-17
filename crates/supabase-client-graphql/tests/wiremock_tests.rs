//! Wiremock-based integration tests for supabase-client-graphql.
//!
//! These tests spin up a local HTTP mock server and exercise every `execute()`
//! path in `GraphqlClient`, `QueryBuilder`, `MutationBuilder`, and the
//! `SupabaseClientGraphqlExt` extension trait.

use serde::Deserialize;
use serde_json::{json, Value};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use supabase_client_graphql::client::GraphqlClient;
use supabase_client_graphql::error::GraphqlError;
use supabase_client_graphql::filter::GqlFilter;
use supabase_client_graphql::types::{Connection, GraphqlResponse, MutationResult};

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

/// A minimal row type used across tests.
#[derive(Debug, Clone, Deserialize, PartialEq)]
struct TestRow {
    id: String,
    name: String,
}

/// Create a `GraphqlClient` pointing at the given mock server.
fn mock_client(server: &MockServer) -> GraphqlClient {
    // The constructor appends `/graphql/v1` to the base URL.
    GraphqlClient::new(&server.uri(), "test-api-key").unwrap()
}

/// A standard connection JSON payload for collection queries.
fn connection_payload(collection: &str) -> Value {
    json!({
        "data": {
            collection: {
                "edges": [
                    {"cursor": "c1", "node": {"id": "1", "name": "Alice"}},
                    {"cursor": "c2", "node": {"id": "2", "name": "Bob"}}
                ],
                "pageInfo": {
                    "hasNextPage": true,
                    "hasPreviousPage": false,
                    "startCursor": "c1",
                    "endCursor": "c2"
                },
                "totalCount": 42
            }
        }
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// 1. GraphqlClient tests  (src/client.rs)
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn client_execute_success_with_data() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql/v1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "usersCollection": {
                        "edges": [
                            {"cursor": "c1", "node": {"id": "1", "name": "Alice"}}
                        ]
                    }
                }
            })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let resp: GraphqlResponse<Value> = client
        .execute("query { usersCollection { edges { node { id name } } } }", None, None)
        .await
        .expect("execute should succeed");

    assert!(resp.errors.is_empty());
    let data = resp.data.expect("data should be present");
    let edges = &data["usersCollection"]["edges"];
    assert_eq!(edges.as_array().unwrap().len(), 1);
    assert_eq!(edges[0]["node"]["name"], "Alice");
}

#[tokio::test]
async fn client_execute_graphql_errors_array() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql/v1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({
                "data": null,
                "errors": [
                    {"message": "Column 'foo' not found"},
                    {"message": "Permission denied"}
                ]
            })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let result: Result<GraphqlResponse<Value>, GraphqlError> = client
        .execute("query { bad }", None, None)
        .await;

    match result {
        Err(GraphqlError::GraphqlErrors(errors)) => {
            assert_eq!(errors.len(), 2);
            assert_eq!(errors[0].message, "Column 'foo' not found");
            assert_eq!(errors[1].message, "Permission denied");
        }
        other => panic!("Expected GraphqlErrors, got: {:?}", other),
    }
}

#[tokio::test]
async fn client_execute_http_400_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql/v1"))
        .respond_with(
            ResponseTemplate::new(400).set_body_string("Bad Request: malformed query"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let result: Result<GraphqlResponse<Value>, GraphqlError> = client
        .execute("invalid", None, None)
        .await;

    match result {
        Err(GraphqlError::HttpError { status, message }) => {
            assert_eq!(status, 400);
            assert!(message.contains("Bad Request"));
        }
        other => panic!("Expected HttpError, got: {:?}", other),
    }
}

#[tokio::test]
async fn client_execute_http_500_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql/v1"))
        .respond_with(
            ResponseTemplate::new(500).set_body_string("Internal Server Error"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let result: Result<GraphqlResponse<Value>, GraphqlError> = client
        .execute("query { x }", None, None)
        .await;

    match result {
        Err(GraphqlError::HttpError { status, message }) => {
            assert_eq!(status, 500);
            assert!(message.contains("Internal Server Error"));
        }
        other => panic!("Expected HttpError, got: {:?}", other),
    }
}

#[tokio::test]
async fn client_execute_with_auth_override() {
    let server = MockServer::start().await;

    // Expect the overridden Authorization header to be present.
    Mock::given(method("POST"))
        .and(path("/graphql/v1"))
        .and(header("authorization", "Bearer user-jwt-token"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({
                "data": {"ok": true}
            })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = mock_client(&server);
    client.set_auth("user-jwt-token");

    let resp: GraphqlResponse<Value> = client
        .execute("query { ok }", None, None)
        .await
        .expect("execute with auth override should succeed");

    assert!(resp.data.is_some());
}

#[tokio::test]
async fn client_execute_sends_apikey_header() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql/v1"))
        .and(header("apikey", "test-api-key"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({
                "data": {"check": true}
            })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let resp: GraphqlResponse<Value> = client
        .execute("query { check }", None, None)
        .await
        .expect("request should include apikey header");

    assert!(resp.data.is_some());
}

#[tokio::test]
async fn client_execute_raw_success() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql/v1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "blogCollection": {
                        "edges": [
                            {"cursor": "x", "node": {"id": "99", "title": "Hello"}}
                        ]
                    }
                }
            })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let resp = client
        .execute_raw("query { blogCollection { edges { node { id title } } } }", None, None)
        .await
        .expect("execute_raw should succeed");

    let data = resp.data.unwrap();
    assert_eq!(data["blogCollection"]["edges"][0]["node"]["id"], "99");
}

#[tokio::test]
async fn client_execute_with_variables_and_operation_name() {
    let server = MockServer::start().await;

    // We will verify the mock receives the request (any POST to /graphql/v1).
    // The important thing is that the client doesn't error out when variables
    // and operationName are provided.
    Mock::given(method("POST"))
        .and(path("/graphql/v1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({
                "data": {"result": 42}
            })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let resp: GraphqlResponse<Value> = client
        .execute(
            "query GetUser($id: Int!) { user(id: $id) { name } }",
            Some(json!({"id": 1})),
            Some("GetUser"),
        )
        .await
        .expect("execute with variables and operation_name should succeed");

    assert_eq!(resp.data.unwrap()["result"], 42);
}

#[tokio::test]
async fn client_execute_graphql_errors_with_data_succeeds() {
    // When there are errors BUT data is also present, execute() should succeed
    // (partial success scenario).
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql/v1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({
                "data": {"partial": true},
                "errors": [{"message": "deprecation warning"}]
            })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let resp: GraphqlResponse<Value> = client
        .execute("query { partial }", None, None)
        .await
        .expect("partial success should not be an error");

    assert!(resp.data.is_some());
    assert_eq!(resp.errors.len(), 1);
    assert_eq!(resp.errors[0].message, "deprecation warning");
}

// Builder method return type tests (no wiremock needed)

#[test]
fn client_collection_returns_query_builder() {
    let client = GraphqlClient::new("https://example.supabase.co", "test-key").unwrap();
    let builder = client.collection("usersCollection");
    // Verify we can chain builder methods without error.
    let (query, _) = builder.select(&["id", "name"]).first(10).build();
    assert!(query.contains("usersCollection"));
}

#[test]
fn client_insert_into_returns_mutation_builder() {
    let client = GraphqlClient::new("https://example.supabase.co", "test-key").unwrap();
    let builder = client.insert_into("blogCollection");
    let (query, _) = builder
        .objects(vec![json!({"title": "test"})])
        .returning(&["id"])
        .build();
    assert!(query.contains("insertIntoBlogCollection"));
}

#[test]
fn client_update_returns_mutation_builder() {
    let client = GraphqlClient::new("https://example.supabase.co", "test-key").unwrap();
    let builder = client.update("blogCollection");
    let (query, _) = builder
        .set(json!({"title": "updated"}))
        .returning(&["id"])
        .build();
    assert!(query.contains("updateBlogCollection"));
}

#[test]
fn client_delete_from_returns_mutation_builder() {
    let client = GraphqlClient::new("https://example.supabase.co", "test-key").unwrap();
    let builder = client.delete_from("blogCollection");
    let (query, _) = builder
        .filter(GqlFilter::eq("id", json!(1)))
        .returning(&["id"])
        .build();
    assert!(query.contains("deleteFromBlogCollection"));
}

#[test]
fn client_new_invalid_url() {
    let result = GraphqlClient::new("not a valid url at all", "key");
    // The Url::parse should fail for a completely invalid URL.
    // Note: url crate is lenient, so "not a valid url at all" actually parses
    // as a relative URL which fails. Let's use an empty string instead.
    let result2 = GraphqlClient::new("", "key");
    // At least one of these should fail.
    assert!(
        result.is_err() || result2.is_err(),
        "Expected at least one invalid URL to fail"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// 2. QueryBuilder tests  (src/query.rs)
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn query_builder_execute_success() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql/v1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(connection_payload("usersCollection")),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let connection: Connection<TestRow> = client
        .collection("usersCollection")
        .select(&["id", "name"])
        .first(10)
        .execute()
        .await
        .expect("query execute should succeed");

    assert_eq!(connection.edges.len(), 2);
    assert_eq!(connection.edges[0].cursor, "c1");
    assert_eq!(connection.edges[0].node.id, "1");
    assert_eq!(connection.edges[0].node.name, "Alice");
    assert_eq!(connection.edges[1].node.id, "2");
    assert_eq!(connection.edges[1].node.name, "Bob");
    assert!(connection.page_info.has_next_page);
    assert!(!connection.page_info.has_previous_page);
    assert_eq!(connection.total_count, Some(42));
}

#[tokio::test]
async fn query_builder_execute_missing_collection_key() {
    let server = MockServer::start().await;

    // The response has data but the collection key is wrong.
    Mock::given(method("POST"))
        .and(path("/graphql/v1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "wrongCollection": {
                        "edges": []
                    }
                }
            })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let result: Result<Connection<TestRow>, GraphqlError> = client
        .collection("usersCollection")
        .select(&["id", "name"])
        .execute()
        .await;

    match result {
        Err(GraphqlError::InvalidConfig(msg)) => {
            assert!(
                msg.contains("usersCollection"),
                "Error should mention the missing collection name, got: {}",
                msg
            );
        }
        other => panic!("Expected InvalidConfig error, got: {:?}", other),
    }
}

#[tokio::test]
async fn query_builder_execute_empty_edges() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql/v1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "usersCollection": {
                        "edges": [],
                        "pageInfo": {
                            "hasNextPage": false,
                            "hasPreviousPage": false
                        }
                    }
                }
            })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let connection: Connection<TestRow> = client
        .collection("usersCollection")
        .select(&["id", "name"])
        .execute()
        .await
        .expect("empty result should still succeed");

    assert!(connection.edges.is_empty());
    assert!(!connection.page_info.has_next_page);
    assert_eq!(connection.total_count, None);
}

#[tokio::test]
async fn query_builder_execute_no_data_in_response() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql/v1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({
                "data": null,
                "errors": [{"message": "table not found"}]
            })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let result: Result<Connection<TestRow>, GraphqlError> = client
        .collection("usersCollection")
        .select(&["id", "name"])
        .execute()
        .await;

    // Should be a GraphqlErrors since data is null and errors are present.
    assert!(result.is_err());
}

#[tokio::test]
async fn query_builder_execute_with_filter_and_pagination() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql/v1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(connection_payload("usersCollection")),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let connection: Connection<TestRow> = client
        .collection("usersCollection")
        .select(&["id", "name"])
        .filter(GqlFilter::eq("name", json!("Alice")))
        .first(5)
        .after("some-cursor")
        .total_count()
        .execute()
        .await
        .expect("filtered + paginated query should succeed");

    assert_eq!(connection.edges.len(), 2);
}

// ──────────────────────────────────────────────────────────────────────────────
// 3. MutationBuilder tests  (src/mutation.rs)
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn mutation_insert_execute_success() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql/v1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "insertIntoBlogCollection": {
                        "affectedCount": 1,
                        "records": [
                            {"id": "10", "name": "New Post"}
                        ]
                    }
                }
            })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let result: MutationResult<TestRow> = client
        .insert_into("blogCollection")
        .objects(vec![json!({"name": "New Post"})])
        .returning(&["id", "name"])
        .execute()
        .await
        .expect("insert mutation should succeed");

    assert_eq!(result.affected_count, 1);
    assert_eq!(result.records.len(), 1);
    assert_eq!(result.records[0].id, "10");
    assert_eq!(result.records[0].name, "New Post");
}

#[tokio::test]
async fn mutation_update_execute_success() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql/v1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "updateBlogCollection": {
                        "affectedCount": 1,
                        "records": [
                            {"id": "5", "name": "Updated Title"}
                        ]
                    }
                }
            })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let result: MutationResult<TestRow> = client
        .update("blogCollection")
        .set(json!({"name": "Updated Title"}))
        .filter(GqlFilter::eq("id", json!("5")))
        .at_most(1)
        .returning(&["id", "name"])
        .execute()
        .await
        .expect("update mutation should succeed");

    assert_eq!(result.affected_count, 1);
    assert_eq!(result.records[0].name, "Updated Title");
}

#[tokio::test]
async fn mutation_delete_execute_success() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql/v1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "deleteFromBlogCollection": {
                        "affectedCount": 1,
                        "records": [
                            {"id": "7", "name": "Deleted Post"}
                        ]
                    }
                }
            })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let result: MutationResult<TestRow> = client
        .delete_from("blogCollection")
        .filter(GqlFilter::eq("id", json!("7")))
        .at_most(1)
        .returning(&["id", "name"])
        .execute()
        .await
        .expect("delete mutation should succeed");

    assert_eq!(result.affected_count, 1);
    assert_eq!(result.records[0].id, "7");
}

#[tokio::test]
async fn mutation_execute_missing_mutation_field() {
    let server = MockServer::start().await;

    // Response data does not contain the expected mutation field.
    Mock::given(method("POST"))
        .and(path("/graphql/v1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "someOtherField": {
                        "affectedCount": 0,
                        "records": []
                    }
                }
            })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let result: Result<MutationResult<TestRow>, GraphqlError> = client
        .insert_into("blogCollection")
        .objects(vec![json!({"title": "test"})])
        .returning(&["id", "name"])
        .execute()
        .await;

    match result {
        Err(GraphqlError::InvalidConfig(msg)) => {
            assert!(
                msg.contains("insertIntoBlogCollection"),
                "Error should mention the expected mutation field, got: {}",
                msg
            );
        }
        other => panic!("Expected InvalidConfig error, got: {:?}", other),
    }
}

#[tokio::test]
async fn mutation_execute_graphql_error_response() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql/v1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({
                "data": null,
                "errors": [{"message": "violates foreign key constraint"}]
            })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let result: Result<MutationResult<TestRow>, GraphqlError> = client
        .insert_into("blogCollection")
        .objects(vec![json!({"title": "test"})])
        .execute()
        .await;

    match result {
        Err(GraphqlError::GraphqlErrors(errors)) => {
            assert_eq!(errors.len(), 1);
            assert!(errors[0].message.contains("foreign key"));
        }
        other => panic!("Expected GraphqlErrors, got: {:?}", other),
    }
}

#[tokio::test]
async fn mutation_execute_http_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql/v1"))
        .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
        .expect(1)
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let result: Result<MutationResult<TestRow>, GraphqlError> = client
        .delete_from("blogCollection")
        .filter(GqlFilter::eq("id", json!(1)))
        .execute()
        .await;

    match result {
        Err(GraphqlError::HttpError { status, message }) => {
            assert_eq!(status, 403);
            assert!(message.contains("Forbidden"));
        }
        other => panic!("Expected HttpError, got: {:?}", other),
    }
}

#[tokio::test]
async fn mutation_insert_multiple_objects() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql/v1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "insertIntoBlogCollection": {
                        "affectedCount": 2,
                        "records": [
                            {"id": "1", "name": "Post A"},
                            {"id": "2", "name": "Post B"}
                        ]
                    }
                }
            })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let result: MutationResult<TestRow> = client
        .insert_into("blogCollection")
        .objects(vec![
            json!({"name": "Post A"}),
            json!({"name": "Post B"}),
        ])
        .returning(&["id", "name"])
        .execute()
        .await
        .expect("multi-object insert should succeed");

    assert_eq!(result.affected_count, 2);
    assert_eq!(result.records.len(), 2);
}

// ──────────────────────────────────────────────────────────────────────────────
// 4. Extension trait tests  (src/lib.rs - SupabaseClientGraphqlExt)
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn extension_trait_graphql_returns_graphql_client() {
    use supabase_client_core::config::SupabaseConfig;
    use supabase_client_core::SupabaseClient;
    use supabase_client_graphql::SupabaseClientGraphqlExt;

    let config = SupabaseConfig::new("https://my-project.supabase.co", "my-anon-key");
    let supa = SupabaseClient::new(config).unwrap();

    let graphql = supa.graphql().expect("graphql() should succeed");

    // The GraphqlClient should have derived the correct base URL.
    assert_eq!(graphql.base_url().path(), "/graphql/v1");
    assert_eq!(graphql.api_key(), "my-anon-key");
    assert!(graphql
        .base_url()
        .as_str()
        .starts_with("https://my-project.supabase.co"));
}

#[tokio::test]
async fn extension_trait_graphql_client_can_execute() {
    use supabase_client_core::config::SupabaseConfig;
    use supabase_client_core::SupabaseClient;
    use supabase_client_graphql::SupabaseClientGraphqlExt;

    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql/v1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({
                "data": {"ping": "pong"}
            })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let config = SupabaseConfig::new(&server.uri(), "my-anon-key");
    let supa = SupabaseClient::new(config).unwrap();
    let graphql = supa.graphql().expect("graphql() should succeed");

    // Note: The GraphqlClient created via the extension trait creates its own
    // reqwest::Client internally (with default headers), so it works standalone
    // against the mock server.
    let resp: GraphqlResponse<Value> = graphql
        .execute("query { ping }", None, None)
        .await
        .expect("execute via extension trait client should succeed");

    assert_eq!(resp.data.unwrap()["ping"], "pong");
}
