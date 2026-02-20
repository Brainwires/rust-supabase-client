use std::marker::PhantomData;

use serde::de::DeserializeOwned;

use supabase_client_core::SupabaseResponse;

use crate::backend::QueryBackend;
use crate::modifier::Modifiable;
use crate::sql::{ParamStore, SqlParts};

/// Builder for INSERT queries. Implements Modifiable (for count).
/// Call `.select()` to add RETURNING clause.
pub struct InsertBuilder<T> {
    pub(crate) backend: QueryBackend,
    pub(crate) parts: SqlParts,
    pub(crate) params: ParamStore,
    pub(crate) _marker: PhantomData<T>,
}

impl<T> Modifiable for InsertBuilder<T> {
    fn parts_mut(&mut self) -> &mut SqlParts {
        &mut self.parts
    }
}

impl<T> InsertBuilder<T> {
    /// Override the schema for this query.
    ///
    /// Generates `"schema"."table"` instead of the default schema.
    pub fn schema(mut self, schema: &str) -> Self {
        self.parts.schema_override = Some(schema.to_string());
        self
    }

    /// Add RETURNING clause to get inserted rows back.
    pub fn select(mut self) -> Self {
        self.parts.returning = Some("*".to_string());
        self
    }

    /// Add RETURNING clause with specific columns.
    pub fn select_columns(mut self, columns: &str) -> Self {
        if columns == "*" || columns.is_empty() {
            self.parts.returning = Some("*".to_string());
        } else {
            let quoted = columns
                .split(',')
                .map(|c| {
                    let c = c.trim();
                    if c.contains('(') || c.contains('*') || c.contains('"') {
                        c.to_string()
                    } else {
                        format!("\"{}\"", c)
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            self.parts.returning = Some(quoted);
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::QueryBackend;
    use crate::sql::{ParamStore, SqlOperation, SqlParam, SqlParts};
    use serde_json::Value as JsonValue;
    use std::marker::PhantomData;
    use std::sync::Arc;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn make_insert_builder() -> InsertBuilder<JsonValue> {
        let mut parts = SqlParts::new(SqlOperation::Insert, "public", "users");
        let mut params = ParamStore::new();
        let idx = params.push(SqlParam::Text("Alice".to_string()));
        parts.set_clauses.push(("name".to_string(), idx));
        InsertBuilder {
            backend: QueryBackend::Rest {
                http: reqwest::Client::new(),
                base_url: Arc::from("http://localhost"),
                api_key: Arc::from("test-key"),
                schema: "public".to_string(),
            },
            parts,
            params,
            _marker: PhantomData,
        }
    }

    // ---- Builder method tests ----

    #[test]
    fn test_schema_sets_override() {
        let builder = make_insert_builder().schema("custom");
        assert_eq!(builder.parts.schema_override.as_deref(), Some("custom"));
    }

    #[test]
    fn test_select_sets_returning_star() {
        let builder = make_insert_builder().select();
        assert_eq!(builder.parts.returning.as_deref(), Some("*"));
    }

    #[test]
    fn test_select_columns_star() {
        let builder = make_insert_builder().select_columns("*");
        assert_eq!(builder.parts.returning.as_deref(), Some("*"));
    }

    #[test]
    fn test_select_columns_empty() {
        let builder = make_insert_builder().select_columns("");
        assert_eq!(builder.parts.returning.as_deref(), Some("*"));
    }

    #[test]
    fn test_select_columns_specific() {
        let builder = make_insert_builder().select_columns("id, name");
        assert_eq!(builder.parts.returning.as_deref(), Some("\"id\", \"name\""));
    }

    #[test]
    fn test_select_columns_complex_passthrough() {
        let builder = make_insert_builder().select_columns("count(*)");
        assert_eq!(builder.parts.returning.as_deref(), Some("count(*)"));
    }

    // ---- execute() via wiremock ----

    #[tokio::test]
    async fn test_execute_insert_success() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rest/v1/users"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!([{"id": 1, "name": "Alice"}])),
            )
            .mount(&mock_server)
            .await;

        let mut parts = SqlParts::new(SqlOperation::Insert, "public", "users");
        let mut params = ParamStore::new();
        let idx = params.push(SqlParam::Text("Alice".to_string()));
        parts.set_clauses.push(("name".to_string(), idx));
        parts.returning = Some("*".to_string());

        let builder: InsertBuilder<JsonValue> = InsertBuilder {
            backend: QueryBackend::Rest {
                http: reqwest::Client::new(),
                base_url: Arc::from(mock_server.uri().as_str()),
                api_key: Arc::from("test-key"),
                schema: "public".to_string(),
            },
            parts,
            params,
            _marker: PhantomData,
        };

        let resp = builder.execute().await;
        assert!(resp.is_ok());
        assert_eq!(resp.data.len(), 1);
        assert_eq!(resp.data[0]["name"], "Alice");
        assert_eq!(resp.status, supabase_client_core::StatusCode::Created);
    }

    #[tokio::test]
    async fn test_execute_insert_error() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rest/v1/users"))
            .respond_with(
                ResponseTemplate::new(409)
                    .set_body_json(serde_json::json!({
                        "message": "Duplicate key",
                        "code": "23505"
                    })),
            )
            .mount(&mock_server)
            .await;

        let mut parts = SqlParts::new(SqlOperation::Insert, "public", "users");
        let mut params = ParamStore::new();
        let idx = params.push(SqlParam::Text("Alice".to_string()));
        parts.set_clauses.push(("name".to_string(), idx));

        let builder: InsertBuilder<JsonValue> = InsertBuilder {
            backend: QueryBackend::Rest {
                http: reqwest::Client::new(),
                base_url: Arc::from(mock_server.uri().as_str()),
                api_key: Arc::from("test-key"),
                schema: "public".to_string(),
            },
            parts,
            params,
            _marker: PhantomData,
        };

        let resp = builder.execute().await;
        assert!(resp.is_err());
        match resp.error.as_ref().unwrap() {
            supabase_client_core::SupabaseError::PostgRest { status, message, code } => {
                assert_eq!(*status, 409);
                assert_eq!(message, "Duplicate key");
                assert_eq!(code.as_deref(), Some("23505"));
            }
            other => panic!("Expected PostgRest error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_execute_insert_no_returning() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rest/v1/users"))
            .respond_with(ResponseTemplate::new(201).set_body_string(""))
            .mount(&mock_server)
            .await;

        let mut parts = SqlParts::new(SqlOperation::Insert, "public", "users");
        let mut params = ParamStore::new();
        let idx = params.push(SqlParam::Text("Alice".to_string()));
        parts.set_clauses.push(("name".to_string(), idx));
        // No returning set

        let builder: InsertBuilder<JsonValue> = InsertBuilder {
            backend: QueryBackend::Rest {
                http: reqwest::Client::new(),
                base_url: Arc::from(mock_server.uri().as_str()),
                api_key: Arc::from("test-key"),
                schema: "public".to_string(),
            },
            parts,
            params,
            _marker: PhantomData,
        };

        let resp = builder.execute().await;
        assert!(resp.is_ok());
        assert!(resp.data.is_empty());
    }
}

impl<T> InsertBuilder<T>
where
    T: DeserializeOwned + Send,
{
    /// Execute the INSERT query.
    pub async fn execute(self) -> SupabaseResponse<T> {
        match &self.backend {
            QueryBackend::Rest { http, base_url, api_key, schema } => {
                let (url, headers, body) = match crate::postgrest::build_postgrest_insert(
                    base_url, &self.parts, &self.params,
                ) {
                    Ok(r) => r,
                    Err(e) => return SupabaseResponse::error(
                        supabase_client_core::SupabaseError::QueryBuilder(e),
                    ),
                };
                crate::postgrest_execute::execute_rest(
                    http, reqwest::Method::POST, &url, headers, Some(body), api_key, schema, &self.parts,
                ).await
            }
            #[cfg(feature = "direct-sql")]
            QueryBackend::DirectSql { pool } => {
                crate::execute::execute_typed::<T>(pool, &self.parts, &self.params).await
            }
        }
    }
}
