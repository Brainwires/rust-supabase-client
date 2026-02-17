use std::marker::PhantomData;

use serde::de::DeserializeOwned;

use supabase_client_core::SupabaseResponse;

use crate::backend::QueryBackend;
use crate::modifier::Modifiable;
use crate::sql::{ParamStore, SqlParts};

/// Builder for UPSERT (INSERT ... ON CONFLICT DO UPDATE) queries.
/// Implements Modifiable. Call `.select()` for RETURNING clause.
pub struct UpsertBuilder<T> {
    pub(crate) backend: QueryBackend,
    pub(crate) parts: SqlParts,
    pub(crate) params: ParamStore,
    pub(crate) _marker: PhantomData<T>,
}

impl<T> Modifiable for UpsertBuilder<T> {
    fn parts_mut(&mut self) -> &mut SqlParts {
        &mut self.parts
    }
}

impl<T> UpsertBuilder<T> {
    /// Set the conflict columns for ON CONFLICT.
    pub fn on_conflict(mut self, columns: &[&str]) -> Self {
        self.parts.conflict_columns = columns.iter().map(|c| c.to_string()).collect();
        self
    }

    /// Set a constraint name for ON CONFLICT ON CONSTRAINT.
    pub fn on_conflict_constraint(mut self, constraint: &str) -> Self {
        self.parts.conflict_constraint = Some(constraint.to_string());
        self
    }

    /// Use ON CONFLICT DO NOTHING instead of DO UPDATE.
    ///
    /// When set, duplicate rows are silently ignored instead of updated.
    pub fn ignore_duplicates(mut self) -> Self {
        self.parts.ignore_duplicates = true;
        self
    }

    /// Override the schema for this query.
    ///
    /// Generates `"schema"."table"` instead of the default schema.
    pub fn schema(mut self, schema: &str) -> Self {
        self.parts.schema_override = Some(schema.to_string());
        self
    }

    /// Add RETURNING * clause.
    pub fn select(mut self) -> Self {
        self.parts.returning = Some("*".to_string());
        self
    }

    /// Add RETURNING with specific columns.
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

    fn make_upsert_builder() -> UpsertBuilder<JsonValue> {
        let mut parts = SqlParts::new(SqlOperation::Upsert, "public", "users");
        let mut params = ParamStore::new();
        let idx1 = params.push(SqlParam::I32(1));
        parts.set_clauses.push(("id".to_string(), idx1));
        let idx2 = params.push(SqlParam::Text("Alice".to_string()));
        parts.set_clauses.push(("name".to_string(), idx2));
        UpsertBuilder {
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
    fn test_on_conflict_sets_columns() {
        let builder = make_upsert_builder().on_conflict(&["id"]);
        assert_eq!(builder.parts.conflict_columns, vec!["id".to_string()]);
    }

    #[test]
    fn test_on_conflict_multiple_columns() {
        let builder = make_upsert_builder().on_conflict(&["id", "email"]);
        assert_eq!(
            builder.parts.conflict_columns,
            vec!["id".to_string(), "email".to_string()]
        );
    }

    #[test]
    fn test_on_conflict_constraint_sets_name() {
        let builder = make_upsert_builder().on_conflict_constraint("users_pkey");
        assert_eq!(builder.parts.conflict_constraint.as_deref(), Some("users_pkey"));
    }

    #[test]
    fn test_ignore_duplicates_sets_flag() {
        let builder = make_upsert_builder().ignore_duplicates();
        assert!(builder.parts.ignore_duplicates);
    }

    #[test]
    fn test_schema_sets_override() {
        let builder = make_upsert_builder().schema("custom");
        assert_eq!(builder.parts.schema_override.as_deref(), Some("custom"));
    }

    #[test]
    fn test_select_sets_returning_star() {
        let builder = make_upsert_builder().select();
        assert_eq!(builder.parts.returning.as_deref(), Some("*"));
    }

    #[test]
    fn test_select_columns_star() {
        let builder = make_upsert_builder().select_columns("*");
        assert_eq!(builder.parts.returning.as_deref(), Some("*"));
    }

    #[test]
    fn test_select_columns_empty() {
        let builder = make_upsert_builder().select_columns("");
        assert_eq!(builder.parts.returning.as_deref(), Some("*"));
    }

    #[test]
    fn test_select_columns_specific() {
        let builder = make_upsert_builder().select_columns("id, name");
        assert_eq!(builder.parts.returning.as_deref(), Some("\"id\", \"name\""));
    }

    #[test]
    fn test_select_columns_complex() {
        let builder = make_upsert_builder().select_columns("count(*)");
        assert_eq!(builder.parts.returning.as_deref(), Some("count(*)"));
    }

    // ---- execute() via wiremock ----

    #[tokio::test]
    async fn test_execute_upsert_success() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rest/v1/users"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!([{"id": 1, "name": "Alice"}])),
            )
            .mount(&mock_server)
            .await;

        let mut parts = SqlParts::new(SqlOperation::Upsert, "public", "users");
        let mut params = ParamStore::new();
        let idx1 = params.push(SqlParam::I32(1));
        parts.set_clauses.push(("id".to_string(), idx1));
        let idx2 = params.push(SqlParam::Text("Alice".to_string()));
        parts.set_clauses.push(("name".to_string(), idx2));
        parts.conflict_columns = vec!["id".to_string()];
        parts.returning = Some("*".to_string());

        let builder: UpsertBuilder<JsonValue> = UpsertBuilder {
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
    async fn test_execute_upsert_error() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rest/v1/users"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(serde_json::json!({
                        "message": "Constraint violation",
                        "code": "23514"
                    })),
            )
            .mount(&mock_server)
            .await;

        let mut parts = SqlParts::new(SqlOperation::Upsert, "public", "users");
        let mut params = ParamStore::new();
        let idx1 = params.push(SqlParam::I32(1));
        parts.set_clauses.push(("id".to_string(), idx1));
        let idx2 = params.push(SqlParam::Text("Alice".to_string()));
        parts.set_clauses.push(("name".to_string(), idx2));
        parts.conflict_columns = vec!["id".to_string()];

        let builder: UpsertBuilder<JsonValue> = UpsertBuilder {
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
                assert_eq!(*status, 400);
                assert_eq!(message, "Constraint violation");
                assert_eq!(code.as_deref(), Some("23514"));
            }
            other => panic!("Expected PostgRest error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_execute_upsert_no_returning() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rest/v1/users"))
            .respond_with(ResponseTemplate::new(201).set_body_string(""))
            .mount(&mock_server)
            .await;

        let mut parts = SqlParts::new(SqlOperation::Upsert, "public", "users");
        let mut params = ParamStore::new();
        let idx1 = params.push(SqlParam::I32(1));
        parts.set_clauses.push(("id".to_string(), idx1));
        let idx2 = params.push(SqlParam::Text("Alice".to_string()));
        parts.set_clauses.push(("name".to_string(), idx2));
        parts.conflict_columns = vec!["id".to_string()];

        let builder: UpsertBuilder<JsonValue> = UpsertBuilder {
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

// REST-only mode: only DeserializeOwned + Send needed
#[cfg(not(feature = "direct-sql"))]
impl<T> UpsertBuilder<T>
where
    T: DeserializeOwned + Send,
{
    /// Execute the UPSERT query.
    pub async fn execute(self) -> SupabaseResponse<T> {
        let QueryBackend::Rest { ref http, ref base_url, ref api_key, ref schema } = self.backend;
        let (url, headers, body) = match crate::postgrest::build_postgrest_upsert(
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
}

// Direct-SQL mode: additional FromRow + Unpin bounds
#[cfg(feature = "direct-sql")]
impl<T> UpsertBuilder<T>
where
    T: DeserializeOwned + Send + Unpin + for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow>,
{
    /// Execute the UPSERT query.
    pub async fn execute(self) -> SupabaseResponse<T> {
        match &self.backend {
            QueryBackend::Rest { http, base_url, api_key, schema } => {
                let (url, headers, body) = match crate::postgrest::build_postgrest_upsert(
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
            QueryBackend::DirectSql { pool } => {
                crate::execute::execute_typed::<T>(pool, &self.parts, &self.params).await
            }
        }
    }
}
