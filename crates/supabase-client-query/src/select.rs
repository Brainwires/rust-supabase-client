use std::marker::PhantomData;

use serde::de::DeserializeOwned;

use supabase_client_core::SupabaseResponse;

use crate::backend::QueryBackend;
use crate::csv_select::CsvSelectBuilder;
use crate::filter::Filterable;
use crate::geojson_select::GeoJsonSelectBuilder;
use crate::modifier::Modifiable;
use crate::sql::{ExplainOptions, FilterCondition, ParamStore, SqlParts};

/// Builder for SELECT queries. Implements both Filterable and Modifiable.
pub struct SelectBuilder<T> {
    pub(crate) backend: QueryBackend,
    pub(crate) parts: SqlParts,
    pub(crate) params: ParamStore,
    pub(crate) _marker: PhantomData<T>,
}

impl<T> Filterable for SelectBuilder<T> {
    fn filters_mut(&mut self) -> &mut Vec<FilterCondition> {
        &mut self.parts.filters
    }
    fn params_mut(&mut self) -> &mut ParamStore {
        &mut self.params
    }
}

impl<T> Modifiable for SelectBuilder<T> {
    fn parts_mut(&mut self) -> &mut SqlParts {
        &mut self.parts
    }
}

impl<T> SelectBuilder<T> {
    /// Override the schema for this query.
    pub fn schema(mut self, schema: &str) -> Self {
        self.parts.schema_override = Some(schema.to_string());
        self
    }

    /// Wrap the SELECT in `EXPLAIN (ANALYZE, FORMAT JSON)`.
    pub fn explain(mut self) -> Self {
        self.parts.explain = Some(ExplainOptions::default());
        self
    }

    /// Wrap the SELECT in EXPLAIN with custom options.
    pub fn explain_with(mut self, options: ExplainOptions) -> Self {
        self.parts.explain = Some(options);
        self
    }

    /// Switch to head/count-only mode.
    pub fn head(mut self) -> Self {
        self.parts.head = true;
        self
    }

    /// Switch to CSV output mode. Returns a `CsvSelectBuilder` that
    /// executes the query and returns the raw CSV text.
    pub fn csv(self) -> CsvSelectBuilder {
        CsvSelectBuilder {
            backend: self.backend,
            parts: self.parts,
            params: self.params,
        }
    }

    /// Switch to GeoJSON output mode. Returns a `GeoJsonSelectBuilder` that
    /// executes the query and returns a `serde_json::Value` (GeoJSON FeatureCollection).
    pub fn geojson(self) -> GeoJsonSelectBuilder {
        GeoJsonSelectBuilder {
            backend: self.backend,
            parts: self.parts,
            params: self.params,
        }
    }
}

// REST-only mode: only DeserializeOwned + Send needed
#[cfg(not(feature = "direct-sql"))]
impl<T> SelectBuilder<T>
where
    T: DeserializeOwned + Send,
{
    /// Execute the SELECT query and return results.
    pub async fn execute(self) -> SupabaseResponse<T> {
        let QueryBackend::Rest { ref http, ref base_url, ref api_key, ref schema } = self.backend;
        let method = if self.parts.head {
            reqwest::Method::HEAD
        } else {
            reqwest::Method::GET
        };
        let (url, headers) = match crate::postgrest::build_postgrest_select(
            base_url, &self.parts, &self.params,
        ) {
            Ok(r) => r,
            Err(e) => return SupabaseResponse::error(
                supabase_client_core::SupabaseError::QueryBuilder(e),
            ),
        };
        crate::postgrest_execute::execute_rest(
            http, method, &url, headers, None, api_key, schema, &self.parts,
        ).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::QueryBackend;
    use crate::sql::{ExplainFormat, ParamStore, SqlOperation, SqlParts};
    use serde_json::Value as JsonValue;
    use std::marker::PhantomData;
    use std::sync::Arc;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn make_select_builder() -> SelectBuilder<JsonValue> {
        SelectBuilder {
            backend: QueryBackend::Rest {
                http: reqwest::Client::new(),
                base_url: Arc::from("http://localhost"),
                api_key: Arc::from("test-key"),
                schema: "public".to_string(),
            },
            parts: SqlParts::new(SqlOperation::Select, "public", "users"),
            params: ParamStore::new(),
            _marker: PhantomData,
        }
    }

    // ---- Builder method tests ----

    #[test]
    fn test_schema_sets_override() {
        let builder = make_select_builder().schema("custom_schema");
        assert_eq!(builder.parts.schema_override.as_deref(), Some("custom_schema"));
    }

    #[test]
    fn test_explain_sets_default_options() {
        let builder = make_select_builder().explain();
        let opts = builder.parts.explain.as_ref().unwrap();
        assert!(opts.analyze);
        assert!(!opts.verbose);
        assert_eq!(opts.format, ExplainFormat::Json);
    }

    #[test]
    fn test_explain_with_custom_options() {
        let opts = crate::sql::ExplainOptions {
            analyze: false,
            verbose: true,
            format: ExplainFormat::Text,
        };
        let builder = make_select_builder().explain_with(opts);
        let actual = builder.parts.explain.as_ref().unwrap();
        assert!(!actual.analyze);
        assert!(actual.verbose);
        assert_eq!(actual.format, ExplainFormat::Text);
    }

    #[test]
    fn test_head_sets_head_mode() {
        let builder = make_select_builder().head();
        assert!(builder.parts.head);
    }

    #[test]
    fn test_csv_returns_csv_builder() {
        let builder = make_select_builder();
        let csv = builder.csv();
        assert_eq!(csv.parts.table, "users");
    }

    #[test]
    fn test_geojson_returns_geojson_builder() {
        let builder = make_select_builder();
        let geo = builder.geojson();
        assert_eq!(geo.parts.table, "users");
    }

    // ---- execute() via wiremock ----

    #[tokio::test]
    async fn test_execute_success_json_array() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/v1/users"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!([
                        {"id": 1, "name": "Alice"},
                        {"id": 2, "name": "Bob"}
                    ])),
            )
            .mount(&mock_server)
            .await;

        let builder: SelectBuilder<JsonValue> = SelectBuilder {
            backend: QueryBackend::Rest {
                http: reqwest::Client::new(),
                base_url: Arc::from(mock_server.uri().as_str()),
                api_key: Arc::from("test-key"),
                schema: "public".to_string(),
            },
            parts: SqlParts::new(SqlOperation::Select, "public", "users"),
            params: ParamStore::new(),
            _marker: PhantomData,
        };

        let resp = builder.execute().await;
        assert!(resp.is_ok());
        assert_eq!(resp.data.len(), 2);
        assert_eq!(resp.data[0]["name"], "Alice");
        assert_eq!(resp.data[1]["name"], "Bob");
    }

    #[tokio::test]
    async fn test_execute_empty_result() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/v1/users"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!([])),
            )
            .mount(&mock_server)
            .await;

        let builder: SelectBuilder<JsonValue> = SelectBuilder {
            backend: QueryBackend::Rest {
                http: reqwest::Client::new(),
                base_url: Arc::from(mock_server.uri().as_str()),
                api_key: Arc::from("test-key"),
                schema: "public".to_string(),
            },
            parts: SqlParts::new(SqlOperation::Select, "public", "users"),
            params: ParamStore::new(),
            _marker: PhantomData,
        };

        let resp = builder.execute().await;
        assert!(resp.is_ok());
        assert!(resp.data.is_empty());
    }

    #[tokio::test]
    async fn test_execute_error_4xx() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/v1/nonexistent"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(serde_json::json!({
                        "message": "Relation not found",
                        "code": "42P01"
                    })),
            )
            .mount(&mock_server)
            .await;

        let builder: SelectBuilder<JsonValue> = SelectBuilder {
            backend: QueryBackend::Rest {
                http: reqwest::Client::new(),
                base_url: Arc::from(mock_server.uri().as_str()),
                api_key: Arc::from("test-key"),
                schema: "public".to_string(),
            },
            parts: SqlParts::new(SqlOperation::Select, "public", "nonexistent"),
            params: ParamStore::new(),
            _marker: PhantomData,
        };

        let resp = builder.execute().await;
        assert!(resp.is_err());
        match resp.error.as_ref().unwrap() {
            supabase_client_core::SupabaseError::PostgRest { status, message, code } => {
                assert_eq!(*status, 404);
                assert_eq!(message, "Relation not found");
                assert_eq!(code.as_deref(), Some("42P01"));
            }
            other => panic!("Expected PostgRest error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_execute_head_mode() {
        let mock_server = MockServer::start().await;
        Mock::given(method("HEAD"))
            .and(path("/rest/v1/users"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-range", "0-9/55"),
            )
            .mount(&mock_server)
            .await;

        let builder: SelectBuilder<JsonValue> = SelectBuilder {
            backend: QueryBackend::Rest {
                http: reqwest::Client::new(),
                base_url: Arc::from(mock_server.uri().as_str()),
                api_key: Arc::from("test-key"),
                schema: "public".to_string(),
            },
            parts: {
                let mut p = SqlParts::new(SqlOperation::Select, "public", "users");
                p.head = true;
                p
            },
            params: ParamStore::new(),
            _marker: PhantomData,
        };

        let resp = builder.execute().await;
        assert!(resp.is_ok());
        assert!(resp.data.is_empty());
        assert_eq!(resp.count, Some(55));
    }
}

// Direct-SQL mode: additional FromRow + Unpin bounds
#[cfg(feature = "direct-sql")]
impl<T> SelectBuilder<T>
where
    T: DeserializeOwned + Send + Unpin + for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow>,
{
    /// Execute the SELECT query and return results.
    pub async fn execute(self) -> SupabaseResponse<T> {
        match &self.backend {
            QueryBackend::Rest { http, base_url, api_key, schema } => {
                let method = if self.parts.head {
                    reqwest::Method::HEAD
                } else {
                    reqwest::Method::GET
                };
                let (url, headers) = match crate::postgrest::build_postgrest_select(
                    base_url, &self.parts, &self.params,
                ) {
                    Ok(r) => r,
                    Err(e) => return SupabaseResponse::error(
                        supabase_client_core::SupabaseError::QueryBuilder(e),
                    ),
                };
                crate::postgrest_execute::execute_rest(
                    http, method, &url, headers, None, api_key, schema, &self.parts,
                ).await
            }
            QueryBackend::DirectSql { pool } => {
                crate::execute::execute_typed::<T>(pool, &self.parts, &self.params).await
            }
        }
    }
}
