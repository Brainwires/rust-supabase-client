use reqwest::header::HeaderValue;
use serde_json::Value as JsonValue;

use supabase_client_core::SupabaseError;

use crate::backend::QueryBackend;
use crate::filter::Filterable;
use crate::modifier::Modifiable;
use crate::sql::{FilterCondition, ParamStore, SqlParts};

/// Builder for SELECT queries that return GeoJSON.
///
/// Created by calling `.geojson()` on a `SelectBuilder`. Returns a
/// `serde_json::Value` (GeoJSON FeatureCollection). REST-only.
pub struct GeoJsonSelectBuilder {
    pub(crate) backend: QueryBackend,
    pub(crate) parts: SqlParts,
    pub(crate) params: ParamStore,
}

impl Filterable for GeoJsonSelectBuilder {
    fn filters_mut(&mut self) -> &mut Vec<FilterCondition> {
        &mut self.parts.filters
    }
    fn params_mut(&mut self) -> &mut ParamStore {
        &mut self.params
    }
}

impl Modifiable for GeoJsonSelectBuilder {
    fn parts_mut(&mut self) -> &mut SqlParts {
        &mut self.parts
    }
}

impl GeoJsonSelectBuilder {
    /// Override the schema for this query.
    pub fn schema(mut self, schema: &str) -> Self {
        self.parts.schema_override = Some(schema.to_string());
        self
    }

    /// Execute the SELECT query and return the response as GeoJSON.
    pub async fn execute(self) -> Result<JsonValue, SupabaseError> {
        match &self.backend {
            QueryBackend::Rest { http, base_url, api_key, schema } => {
                let (url, mut headers) = crate::postgrest::build_postgrest_select(
                    base_url, &self.parts, &self.params,
                )
                .map_err(SupabaseError::QueryBuilder)?;

                // Override Accept to GeoJSON
                headers.insert(
                    "Accept",
                    HeaderValue::from_static("application/geo+json"),
                );

                // Standard auth headers
                headers.insert("apikey", HeaderValue::from_str(api_key).unwrap());
                headers.insert(
                    "Authorization",
                    HeaderValue::from_str(&format!("Bearer {}", api_key)).unwrap(),
                );

                // Schema profile
                if let Some(ref so) = self.parts.schema_override {
                    headers.insert(
                        "Accept-Profile",
                        HeaderValue::from_str(so).unwrap(),
                    );
                } else if schema != "public" {
                    headers.entry("Accept-Profile")
                        .or_insert_with(|| HeaderValue::from_str(schema).unwrap());
                }

                let response = http
                    .get(&url)
                    .headers(headers)
                    .send()
                    .await
                    .map_err(|e| SupabaseError::Http(e.to_string()))?;

                let status = response.status().as_u16();
                let body = response
                    .text()
                    .await
                    .map_err(|e| SupabaseError::Http(e.to_string()))?;

                if status >= 400 {
                    return Err(SupabaseError::postgrest(status, body, None));
                }

                serde_json::from_str(&body).map_err(|e| {
                    SupabaseError::Serialization(format!(
                        "Failed to parse GeoJSON response: {}",
                        e
                    ))
                })
            }
            #[cfg(feature = "direct-sql")]
            QueryBackend::DirectSql { .. } => {
                Err(SupabaseError::query_builder(
                    "GeoJSON output is only supported with the REST (PostgREST) backend",
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql::{SqlOperation, SqlParts, ParamStore};

    #[test]
    fn test_geojson_builder_modifiable() {
        let mut builder = GeoJsonSelectBuilder {
            backend: QueryBackend::Rest {
                http: reqwest::Client::new(),
                base_url: "http://localhost".into(),
                api_key: "key".into(),
                schema: "public".to_string(),
            },
            parts: SqlParts::new(SqlOperation::Select, "public", "cities"),
            params: ParamStore::new(),
        };
        builder = builder.limit(10);
        assert_eq!(builder.parts.limit, Some(10));
    }

    #[test]
    fn test_geojson_builder_filterable() {
        let builder = GeoJsonSelectBuilder {
            backend: QueryBackend::Rest {
                http: reqwest::Client::new(),
                base_url: "http://localhost".into(),
                api_key: "key".into(),
                schema: "public".to_string(),
            },
            parts: SqlParts::new(SqlOperation::Select, "public", "cities"),
            params: ParamStore::new(),
        };
        let builder = builder.eq("name", "Auckland");
        assert_eq!(builder.parts.filters.len(), 1);
    }

    #[test]
    fn test_geojson_accept_header() {
        let parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        let params = ParamStore::new();
        let (_, mut headers) = crate::postgrest::build_postgrest_select(
            "http://localhost:64321", &parts, &params,
        ).unwrap();
        // Simulate what GeoJsonSelectBuilder does
        headers.insert("Accept", HeaderValue::from_static("application/geo+json"));
        assert_eq!(headers.get("Accept").unwrap(), "application/geo+json");
    }

    #[test]
    fn test_geojson_schema_sets_override() {
        let builder = GeoJsonSelectBuilder {
            backend: QueryBackend::Rest {
                http: reqwest::Client::new(),
                base_url: "http://localhost".into(),
                api_key: "key".into(),
                schema: "public".to_string(),
            },
            parts: SqlParts::new(SqlOperation::Select, "public", "cities"),
            params: ParamStore::new(),
        };
        let builder = builder.schema("geo_schema");
        assert_eq!(builder.parts.schema_override.as_deref(), Some("geo_schema"));
    }

    // ---- execute() via wiremock ----

    #[tokio::test]
    async fn test_geojson_execute_success() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let geojson = serde_json::json!({
            "type": "FeatureCollection",
            "features": [
                {
                    "type": "Feature",
                    "geometry": {
                        "type": "Point",
                        "coordinates": [174.7633, -36.8485]
                    },
                    "properties": {
                        "name": "Auckland"
                    }
                }
            ]
        });
        Mock::given(method("GET"))
            .and(path("/rest/v1/cities"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(geojson.clone()),
            )
            .mount(&mock_server)
            .await;

        let builder = GeoJsonSelectBuilder {
            backend: QueryBackend::Rest {
                http: reqwest::Client::new(),
                base_url: mock_server.uri().into(),
                api_key: "test-key".into(),
                schema: "public".to_string(),
            },
            parts: SqlParts::new(SqlOperation::Select, "public", "cities"),
            params: ParamStore::new(),
        };

        let result = builder.execute().await;
        assert!(result.is_ok());
        let value = result.unwrap();
        assert_eq!(value["type"], "FeatureCollection");
        assert_eq!(value["features"][0]["properties"]["name"], "Auckland");
    }

    #[tokio::test]
    async fn test_geojson_execute_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/v1/nonexistent"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_string("Relation not found"),
            )
            .mount(&mock_server)
            .await;

        let builder = GeoJsonSelectBuilder {
            backend: QueryBackend::Rest {
                http: reqwest::Client::new(),
                base_url: mock_server.uri().into(),
                api_key: "test-key".into(),
                schema: "public".to_string(),
            },
            parts: SqlParts::new(SqlOperation::Select, "public", "nonexistent"),
            params: ParamStore::new(),
        };

        let result = builder.execute().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            SupabaseError::PostgRest { status, .. } => {
                assert_eq!(status, 404);
            }
            other => panic!("Expected PostgRest error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_geojson_execute_invalid_json_body() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/v1/cities"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("this is not json"),
            )
            .mount(&mock_server)
            .await;

        let builder = GeoJsonSelectBuilder {
            backend: QueryBackend::Rest {
                http: reqwest::Client::new(),
                base_url: mock_server.uri().into(),
                api_key: "test-key".into(),
                schema: "public".to_string(),
            },
            parts: SqlParts::new(SqlOperation::Select, "public", "cities"),
            params: ParamStore::new(),
        };

        let result = builder.execute().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            SupabaseError::Serialization(msg) => {
                assert!(msg.contains("Failed to parse GeoJSON"));
            }
            other => panic!("Expected Serialization error, got {:?}", other),
        }
    }
}
