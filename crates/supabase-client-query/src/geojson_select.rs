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
}
