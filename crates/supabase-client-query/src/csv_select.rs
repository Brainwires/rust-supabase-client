use reqwest::header::HeaderValue;

use supabase_client_core::SupabaseError;

use crate::backend::QueryBackend;
use crate::filter::Filterable;
use crate::modifier::Modifiable;
use crate::sql::{FilterCondition, ParamStore, SqlParts};

/// Builder for SELECT queries that return CSV text.
///
/// Created by calling `.csv()` on a `SelectBuilder`. Returns raw CSV string
/// instead of deserialized rows. REST-only (returns error for direct-sql backend).
pub struct CsvSelectBuilder {
    pub(crate) backend: QueryBackend,
    pub(crate) parts: SqlParts,
    pub(crate) params: ParamStore,
}

impl Filterable for CsvSelectBuilder {
    fn filters_mut(&mut self) -> &mut Vec<FilterCondition> {
        &mut self.parts.filters
    }
    fn params_mut(&mut self) -> &mut ParamStore {
        &mut self.params
    }
}

impl Modifiable for CsvSelectBuilder {
    fn parts_mut(&mut self) -> &mut SqlParts {
        &mut self.parts
    }
}

impl CsvSelectBuilder {
    /// Override the schema for this query.
    pub fn schema(mut self, schema: &str) -> Self {
        self.parts.schema_override = Some(schema.to_string());
        self
    }

    /// Execute the SELECT query and return the response as a CSV string.
    pub async fn execute(self) -> Result<String, SupabaseError> {
        match &self.backend {
            QueryBackend::Rest { http, base_url, api_key, schema } => {
                let (url, mut headers) = crate::postgrest::build_postgrest_select(
                    base_url, &self.parts, &self.params,
                )
                .map_err(SupabaseError::QueryBuilder)?;

                // Override Accept to text/csv
                headers.insert("Accept", HeaderValue::from_static("text/csv"));

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

                Ok(body)
            }
            #[cfg(feature = "direct-sql")]
            QueryBackend::DirectSql { .. } => {
                Err(SupabaseError::query_builder(
                    "CSV output is only supported with the REST (PostgREST) backend",
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
    fn test_csv_builder_modifiable() {
        let mut builder = CsvSelectBuilder {
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
    fn test_csv_builder_filterable() {
        let builder = CsvSelectBuilder {
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
    fn test_csv_accept_header() {
        let parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        let params = ParamStore::new();
        let (_, mut headers) = crate::postgrest::build_postgrest_select(
            "http://localhost:64321", &parts, &params,
        ).unwrap();
        // Simulate what CsvSelectBuilder does
        headers.insert("Accept", HeaderValue::from_static("text/csv"));
        assert_eq!(headers.get("Accept").unwrap(), "text/csv");
    }
}
