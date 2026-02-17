use std::sync::Arc;

#[cfg(feature = "direct-sql")]
use sqlx::PgPool;

/// Backend for query execution.
///
/// By default, queries are executed via the PostgREST REST API.
/// With the `direct-sql` feature, queries can be executed directly via sqlx.
#[derive(Clone)]
pub enum QueryBackend {
    /// PostgREST REST API backend (default).
    Rest {
        http: reqwest::Client,
        base_url: Arc<str>,
        api_key: Arc<str>,
        schema: String,
    },
    /// Direct SQL via sqlx (opt-in with `direct-sql` feature).
    #[cfg(feature = "direct-sql")]
    DirectSql {
        pool: Arc<PgPool>,
    },
}

impl std::fmt::Debug for QueryBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rest { base_url, schema, .. } => {
                f.debug_struct("Rest")
                    .field("base_url", base_url)
                    .field("schema", schema)
                    .finish()
            }
            #[cfg(feature = "direct-sql")]
            Self::DirectSql { .. } => f.debug_struct("DirectSql").finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_backend_rest_construction() {
        let backend = QueryBackend::Rest {
            http: reqwest::Client::new(),
            base_url: Arc::from("http://localhost:54321"),
            api_key: Arc::from("test-api-key"),
            schema: "public".to_string(),
        };
        match &backend {
            QueryBackend::Rest { base_url, api_key, schema, .. } => {
                assert_eq!(base_url.as_ref(), "http://localhost:54321");
                assert_eq!(api_key.as_ref(), "test-api-key");
                assert_eq!(schema, "public");
            }
            #[cfg(feature = "direct-sql")]
            _ => panic!("expected Rest variant"),
        }
    }

    #[test]
    fn test_query_backend_debug_rest() {
        let backend = QueryBackend::Rest {
            http: reqwest::Client::new(),
            base_url: Arc::from("http://localhost:54321"),
            api_key: Arc::from("secret-key"),
            schema: "public".to_string(),
        };
        let debug_str = format!("{:?}", backend);
        // Debug should include base_url and schema but not expose api_key
        assert!(debug_str.contains("Rest"));
        assert!(debug_str.contains("http://localhost:54321"));
        assert!(debug_str.contains("public"));
        // api_key is not included in the debug output (only base_url and schema are)
        assert!(!debug_str.contains("secret-key"));
    }

    #[test]
    fn test_query_backend_clone() {
        let backend = QueryBackend::Rest {
            http: reqwest::Client::new(),
            base_url: Arc::from("http://localhost"),
            api_key: Arc::from("key"),
            schema: "public".to_string(),
        };
        let cloned = backend.clone();
        match (&backend, &cloned) {
            (
                QueryBackend::Rest { base_url: a, schema: sa, .. },
                QueryBackend::Rest { base_url: b, schema: sb, .. },
            ) => {
                assert_eq!(a, b);
                assert_eq!(sa, sb);
            }
            #[cfg(feature = "direct-sql")]
            _ => panic!("expected Rest variants"),
        }
    }
}
