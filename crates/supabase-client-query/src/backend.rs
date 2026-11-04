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
        /// Access token (JWT) of the signed-in user. When set it is sent as
        /// `Authorization: Bearer <token>` instead of the API key, so
        /// PostgREST applies row level security as that user. `apikey` is
        /// always the API key.
        access_token: Option<Arc<str>>,
        schema: String,
    },
    /// Direct SQL via sqlx (opt-in with `direct-sql` feature).
    #[cfg(feature = "direct-sql")]
    DirectSql { pool: Arc<PgPool> },
}

impl QueryBackend {
    /// Return this backend with the user access token set, so requests send
    /// `Authorization: Bearer <access_token>` (with `apikey: <api key>`).
    ///
    /// Has no effect on the direct-SQL backend, which connects with its own
    /// database credentials and does not evaluate PostgREST RLS claims.
    pub fn with_access_token(mut self, access_token: impl Into<Arc<str>>) -> Self {
        self.set_access_token(Some(access_token.into()));
        self
    }

    /// Set or clear (with `None`) the user access token. See
    /// [`with_access_token`](Self::with_access_token).
    pub fn set_access_token(&mut self, token: Option<Arc<str>>) {
        match self {
            Self::Rest { access_token, .. } => *access_token = token,
            #[cfg(feature = "direct-sql")]
            Self::DirectSql { .. } => {}
        }
    }

    /// The user access token, if one is set.
    pub fn access_token(&self) -> Option<&str> {
        match self {
            Self::Rest { access_token, .. } => access_token.as_deref(),
            #[cfg(feature = "direct-sql")]
            Self::DirectSql { .. } => None,
        }
    }
}

impl std::fmt::Debug for QueryBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rest {
                base_url, schema, ..
            } => f
                .debug_struct("Rest")
                .field("base_url", base_url)
                .field("schema", schema)
                .finish_non_exhaustive(),
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
            access_token: None,
            schema: "public".to_string(),
        };
        match &backend {
            QueryBackend::Rest {
                base_url,
                api_key,
                schema,
                ..
            } => {
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
            access_token: None,
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
            access_token: None,
            schema: "public".to_string(),
        };
        let cloned = backend.clone();
        match (&backend, &cloned) {
            (
                QueryBackend::Rest {
                    base_url: a,
                    schema: sa,
                    ..
                },
                QueryBackend::Rest {
                    base_url: b,
                    schema: sb,
                    ..
                },
            ) => {
                assert_eq!(a, b);
                assert_eq!(sa, sb);
            }
            #[cfg(feature = "direct-sql")]
            _ => panic!("expected Rest variants"),
        }
    }
}
