use serde::Deserialize;
use supabase_client_core::SupabaseError;

/// A single error entry from the GraphQL `errors` array.
#[derive(Debug, Clone, Deserialize)]
pub struct GraphqlApiError {
    pub message: String,
    #[serde(default)]
    pub locations: Vec<GraphqlErrorLocation>,
    #[serde(default)]
    pub path: Vec<serde_json::Value>,
    #[serde(default)]
    pub extensions: Option<serde_json::Value>,
}

/// Source location of a GraphQL error.
#[derive(Debug, Clone, Deserialize)]
pub struct GraphqlErrorLocation {
    pub line: u64,
    pub column: u64,
}

impl std::fmt::Display for GraphqlApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// GraphQL-specific errors.
#[derive(Debug, thiserror::Error)]
pub enum GraphqlError {
    /// HTTP transport error from reqwest.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// The GraphQL response contained one or more errors in the `errors` array.
    #[error("GraphQL errors: {}", format_errors(.0))]
    GraphqlErrors(Vec<GraphqlApiError>),

    /// Non-2xx HTTP status from the GraphQL endpoint.
    #[error("GraphQL HTTP error ({status}): {message}")]
    HttpError { status: u16, message: String },

    /// Invalid configuration (missing URL or key).
    #[error("Invalid GraphQL configuration: {0}")]
    InvalidConfig(String),

    /// JSON serialization/deserialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// URL parsing error.
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),
}

fn format_errors(errors: &[GraphqlApiError]) -> String {
    errors
        .iter()
        .map(|e| e.message.as_str())
        .collect::<Vec<_>>()
        .join("; ")
}

impl From<GraphqlError> for SupabaseError {
    fn from(err: GraphqlError) -> Self {
        SupabaseError::GraphQL(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_http_error() {
        let err = GraphqlError::HttpError {
            status: 400,
            message: "Bad Request".into(),
        };
        assert_eq!(err.to_string(), "GraphQL HTTP error (400): Bad Request");
    }

    #[test]
    fn error_display_invalid_config() {
        let err = GraphqlError::InvalidConfig("missing url".into());
        assert_eq!(
            err.to_string(),
            "Invalid GraphQL configuration: missing url"
        );
    }

    #[test]
    fn error_display_graphql_errors() {
        let err = GraphqlError::GraphqlErrors(vec![
            GraphqlApiError {
                message: "field not found".into(),
                locations: vec![],
                path: vec![],
                extensions: None,
            },
            GraphqlApiError {
                message: "type mismatch".into(),
                locations: vec![],
                path: vec![],
                extensions: None,
            },
        ]);
        assert_eq!(
            err.to_string(),
            "GraphQL errors: field not found; type mismatch"
        );
    }

    #[test]
    fn error_converts_to_supabase_error() {
        let err = GraphqlError::HttpError {
            status: 500,
            message: "Internal".into(),
        };
        let supa: SupabaseError = err.into();
        match supa {
            SupabaseError::GraphQL(msg) => assert!(msg.contains("Internal")),
            other => panic!("Expected GraphQL variant, got: {:?}", other),
        }
    }

    #[test]
    fn api_error_deserialization() {
        let json = r#"{"message":"Column not found","locations":[{"line":1,"column":5}]}"#;
        let err: GraphqlApiError = serde_json::from_str(json).unwrap();
        assert_eq!(err.message, "Column not found");
        assert_eq!(err.locations.len(), 1);
        assert_eq!(err.locations[0].line, 1);
        assert_eq!(err.locations[0].column, 5);
    }
}
