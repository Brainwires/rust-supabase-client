use std::fmt;

/// All errors that can occur in the supabase-client crate.
#[derive(Debug, thiserror::Error)]
pub enum SupabaseError {
    #[cfg(feature = "direct-sql")]
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("PostgREST error ({status}): {message}")]
    PostgRest {
        status: u16,
        message: String,
        code: Option<String>,
    },

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("Query builder error: {0}")]
    QueryBuilder(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Expected exactly one row, but got none")]
    NoRows,

    #[error("Expected at most one row, but got {0}")]
    MultipleRows(usize),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Auth error: {0}")]
    Auth(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Realtime error: {0}")]
    Realtime(String),

    #[error("Functions error: {0}")]
    Functions(String),

    #[error("GraphQL error: {0}")]
    GraphQL(String),
}

impl SupabaseError {
    pub fn query_builder(msg: impl Into<String>) -> Self {
        Self::QueryBuilder(msg.into())
    }

    pub fn serialization(msg: impl Into<String>) -> Self {
        Self::Serialization(msg.into())
    }

    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    pub fn postgrest(status: u16, message: impl Into<String>, code: Option<String>) -> Self {
        Self::PostgRest {
            status,
            message: message.into(),
            code,
        }
    }
}

impl From<serde_json::Error> for SupabaseError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}

impl From<reqwest::Error> for SupabaseError {
    fn from(e: reqwest::Error) -> Self {
        Self::Http(e.to_string())
    }
}

/// Result alias using SupabaseError.
pub type SupabaseResult<T> = Result<T, SupabaseError>;

/// HTTP-like status codes for response metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusCode {
    Ok = 200,
    Created = 201,
    NoContent = 204,
    NotFound = 404,
    Conflict = 409,
    InternalError = 500,
}

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => write!(f, "200 OK"),
            Self::Created => write!(f, "201 Created"),
            Self::NoContent => write!(f, "204 No Content"),
            Self::NotFound => write!(f, "404 Not Found"),
            Self::Conflict => write!(f, "409 Conflict"),
            Self::InternalError => write!(f, "500 Internal Server Error"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Constructor tests ---

    #[test]
    fn test_query_builder_constructor() {
        let err = SupabaseError::query_builder("bad query");
        match err {
            SupabaseError::QueryBuilder(msg) => assert_eq!(msg, "bad query"),
            other => panic!("Expected QueryBuilder, got {:?}", other),
        }
    }

    #[test]
    fn test_query_builder_constructor_with_string() {
        let err = SupabaseError::query_builder(String::from("owned message"));
        match err {
            SupabaseError::QueryBuilder(msg) => assert_eq!(msg, "owned message"),
            other => panic!("Expected QueryBuilder, got {:?}", other),
        }
    }

    #[test]
    fn test_serialization_constructor() {
        let err = SupabaseError::serialization("invalid json");
        match err {
            SupabaseError::Serialization(msg) => assert_eq!(msg, "invalid json"),
            other => panic!("Expected Serialization, got {:?}", other),
        }
    }

    #[test]
    fn test_config_constructor() {
        let err = SupabaseError::config("missing url");
        match err {
            SupabaseError::Config(msg) => assert_eq!(msg, "missing url"),
            other => panic!("Expected Config, got {:?}", other),
        }
    }

    #[test]
    fn test_postgrest_constructor_with_code() {
        let err = SupabaseError::postgrest(404, "not found", Some("PGRST116".to_string()));
        match err {
            SupabaseError::PostgRest {
                status,
                message,
                code,
            } => {
                assert_eq!(status, 404);
                assert_eq!(message, "not found");
                assert_eq!(code, Some("PGRST116".to_string()));
            }
            other => panic!("Expected PostgRest, got {:?}", other),
        }
    }

    #[test]
    fn test_postgrest_constructor_without_code() {
        let err = SupabaseError::postgrest(500, "server error", None);
        match err {
            SupabaseError::PostgRest {
                status,
                message,
                code,
            } => {
                assert_eq!(status, 500);
                assert_eq!(message, "server error");
                assert_eq!(code, None);
            }
            other => panic!("Expected PostgRest, got {:?}", other),
        }
    }

    // --- From conversion tests ---

    #[test]
    fn test_from_serde_json_error() {
        let json_err = serde_json::from_str::<String>("not valid json").unwrap_err();
        let err: SupabaseError = json_err.into();
        match err {
            SupabaseError::Serialization(msg) => {
                assert!(!msg.is_empty(), "Error message should not be empty");
            }
            other => panic!("Expected Serialization, got {:?}", other),
        }
    }

    #[test]
    fn test_from_reqwest_error() {
        // Create a reqwest error by trying to build a request with an invalid URL
        let reqwest_err = reqwest::Client::new()
            .get("://invalid-url")
            .build()
            .unwrap_err();
        let err: SupabaseError = reqwest_err.into();
        match err {
            SupabaseError::Http(msg) => {
                assert!(!msg.is_empty(), "Error message should not be empty");
            }
            other => panic!("Expected Http, got {:?}", other),
        }
    }

    // --- StatusCode Display tests ---

    #[test]
    fn test_status_code_display_ok() {
        assert_eq!(StatusCode::Ok.to_string(), "200 OK");
    }

    #[test]
    fn test_status_code_display_created() {
        assert_eq!(StatusCode::Created.to_string(), "201 Created");
    }

    #[test]
    fn test_status_code_display_no_content() {
        assert_eq!(StatusCode::NoContent.to_string(), "204 No Content");
    }

    #[test]
    fn test_status_code_display_not_found() {
        assert_eq!(StatusCode::NotFound.to_string(), "404 Not Found");
    }

    #[test]
    fn test_status_code_display_conflict() {
        assert_eq!(StatusCode::Conflict.to_string(), "409 Conflict");
    }

    #[test]
    fn test_status_code_display_internal_error() {
        assert_eq!(
            StatusCode::InternalError.to_string(),
            "500 Internal Server Error"
        );
    }

    // --- SupabaseError Display tests ---

    #[test]
    fn test_display_graphql() {
        let err = SupabaseError::GraphQL("query failed".to_string());
        assert_eq!(err.to_string(), "GraphQL error: query failed");
    }

    #[test]
    fn test_display_no_rows() {
        let err = SupabaseError::NoRows;
        assert_eq!(err.to_string(), "Expected exactly one row, but got none");
    }

    #[test]
    fn test_display_multiple_rows() {
        let err = SupabaseError::MultipleRows(5);
        assert_eq!(err.to_string(), "Expected at most one row, but got 5");
    }

    #[test]
    fn test_display_auth() {
        let err = SupabaseError::Auth("invalid token".to_string());
        assert_eq!(err.to_string(), "Auth error: invalid token");
    }

    #[test]
    fn test_display_storage() {
        let err = SupabaseError::Storage("bucket not found".to_string());
        assert_eq!(err.to_string(), "Storage error: bucket not found");
    }

    #[test]
    fn test_display_realtime() {
        let err = SupabaseError::Realtime("connection lost".to_string());
        assert_eq!(err.to_string(), "Realtime error: connection lost");
    }

    #[test]
    fn test_display_functions() {
        let err = SupabaseError::Functions("timeout".to_string());
        assert_eq!(err.to_string(), "Functions error: timeout");
    }

    #[test]
    fn test_display_http() {
        let err = SupabaseError::Http("connection refused".to_string());
        assert_eq!(err.to_string(), "HTTP error: connection refused");
    }

    #[test]
    fn test_display_query_builder() {
        let err = SupabaseError::QueryBuilder("invalid filter".to_string());
        assert_eq!(err.to_string(), "Query builder error: invalid filter");
    }

    #[test]
    fn test_display_serialization() {
        let err = SupabaseError::Serialization("parse failed".to_string());
        assert_eq!(err.to_string(), "Serialization error: parse failed");
    }

    #[test]
    fn test_display_config() {
        let err = SupabaseError::Config("missing key".to_string());
        assert_eq!(err.to_string(), "Configuration error: missing key");
    }

    #[test]
    fn test_display_postgrest() {
        let err = SupabaseError::PostgRest {
            status: 400,
            message: "bad request".to_string(),
            code: Some("PGRST100".to_string()),
        };
        assert_eq!(err.to_string(), "PostgREST error (400): bad request");
    }

    // --- StatusCode equality and copy ---

    #[test]
    fn test_status_code_equality() {
        assert_eq!(StatusCode::Ok, StatusCode::Ok);
        assert_ne!(StatusCode::Ok, StatusCode::Created);
    }

    #[test]
    fn test_status_code_copy() {
        let s = StatusCode::Ok;
        let s2 = s; // copy
        assert_eq!(s, s2);
    }
}
