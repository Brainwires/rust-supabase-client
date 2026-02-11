use std::fmt;

/// All errors that can occur in the supabase-client crate.
#[derive(Debug, thiserror::Error)]
pub enum SupabaseError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

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
}

impl From<serde_json::Error> for SupabaseError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e.to_string())
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
