use serde::Deserialize;
use supabase_client_core::SupabaseError;

/// Error response format from the Supabase Storage API.
#[derive(Debug, Clone, Deserialize)]
pub struct StorageApiErrorResponse {
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default, rename = "statusCode")]
    pub status_code: Option<String>,
}

impl StorageApiErrorResponse {
    /// Extract the most informative error message from the response.
    pub fn error_message(&self) -> String {
        self.message
            .as_deref()
            .or(self.error.as_deref())
            .unwrap_or("Unknown error")
            .to_string()
    }
}

/// Storage-specific errors.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// HTTP transport error from reqwest.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// Storage API returned an error response.
    #[error("Storage API error ({status}): {message}")]
    Api { status: u16, message: String },

    /// Invalid configuration (missing URL or key).
    #[error("Invalid storage configuration: {0}")]
    InvalidConfig(String),

    /// JSON serialization/deserialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// URL parsing error.
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),
}

impl From<StorageError> for SupabaseError {
    fn from(err: StorageError) -> Self {
        SupabaseError::Storage(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_api() {
        let err = StorageError::Api {
            status: 404,
            message: "Not found".into(),
        };
        assert_eq!(err.to_string(), "Storage API error (404): Not found");
    }

    #[test]
    fn error_display_invalid_config() {
        let err = StorageError::InvalidConfig("missing url".into());
        assert_eq!(
            err.to_string(),
            "Invalid storage configuration: missing url"
        );
    }

    #[test]
    fn error_converts_to_supabase_error() {
        let err = StorageError::Api {
            status: 500,
            message: "Internal".into(),
        };
        let supa: SupabaseError = err.into();
        match supa {
            SupabaseError::Storage(msg) => assert!(msg.contains("Internal")),
            other => panic!("Expected Storage variant, got: {:?}", other),
        }
    }

    #[test]
    fn api_error_response_deserialization() {
        let json = r#"{"error":"Bucket not found","message":"The resource was not found","statusCode":"404"}"#;
        let resp: StorageApiErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.error.as_deref(), Some("Bucket not found"));
        assert_eq!(
            resp.message.as_deref(),
            Some("The resource was not found")
        );
        assert_eq!(resp.status_code.as_deref(), Some("404"));
        // message takes priority
        assert_eq!(resp.error_message(), "The resource was not found");
    }

    #[test]
    fn api_error_response_fallback_to_error() {
        let json = r#"{"error":"Something went wrong"}"#;
        let resp: StorageApiErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.error_message(), "Something went wrong");
    }

    #[test]
    fn api_error_response_unknown() {
        let json = r#"{}"#;
        let resp: StorageApiErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.error_message(), "Unknown error");
    }
}
