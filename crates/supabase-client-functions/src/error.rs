use serde::Deserialize;
use supabase_client_core::SupabaseError;

/// Error response format from Supabase Edge Functions.
#[derive(Debug, Clone, Deserialize)]
pub struct FunctionsApiErrorResponse {
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

impl FunctionsApiErrorResponse {
    /// Extract the most informative error message from the response.
    pub fn error_message(&self) -> String {
        self.message
            .as_deref()
            .or(self.error.as_deref())
            .unwrap_or("Unknown error")
            .to_string()
    }
}

/// Edge Functions-specific errors.
#[derive(Debug, thiserror::Error)]
pub enum FunctionsError {
    /// HTTP transport error from reqwest.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// Function returned non-2xx status (JS: FunctionsHttpError).
    #[error("Functions HTTP error ({status}): {message}")]
    HttpError { status: u16, message: String },

    /// Relay/infrastructure error, detected via `x-relay-error: true` header (JS: FunctionsRelayError).
    #[error("Functions relay error ({status}): {message}")]
    RelayError { status: u16, message: String },

    /// Invalid configuration (missing URL or key).
    #[error("Invalid functions configuration: {0}")]
    InvalidConfig(String),

    /// JSON serialization/deserialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// URL parsing error.
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),
}

impl From<FunctionsError> for SupabaseError {
    fn from(err: FunctionsError) -> Self {
        SupabaseError::Functions(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_http_error() {
        let err = FunctionsError::HttpError {
            status: 400,
            message: "Bad Request".into(),
        };
        assert_eq!(err.to_string(), "Functions HTTP error (400): Bad Request");
    }

    #[test]
    fn error_display_relay_error() {
        let err = FunctionsError::RelayError {
            status: 502,
            message: "Function not found".into(),
        };
        assert_eq!(
            err.to_string(),
            "Functions relay error (502): Function not found"
        );
    }

    #[test]
    fn error_display_invalid_config() {
        let err = FunctionsError::InvalidConfig("missing url".into());
        assert_eq!(
            err.to_string(),
            "Invalid functions configuration: missing url"
        );
    }

    #[test]
    fn error_converts_to_supabase_error() {
        let err = FunctionsError::HttpError {
            status: 500,
            message: "Internal".into(),
        };
        let supa: SupabaseError = err.into();
        match supa {
            SupabaseError::Functions(msg) => assert!(msg.contains("Internal")),
            other => panic!("Expected Functions variant, got: {:?}", other),
        }
    }

    #[test]
    fn api_error_response_deserialization() {
        let json = r#"{"error":"not_found","message":"Function not found"}"#;
        let resp: FunctionsApiErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.error.as_deref(), Some("not_found"));
        assert_eq!(resp.message.as_deref(), Some("Function not found"));
        assert_eq!(resp.error_message(), "Function not found");
    }

    #[test]
    fn api_error_response_fallback_to_error() {
        let json = r#"{"error":"Something went wrong"}"#;
        let resp: FunctionsApiErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.error_message(), "Something went wrong");
    }

    #[test]
    fn api_error_response_unknown() {
        let json = r#"{}"#;
        let resp: FunctionsApiErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.error_message(), "Unknown error");
    }
}
