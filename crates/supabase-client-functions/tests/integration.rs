//! Integration tests for supabase-client-functions.
//!
//! These tests require a running local Supabase instance started via `supabase start`.
//! Edge functions must be served via `supabase functions serve` (or automatically via `supabase start`).
//!
//! Run with: cargo test -p supabase-client-functions --test integration -- --test-threads=1

use supabase_client_functions::{
    FunctionRegion, FunctionsClient, FunctionsError, HttpMethod, InvokeOptions,
};

/// Default local Supabase URL (from `supabase start` output).
fn supabase_url() -> String {
    std::env::var("SUPABASE_URL").unwrap_or_else(|_| "http://127.0.0.1:64321".to_string())
}

/// Default local anon key.
fn anon_key() -> String {
    std::env::var("SUPABASE_ANON_KEY").unwrap_or_else(|_| {
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0".to_string()
    })
}

/// Default local service_role key.
fn service_role_key() -> String {
    std::env::var("SUPABASE_SERVICE_ROLE_KEY").unwrap_or_else(|_| {
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU".to_string()
    })
}

fn functions_client() -> FunctionsClient {
    FunctionsClient::new(&supabase_url(), &anon_key()).expect("Failed to create FunctionsClient")
}

fn should_skip() -> bool {
    std::env::var("SKIP_FUNCTIONS_TESTS").is_ok()
}

// ─── Unit Tests (no server needed) ────────────────────────────

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn functions_client_new_ok() {
        let client = FunctionsClient::new("https://example.supabase.co", "test-key");
        assert!(client.is_ok());
    }

    #[test]
    fn functions_client_base_url() {
        let client = FunctionsClient::new("https://example.supabase.co", "test-key").unwrap();
        assert_eq!(client.base_url().path(), "/functions/v1");
    }

    #[test]
    fn invoke_options_builder_chain() {
        let opts = InvokeOptions::new()
            .body(serde_json::json!({"test": true}))
            .method(HttpMethod::Put)
            .header("x-test", "value")
            .region(FunctionRegion::UsEast1)
            .authorization("Bearer custom-token");
        // Builder chain compiles and returns InvokeOptions
        let _ = opts;
    }
}

// ─── Integration Tests ────────────────────────────────────────

#[tokio::test]
async fn invoke_hello_with_json_body() {
    if should_skip() {
        return;
    }
    let client = functions_client();
    let response = client
        .invoke(
            "hello",
            InvokeOptions::new().body(serde_json::json!({"name": "World"})),
        )
        .await
        .expect("invoke failed");

    assert_eq!(response.status(), 200);
    let data: serde_json::Value = response.json().unwrap();
    assert_eq!(data["message"], "Hello World!");
}

#[tokio::test]
async fn invoke_hello_without_body() {
    if should_skip() {
        return;
    }
    let client = functions_client();
    let response = client
        .invoke("hello", InvokeOptions::new())
        .await
        .expect("invoke failed");

    assert_eq!(response.status(), 200);
    let data: serde_json::Value = response.json().unwrap();
    assert_eq!(data["message"], "Hello anonymous!");
}

#[tokio::test]
async fn invoke_with_custom_headers() {
    if should_skip() {
        return;
    }
    let client = functions_client();
    let response = client
        .invoke(
            "echo-headers",
            InvokeOptions::new()
                .header("x-custom-test", "my-value")
                .header("x-another", "second"),
        )
        .await
        .expect("invoke failed");

    assert_eq!(response.status(), 200);
    let data: serde_json::Value = response.json().unwrap();
    assert_eq!(data["headers"]["x-custom-test"], "my-value");
    assert_eq!(data["headers"]["x-another"], "second");
}

#[tokio::test]
async fn invoke_with_get_method() {
    if should_skip() {
        return;
    }
    let client = functions_client();
    let response = client
        .invoke("echo-method", InvokeOptions::new().method(HttpMethod::Get))
        .await
        .expect("invoke failed");

    assert_eq!(response.status(), 200);
    let data: serde_json::Value = response.json().unwrap();
    assert_eq!(data["method"], "GET");
}

#[tokio::test]
async fn invoke_with_put_method() {
    if should_skip() {
        return;
    }
    let client = functions_client();
    let response = client
        .invoke(
            "echo-method",
            InvokeOptions::new()
                .method(HttpMethod::Put)
                .body(serde_json::json!({"action": "update"})),
        )
        .await
        .expect("invoke failed");

    assert_eq!(response.status(), 200);
    let data: serde_json::Value = response.json().unwrap();
    assert_eq!(data["method"], "PUT");
    assert_eq!(data["body"]["action"], "update");
}

#[tokio::test]
async fn invoke_with_delete_method() {
    if should_skip() {
        return;
    }
    let client = functions_client();
    let response = client
        .invoke(
            "echo-method",
            InvokeOptions::new().method(HttpMethod::Delete),
        )
        .await
        .expect("invoke failed");

    assert_eq!(response.status(), 200);
    let data: serde_json::Value = response.json().unwrap();
    assert_eq!(data["method"], "DELETE");
}

#[tokio::test]
async fn invoke_with_patch_method() {
    if should_skip() {
        return;
    }
    let client = functions_client();
    let response = client
        .invoke(
            "echo-method",
            InvokeOptions::new()
                .method(HttpMethod::Patch)
                .body(serde_json::json!({"field": "value"})),
        )
        .await
        .expect("invoke failed");

    assert_eq!(response.status(), 200);
    let data: serde_json::Value = response.json().unwrap();
    assert_eq!(data["method"], "PATCH");
}

#[tokio::test]
async fn invoke_binary_default_response() {
    if should_skip() {
        return;
    }
    let client = functions_client();
    let response = client
        .invoke("echo-binary", InvokeOptions::new())
        .await
        .expect("invoke failed");

    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes(), &[0, 1, 2, 3, 4, 5, 255]);
}

#[tokio::test]
async fn invoke_binary_echo_round_trip() {
    if should_skip() {
        return;
    }
    let client = functions_client();
    let input = vec![10, 20, 30, 40, 50, 100, 200, 255];
    let response = client
        .invoke(
            "echo-binary",
            InvokeOptions::new().body_bytes(input.clone()),
        )
        .await
        .expect("invoke failed");

    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes(), &input);
}

#[tokio::test]
async fn invoke_nonexistent_function() {
    if should_skip() {
        return;
    }
    let client = functions_client();
    let result = client
        .invoke(
            "this-function-does-not-exist-xyz",
            InvokeOptions::new(),
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    match &err {
        FunctionsError::RelayError { status, .. } => {
            assert!(*status >= 400);
        }
        FunctionsError::HttpError { status, .. } => {
            assert!(*status >= 400);
        }
        _ => panic!("Expected RelayError or HttpError, got: {:?}", err),
    }
}

#[tokio::test]
async fn response_headers_accessible() {
    if should_skip() {
        return;
    }
    let client = functions_client();
    let response = client
        .invoke("hello", InvokeOptions::new())
        .await
        .expect("invoke failed");

    // The response should have a content-type header
    assert!(response.content_type().is_some());
    assert!(response
        .content_type()
        .unwrap()
        .contains("application/json"));
}

#[tokio::test]
async fn invoke_with_authorization_override() {
    if should_skip() {
        return;
    }
    let client = functions_client();
    let custom_auth = format!("Bearer {}", service_role_key());
    let response = client
        .invoke(
            "echo-headers",
            InvokeOptions::new().authorization(&custom_auth),
        )
        .await
        .expect("invoke failed");

    assert_eq!(response.status(), 200);
    let data: serde_json::Value = response.json().unwrap();
    // The authorization header should be our custom one
    let auth_header = data["headers"]["authorization"]
        .as_str()
        .unwrap_or_default();
    assert!(auth_header.contains(&service_role_key()));
}

#[tokio::test]
async fn invoke_with_region_header() {
    if should_skip() {
        return;
    }
    let client = functions_client();
    let response = client
        .invoke(
            "echo-headers",
            InvokeOptions::new().region(FunctionRegion::UsEast1),
        )
        .await
        .expect("invoke failed");

    assert_eq!(response.status(), 200);
    let data: serde_json::Value = response.json().unwrap();
    assert_eq!(data["headers"]["x-region"], "us-east-1");
}

#[tokio::test]
async fn invoke_full_lifecycle() {
    if should_skip() {
        return;
    }
    let client = functions_client();

    // 1. JSON invocation
    let resp = client
        .invoke(
            "hello",
            InvokeOptions::new().body(serde_json::json!({"name": "Rust"})),
        )
        .await
        .expect("hello invoke failed");
    let data: serde_json::Value = resp.json().unwrap();
    assert_eq!(data["message"], "Hello Rust!");

    // 2. Custom headers + GET
    let resp = client
        .invoke(
            "echo-headers",
            InvokeOptions::new()
                .method(HttpMethod::Get)
                .header("x-lifecycle", "test"),
        )
        .await
        .expect("echo-headers invoke failed");
    let data: serde_json::Value = resp.json().unwrap();
    assert_eq!(data["method"], "GET");
    assert_eq!(data["headers"]["x-lifecycle"], "test");

    // 3. Binary round-trip
    let input = vec![42, 43, 44];
    let resp = client
        .invoke(
            "echo-binary",
            InvokeOptions::new().body_bytes(input.clone()),
        )
        .await
        .expect("echo-binary invoke failed");
    assert_eq!(resp.bytes(), &input);
}
