use reqwest::header::{HeaderMap, HeaderValue};
use serde::de::DeserializeOwned;
use serde_json::Value as JsonValue;

use supabase_client_core::{StatusCode, SupabaseError, SupabaseResponse};

use crate::sql::{CountOption, SqlOperation, SqlParts};

/// Execute a PostgREST request and parse the response.
pub async fn execute_rest<T: DeserializeOwned + Send>(
    http: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    mut headers: HeaderMap,
    body: Option<JsonValue>,
    api_key: &str,
    schema: &str,
    parts: &SqlParts,
) -> SupabaseResponse<T> {
    // Add standard headers
    headers.insert("apikey", HeaderValue::from_str(api_key).unwrap());
    headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {}", api_key)).unwrap(),
    );

    // Set Accept-Profile / Content-Profile for schema if not already set
    if parts.schema_override.is_none() && schema != "public" {
        match parts.operation {
            SqlOperation::Select => {
                headers
                    .entry("Accept-Profile")
                    .or_insert_with(|| HeaderValue::from_str(schema).unwrap());
            }
            _ => {
                headers
                    .entry("Content-Profile")
                    .or_insert_with(|| HeaderValue::from_str(schema).unwrap());
            }
        }
    }

    // Default Accept to JSON if not already set
    headers
        .entry("Accept")
        .or_insert(HeaderValue::from_static("application/json"));

    tracing::debug!(
        method = %method,
        url = %url,
        "Executing PostgREST request"
    );

    let mut request = http.request(method.clone(), url).headers(headers);

    if let Some(body) = body {
        request = request.json(&body);
    }

    let response = match request.send().await {
        Ok(r) => r,
        Err(e) => return SupabaseResponse::error(SupabaseError::Http(e.to_string())),
    };

    let status_code = response.status().as_u16();
    let resp_headers = response.headers().clone();

    // For HEAD method (head mode), we just need the count from Content-Range
    if method == reqwest::Method::HEAD || parts.head {
        let count = parse_count_from_headers(&resp_headers);
        if status_code >= 200 && status_code < 300 {
            let mut resp = SupabaseResponse::<T>::ok(Vec::new());
            if let Some(c) = count {
                resp.count = Some(c);
            }
            return resp;
        } else {
            return SupabaseResponse::error(SupabaseError::postgrest(
                status_code,
                format!("HEAD request failed with status {}", status_code),
                None,
            ));
        }
    }

    // Read response body
    let body_text = match response.text().await {
        Ok(t) => t,
        Err(e) => return SupabaseResponse::error(SupabaseError::Http(e.to_string())),
    };

    // Handle error responses
    if status_code >= 400 {
        return parse_error_response(status_code, &body_text);
    }

    // Handle 204 No Content
    if status_code == 204 || body_text.is_empty() {
        let count = parse_count_from_headers(&resp_headers);
        let mut resp = SupabaseResponse::<T>::no_content();
        resp.count = count;
        return resp;
    }

    // Parse count from Content-Range header
    let count = parse_count_from_headers(&resp_headers);

    // Parse response based on whether single was requested
    if parts.single {
        // PostgREST returns a single object (not array) when Accept: application/vnd.pgrst.object+json
        match serde_json::from_str::<T>(&body_text) {
            Ok(item) => {
                let mut resp = build_response_from_operation(vec![item], parts);
                if let Some(c) = count {
                    resp.count = Some(c);
                }
                resp
            }
            Err(e) => SupabaseResponse::error(SupabaseError::Serialization(format!(
                "Failed to parse single response: {}",
                e
            ))),
        }
    } else {
        // Try to parse as array first (normal case)
        match serde_json::from_str::<Vec<T>>(&body_text) {
            Ok(data) => {
                let mut resp = build_response_from_operation(data, parts);
                if let Some(c) = count {
                    resp.count = Some(c);
                }
                // Respect maybe_single
                if parts.maybe_single {
                    match resp.data.len() {
                        0 | 1 => {}
                        n => return SupabaseResponse::error(SupabaseError::MultipleRows(n)),
                    }
                }
                resp
            }
            Err(_) => {
                // Maybe it's a single object (e.g., insert with return=representation)
                match serde_json::from_str::<T>(&body_text) {
                    Ok(item) => {
                        let mut resp = build_response_from_operation(vec![item], parts);
                        if let Some(c) = count {
                            resp.count = Some(c);
                        }
                        resp
                    }
                    Err(_) => {
                        // Handle scalar responses from PostgREST (e.g., scalar RPC functions
                        // return bare values like `10` or `"hello"` instead of JSON arrays).
                        // Wrap the scalar in an object keyed by the function/table name.
                        match serde_json::from_str::<JsonValue>(&body_text) {
                            Ok(scalar) if !scalar.is_array() && !scalar.is_object() => {
                                let wrapped = format!(
                                    "[{{\"{}\": {}}}]",
                                    parts.table, body_text
                                );
                                match serde_json::from_str::<Vec<T>>(&wrapped) {
                                    Ok(data) => {
                                        let mut resp =
                                            build_response_from_operation(data, parts);
                                        if let Some(c) = count {
                                            resp.count = Some(c);
                                        }
                                        resp
                                    }
                                    Err(e) => SupabaseResponse::error(
                                        SupabaseError::Serialization(format!(
                                            "Failed to parse scalar response: {}",
                                            e
                                        )),
                                    ),
                                }
                            }
                            _ => SupabaseResponse::error(SupabaseError::Serialization(
                                format!(
                                    "Failed to parse response: {}",
                                    body_text
                                ),
                            )),
                        }
                    }
                }
            }
        }
    }
}

fn build_response_from_operation<T>(data: Vec<T>, parts: &SqlParts) -> SupabaseResponse<T> {
    let status = match parts.operation {
        SqlOperation::Insert | SqlOperation::Upsert => StatusCode::Created,
        _ => StatusCode::Ok,
    };

    let count = if parts.count != CountOption::None {
        Some(data.len() as i64)
    } else {
        None
    };

    SupabaseResponse {
        data,
        error: None,
        count,
        status,
    }
}

fn parse_count_from_headers(headers: &HeaderMap) -> Option<i64> {
    // PostgREST returns count in Content-Range header: "0-9/100" or "*/100"
    headers
        .get("content-range")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            if let Some(slash_pos) = s.rfind('/') {
                let count_str = &s[slash_pos + 1..];
                if count_str == "*" {
                    None
                } else {
                    count_str.parse::<i64>().ok()
                }
            } else {
                None
            }
        })
}

fn parse_error_response<T>(status_code: u16, body: &str) -> SupabaseResponse<T> {
    // PostgREST error format: { "message": "...", "code": "...", "details": "...", "hint": "..." }
    if let Ok(error_obj) = serde_json::from_str::<JsonValue>(body) {
        let message = error_obj
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error")
            .to_string();
        let code = error_obj
            .get("code")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        SupabaseResponse::error(SupabaseError::postgrest(status_code, message, code))
    } else {
        SupabaseResponse::error(SupabaseError::postgrest(
            status_code,
            body.to_string(),
            None,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // ---- parse_count_from_headers ----

    #[test]
    fn test_parse_count_range_format() {
        let mut headers = HeaderMap::new();
        headers.insert("content-range", HeaderValue::from_static("0-9/100"));
        assert_eq!(parse_count_from_headers(&headers), Some(100));
    }

    #[test]
    fn test_parse_count_star_range_format() {
        let mut headers = HeaderMap::new();
        headers.insert("content-range", HeaderValue::from_static("*/42"));
        assert_eq!(parse_count_from_headers(&headers), Some(42));
    }

    #[test]
    fn test_parse_count_star_count() {
        let mut headers = HeaderMap::new();
        headers.insert("content-range", HeaderValue::from_static("0-9/*"));
        assert_eq!(parse_count_from_headers(&headers), None);
    }

    #[test]
    fn test_parse_count_no_header() {
        let headers = HeaderMap::new();
        assert_eq!(parse_count_from_headers(&headers), None);
    }

    #[test]
    fn test_parse_count_no_slash() {
        let mut headers = HeaderMap::new();
        headers.insert("content-range", HeaderValue::from_static("0-9"));
        assert_eq!(parse_count_from_headers(&headers), None);
    }

    #[test]
    fn test_parse_count_invalid_number() {
        let mut headers = HeaderMap::new();
        headers.insert("content-range", HeaderValue::from_static("0-9/abc"));
        assert_eq!(parse_count_from_headers(&headers), None);
    }

    #[test]
    fn test_parse_count_large_number() {
        let mut headers = HeaderMap::new();
        headers.insert("content-range", HeaderValue::from_static("0-99/1000000"));
        assert_eq!(parse_count_from_headers(&headers), Some(1_000_000));
    }

    // ---- parse_error_response ----

    #[test]
    fn test_parse_error_response_valid_json() {
        let body = r#"{"message":"Row not found","code":"PGRST116","details":null,"hint":null}"#;
        let resp: SupabaseResponse<JsonValue> = parse_error_response(404, body);
        assert!(resp.is_err());
        match resp.error.as_ref().unwrap() {
            SupabaseError::PostgRest { status, message, code } => {
                assert_eq!(*status, 404);
                assert_eq!(message, "Row not found");
                assert_eq!(code.as_deref(), Some("PGRST116"));
            }
            other => panic!("Expected PostgRest error, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_error_response_valid_json_no_code() {
        let body = r#"{"message":"Something went wrong"}"#;
        let resp: SupabaseResponse<JsonValue> = parse_error_response(500, body);
        assert!(resp.is_err());
        match resp.error.as_ref().unwrap() {
            SupabaseError::PostgRest { status, message, code } => {
                assert_eq!(*status, 500);
                assert_eq!(message, "Something went wrong");
                assert!(code.is_none());
            }
            other => panic!("Expected PostgRest error, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_error_response_no_message_field() {
        let body = r#"{"error":"some error"}"#;
        let resp: SupabaseResponse<JsonValue> = parse_error_response(400, body);
        assert!(resp.is_err());
        match resp.error.as_ref().unwrap() {
            SupabaseError::PostgRest { message, .. } => {
                assert_eq!(message, "Unknown error");
            }
            other => panic!("Expected PostgRest error, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_error_response_invalid_json() {
        let body = "this is not json";
        let resp: SupabaseResponse<JsonValue> = parse_error_response(500, body);
        assert!(resp.is_err());
        match resp.error.as_ref().unwrap() {
            SupabaseError::PostgRest { status, message, code } => {
                assert_eq!(*status, 500);
                assert_eq!(message, "this is not json");
                assert!(code.is_none());
            }
            other => panic!("Expected PostgRest error, got {:?}", other),
        }
    }

    // ---- execute_rest via wiremock ----

    fn make_select_parts(table: &str) -> SqlParts {
        SqlParts::new(SqlOperation::Select, "public", table)
    }

    #[tokio::test]
    async fn test_execute_rest_select_json_array() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/v1/users"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!([{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}])),
            )
            .mount(&mock_server)
            .await;

        let http = reqwest::Client::new();
        let url = format!("{}/rest/v1/users", mock_server.uri());
        let headers = HeaderMap::new();
        let parts = make_select_parts("users");

        let resp: SupabaseResponse<JsonValue> =
            execute_rest(&http, reqwest::Method::GET, &url, headers, None, "test-key", "public", &parts).await;

        assert!(resp.is_ok());
        assert_eq!(resp.data.len(), 2);
        assert_eq!(resp.data[0]["id"], 1);
        assert_eq!(resp.data[0]["name"], "Alice");
        assert_eq!(resp.data[1]["id"], 2);
        assert_eq!(resp.data[1]["name"], "Bob");
    }

    #[tokio::test]
    async fn test_execute_rest_select_single_object() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/v1/users"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"id": 1, "name": "Alice"})),
            )
            .mount(&mock_server)
            .await;

        let http = reqwest::Client::new();
        let url = format!("{}/rest/v1/users", mock_server.uri());
        let headers = HeaderMap::new();
        let mut parts = make_select_parts("users");
        parts.single = true;

        let resp: SupabaseResponse<JsonValue> =
            execute_rest(&http, reqwest::Method::GET, &url, headers, None, "test-key", "public", &parts).await;

        assert!(resp.is_ok());
        assert_eq!(resp.data.len(), 1);
        assert_eq!(resp.data[0]["id"], 1);
        assert_eq!(resp.data[0]["name"], "Alice");
    }

    #[tokio::test]
    async fn test_execute_rest_head_with_count() {
        let mock_server = MockServer::start().await;
        Mock::given(method("HEAD"))
            .and(path("/rest/v1/users"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-range", "0-9/42"),
            )
            .mount(&mock_server)
            .await;

        let http = reqwest::Client::new();
        let url = format!("{}/rest/v1/users", mock_server.uri());
        let headers = HeaderMap::new();
        let mut parts = make_select_parts("users");
        parts.head = true;

        let resp: SupabaseResponse<JsonValue> =
            execute_rest(&http, reqwest::Method::HEAD, &url, headers, None, "test-key", "public", &parts).await;

        assert!(resp.is_ok());
        assert!(resp.data.is_empty());
        assert_eq!(resp.count, Some(42));
    }

    #[tokio::test]
    async fn test_execute_rest_head_error_status() {
        let mock_server = MockServer::start().await;
        Mock::given(method("HEAD"))
            .and(path("/rest/v1/users"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let http = reqwest::Client::new();
        let url = format!("{}/rest/v1/users", mock_server.uri());
        let headers = HeaderMap::new();
        let mut parts = make_select_parts("users");
        parts.head = true;

        let resp: SupabaseResponse<JsonValue> =
            execute_rest(&http, reqwest::Method::HEAD, &url, headers, None, "test-key", "public", &parts).await;

        assert!(resp.is_err());
        match resp.error.as_ref().unwrap() {
            SupabaseError::PostgRest { status, .. } => {
                assert_eq!(*status, 401);
            }
            other => panic!("Expected PostgRest error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_execute_rest_4xx_error_json_body() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/v1/users"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(json!({"message": "Bad request", "code": "42703"})),
            )
            .mount(&mock_server)
            .await;

        let http = reqwest::Client::new();
        let url = format!("{}/rest/v1/users", mock_server.uri());
        let headers = HeaderMap::new();
        let parts = make_select_parts("users");

        let resp: SupabaseResponse<JsonValue> =
            execute_rest(&http, reqwest::Method::GET, &url, headers, None, "test-key", "public", &parts).await;

        assert!(resp.is_err());
        match resp.error.as_ref().unwrap() {
            SupabaseError::PostgRest { status, message, code } => {
                assert_eq!(*status, 400);
                assert_eq!(message, "Bad request");
                assert_eq!(code.as_deref(), Some("42703"));
            }
            other => panic!("Expected PostgRest error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_execute_rest_204_no_content() {
        let mock_server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/rest/v1/users"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&mock_server)
            .await;

        let http = reqwest::Client::new();
        let url = format!("{}/rest/v1/users", mock_server.uri());
        let headers = HeaderMap::new();
        let mut parts = SqlParts::new(SqlOperation::Delete, "public", "users");
        // No returning - expect 204
        parts.returning = None;

        let resp: SupabaseResponse<JsonValue> =
            execute_rest(&http, reqwest::Method::DELETE, &url, headers, None, "test-key", "public", &parts).await;

        assert!(resp.is_ok());
        assert!(resp.data.is_empty());
    }

    #[tokio::test]
    async fn test_execute_rest_empty_body_response() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rest/v1/users"))
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
            .mount(&mock_server)
            .await;

        let http = reqwest::Client::new();
        let url = format!("{}/rest/v1/users", mock_server.uri());
        let headers = HeaderMap::new();
        let parts = SqlParts::new(SqlOperation::Insert, "public", "users");

        let resp: SupabaseResponse<JsonValue> =
            execute_rest(&http, reqwest::Method::POST, &url, headers, None, "test-key", "public", &parts).await;

        assert!(resp.is_ok());
        assert!(resp.data.is_empty());
    }

    #[tokio::test]
    async fn test_execute_rest_insert_returns_created_status() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rest/v1/users"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(json!([{"id": 1, "name": "Alice"}])),
            )
            .mount(&mock_server)
            .await;

        let http = reqwest::Client::new();
        let url = format!("{}/rest/v1/users", mock_server.uri());
        let headers = HeaderMap::new();
        let parts = SqlParts::new(SqlOperation::Insert, "public", "users");

        let resp: SupabaseResponse<JsonValue> =
            execute_rest(&http, reqwest::Method::POST, &url, headers, None, "test-key", "public", &parts).await;

        assert!(resp.is_ok());
        assert_eq!(resp.data.len(), 1);
        assert_eq!(resp.status, supabase_client_core::StatusCode::Created);
    }

    #[tokio::test]
    async fn test_execute_rest_with_count_header() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/v1/users"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!([{"id": 1}]))
                    .insert_header("content-range", "0-0/25"),
            )
            .mount(&mock_server)
            .await;

        let http = reqwest::Client::new();
        let url = format!("{}/rest/v1/users", mock_server.uri());
        let headers = HeaderMap::new();
        let parts = make_select_parts("users");

        let resp: SupabaseResponse<JsonValue> =
            execute_rest(&http, reqwest::Method::GET, &url, headers, None, "test-key", "public", &parts).await;

        assert!(resp.is_ok());
        assert_eq!(resp.count, Some(25));
    }

    #[tokio::test]
    async fn test_execute_rest_sets_auth_headers() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/v1/users"))
            .and(wiremock::matchers::header("apikey", "my-secret-key"))
            .and(wiremock::matchers::header("Authorization", "Bearer my-secret-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&mock_server)
            .await;

        let http = reqwest::Client::new();
        let url = format!("{}/rest/v1/users", mock_server.uri());
        let headers = HeaderMap::new();
        let parts = make_select_parts("users");

        let resp: SupabaseResponse<JsonValue> =
            execute_rest(&http, reqwest::Method::GET, &url, headers, None, "my-secret-key", "public", &parts).await;

        assert!(resp.is_ok());
    }

    #[tokio::test]
    async fn test_execute_rest_non_public_schema_sets_profile() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/v1/users"))
            .and(wiremock::matchers::header("Accept-Profile", "custom_schema"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&mock_server)
            .await;

        let http = reqwest::Client::new();
        let url = format!("{}/rest/v1/users", mock_server.uri());
        let headers = HeaderMap::new();
        let parts = make_select_parts("users");

        let resp: SupabaseResponse<JsonValue> =
            execute_rest(&http, reqwest::Method::GET, &url, headers, None, "key", "custom_schema", &parts).await;

        assert!(resp.is_ok());
    }

    #[tokio::test]
    async fn test_execute_rest_with_body() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rest/v1/users"))
            .and(wiremock::matchers::body_json(json!({"name": "Alice"})))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(json!([{"id": 1, "name": "Alice"}])),
            )
            .mount(&mock_server)
            .await;

        let http = reqwest::Client::new();
        let url = format!("{}/rest/v1/users", mock_server.uri());
        let headers = HeaderMap::new();
        let parts = SqlParts::new(SqlOperation::Insert, "public", "users");

        let resp: SupabaseResponse<JsonValue> =
            execute_rest(
                &http, reqwest::Method::POST, &url, headers,
                Some(json!({"name": "Alice"})), "key", "public", &parts,
            ).await;

        assert!(resp.is_ok());
        assert_eq!(resp.data.len(), 1);
    }

    #[tokio::test]
    async fn test_execute_rest_maybe_single_with_one_row() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/v1/users"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!([{"id": 1}])),
            )
            .mount(&mock_server)
            .await;

        let http = reqwest::Client::new();
        let url = format!("{}/rest/v1/users", mock_server.uri());
        let headers = HeaderMap::new();
        let mut parts = make_select_parts("users");
        parts.maybe_single = true;

        let resp: SupabaseResponse<JsonValue> =
            execute_rest(&http, reqwest::Method::GET, &url, headers, None, "key", "public", &parts).await;

        assert!(resp.is_ok());
        assert_eq!(resp.data.len(), 1);
    }

    #[tokio::test]
    async fn test_execute_rest_maybe_single_with_multiple_rows_errors() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/v1/users"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!([{"id": 1}, {"id": 2}, {"id": 3}])),
            )
            .mount(&mock_server)
            .await;

        let http = reqwest::Client::new();
        let url = format!("{}/rest/v1/users", mock_server.uri());
        let headers = HeaderMap::new();
        let mut parts = make_select_parts("users");
        parts.maybe_single = true;

        let resp: SupabaseResponse<JsonValue> =
            execute_rest(&http, reqwest::Method::GET, &url, headers, None, "key", "public", &parts).await;

        assert!(resp.is_err());
        assert!(matches!(resp.error.as_ref().unwrap(), SupabaseError::MultipleRows(3)));
    }

    #[tokio::test]
    async fn test_execute_rest_scalar_response() {
        // When PostgREST returns a bare scalar (e.g., from an RPC function),
        // the parser falls through to the single-object parse path since
        // serde_json::Value can parse any valid JSON. The result is a Vec
        // containing the scalar value directly.
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/v1/my_func"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("42"),
            )
            .mount(&mock_server)
            .await;

        let http = reqwest::Client::new();
        let url = format!("{}/rest/v1/my_func", mock_server.uri());
        let headers = HeaderMap::new();
        let parts = make_select_parts("my_func");

        let resp: SupabaseResponse<JsonValue> =
            execute_rest(&http, reqwest::Method::GET, &url, headers, None, "key", "public", &parts).await;

        assert!(resp.is_ok());
        assert_eq!(resp.data.len(), 1);
        // serde_json::Value parses "42" as Number(42) in the single-object fallback
        assert_eq!(resp.data[0], serde_json::json!(42));
    }
}
