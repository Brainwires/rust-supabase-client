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
