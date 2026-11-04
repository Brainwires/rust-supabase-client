//! HTTP helpers shared by the service clients.

use std::fmt;

/// Largest error body read from a failed response. Anything past this is
/// discarded, so a misbehaving or hostile server cannot make the client buffer
/// an unbounded error message.
pub const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;

/// Error from [`read_body_limited`].
#[derive(Debug)]
pub enum BodyReadError {
    /// The transport failed while reading the body.
    Http(reqwest::Error),
    /// The body is larger than the allowed limit.
    TooLarge {
        /// The configured limit in bytes.
        limit: u64,
    },
}

impl fmt::Display for BodyReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BodyReadError::Http(e) => write!(f, "{}", e),
            BodyReadError::TooLarge { limit } => {
                write!(f, "response body exceeds the {} byte limit", limit)
            }
        }
    }
}

impl std::error::Error for BodyReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BodyReadError::Http(e) => Some(e),
            BodyReadError::TooLarge { .. } => None,
        }
    }
}

impl From<reqwest::Error> for BodyReadError {
    fn from(e: reqwest::Error) -> Self {
        BodyReadError::Http(e)
    }
}

/// Read a response body, failing with [`BodyReadError::TooLarge`] once more
/// than `limit` bytes arrive. `None` reads the whole body.
///
/// On native targets the body is streamed and reading stops at the limit. On
/// wasm32 the `Content-Length` header is checked first and the length of the
/// buffered body afterwards.
pub async fn read_body_limited(
    resp: reqwest::Response,
    limit: Option<u64>,
) -> Result<Vec<u8>, BodyReadError> {
    let Some(limit) = limit else {
        return Ok(resp.bytes().await?.to_vec());
    };
    if let Some(len) = resp.content_length() {
        if len > limit {
            return Err(BodyReadError::TooLarge { limit });
        }
    }
    read_capped(resp, limit).await
}

#[cfg(not(target_arch = "wasm32"))]
async fn read_capped(mut resp: reqwest::Response, limit: u64) -> Result<Vec<u8>, BodyReadError> {
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if buf.len() as u64 + chunk.len() as u64 > limit {
            return Err(BodyReadError::TooLarge { limit });
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

#[cfg(target_arch = "wasm32")]
async fn read_capped(resp: reqwest::Response, limit: u64) -> Result<Vec<u8>, BodyReadError> {
    let bytes = resp.bytes().await?;
    if bytes.len() as u64 > limit {
        return Err(BodyReadError::TooLarge { limit });
    }
    Ok(bytes.to_vec())
}

/// Read at most [`MAX_ERROR_BODY_BYTES`] of an error response body.
///
/// Bodies over the limit are truncated rather than rejected, since the caller
/// only wants a message out of them. Transport errors yield an empty body.
pub async fn read_error_body(resp: reqwest::Response) -> Vec<u8> {
    read_truncated(resp, MAX_ERROR_BODY_BYTES).await
}

#[cfg(not(target_arch = "wasm32"))]
async fn read_truncated(mut resp: reqwest::Response, limit: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    while let Ok(Some(chunk)) = resp.chunk().await {
        let room = limit - buf.len();
        if chunk.len() >= room {
            buf.extend_from_slice(&chunk[..room]);
            break;
        }
        buf.extend_from_slice(&chunk);
    }
    buf
}

#[cfg(target_arch = "wasm32")]
async fn read_truncated(resp: reqwest::Response, limit: usize) -> Vec<u8> {
    match resp.bytes().await {
        Ok(b) => b[..b.len().min(limit)].to_vec(),
        Err(_) => Vec::new(),
    }
}

/// Mark a header value as sensitive so it is omitted from `Debug` output.
pub fn sensitive_header(
    value: &str,
) -> Result<reqwest::header::HeaderValue, reqwest::header::InvalidHeaderValue> {
    let mut v = reqwest::header::HeaderValue::from_str(value)?;
    v.set_sensitive(true);
    Ok(v)
}

/// Build a sensitive `Authorization: Bearer <token>` header value.
pub fn bearer_header(
    token: &str,
) -> Result<reqwest::header::HeaderValue, reqwest::header::InvalidHeaderValue> {
    sensitive_header(&format!("Bearer {}", token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_header_is_redacted_in_debug() {
        let v = bearer_header("secret").unwrap();
        assert!(v.is_sensitive());
        assert!(!format!("{:?}", v).contains("secret"));
    }

    #[test]
    fn too_large_display() {
        let e = BodyReadError::TooLarge { limit: 10 };
        assert_eq!(e.to_string(), "response body exceeds the 10 byte limit");
    }
}
