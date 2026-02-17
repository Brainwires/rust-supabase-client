use crate::error::{StatusCode, SupabaseError};

/// Response type matching Supabase's `{ data, error, count, status }` pattern.
#[derive(Debug)]
pub struct SupabaseResponse<T> {
    /// The returned data (empty Vec on error).
    pub data: Vec<T>,
    /// Error, if any.
    pub error: Option<SupabaseError>,
    /// Row count (if count was requested).
    pub count: Option<i64>,
    /// HTTP-like status code.
    pub status: StatusCode,
}

impl<T> SupabaseResponse<T> {
    /// Create a successful response with data.
    pub fn ok(data: Vec<T>) -> Self {
        Self {
            data,
            error: None,
            count: None,
            status: StatusCode::Ok,
        }
    }

    /// Create a successful response with data and count.
    pub fn ok_with_count(data: Vec<T>, count: i64) -> Self {
        Self {
            data,
            error: None,
            count: Some(count),
            status: StatusCode::Ok,
        }
    }

    /// Create a created (201) response (for inserts).
    pub fn created(data: Vec<T>) -> Self {
        Self {
            data,
            error: None,
            count: None,
            status: StatusCode::Created,
        }
    }

    /// Create an error response.
    pub fn error(err: SupabaseError) -> Self {
        let status = match &err {
            SupabaseError::NoRows => StatusCode::NotFound,
            #[cfg(feature = "direct-sql")]
            SupabaseError::Database(_) => StatusCode::InternalError,
            _ => StatusCode::InternalError,
        };
        Self {
            data: Vec::new(),
            error: Some(err),
            count: None,
            status,
        }
    }

    /// Create a no-content (204) response (for deletes without RETURNING).
    pub fn no_content() -> Self {
        Self {
            data: Vec::new(),
            error: None,
            count: None,
            status: StatusCode::NoContent,
        }
    }

    /// Check if the response is successful.
    pub fn is_ok(&self) -> bool {
        self.error.is_none()
    }

    /// Check if the response has an error.
    pub fn is_err(&self) -> bool {
        self.error.is_some()
    }

    /// Convert into a Result, consuming the response.
    /// Returns the data vec on success, or the error on failure.
    pub fn into_result(self) -> Result<Vec<T>, SupabaseError> {
        match self.error {
            Some(err) => Err(err),
            None => Ok(self.data),
        }
    }

    /// Get the first item, or None if empty.
    pub fn first(&self) -> Option<&T> {
        self.data.first()
    }

    /// Consume and return exactly one row, or error.
    pub fn into_single(self) -> Result<T, SupabaseError> {
        if let Some(err) = self.error {
            return Err(err);
        }
        let mut data = self.data;
        match data.len() {
            0 => Err(SupabaseError::NoRows),
            1 => Ok(data.remove(0)),
            n => Err(SupabaseError::MultipleRows(n)),
        }
    }

    /// Consume and return zero or one row.
    pub fn into_maybe_single(self) -> Result<Option<T>, SupabaseError> {
        if let Some(err) = self.error {
            return Err(err);
        }
        let mut data = self.data;
        match data.len() {
            0 => Ok(None),
            1 => Ok(Some(data.remove(0))),
            n => Err(SupabaseError::MultipleRows(n)),
        }
    }
}

impl<T> SupabaseResponse<T>
where
    T: Clone,
{
    /// Set the status code.
    pub fn with_status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    /// Set the count.
    pub fn with_count(mut self, count: i64) -> Self {
        self.count = Some(count);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ok_response() {
        let resp = SupabaseResponse::ok(vec![1, 2, 3]);
        assert_eq!(resp.data, vec![1, 2, 3]);
        assert!(resp.error.is_none());
        assert_eq!(resp.status, StatusCode::Ok);
        assert_eq!(resp.count, None);
    }

    #[test]
    fn test_ok_with_count() {
        let resp = SupabaseResponse::ok_with_count(vec!["a", "b"], 10);
        assert_eq!(resp.data, vec!["a", "b"]);
        assert_eq!(resp.count, Some(10));
        assert_eq!(resp.status, StatusCode::Ok);
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_created_response() {
        let resp = SupabaseResponse::created(vec![42]);
        assert_eq!(resp.data, vec![42]);
        assert_eq!(resp.status, StatusCode::Created);
        assert!(resp.error.is_none());
        assert_eq!(resp.count, None);
    }

    #[test]
    fn test_error_response_no_rows() {
        let resp = SupabaseResponse::<i32>::error(SupabaseError::NoRows);
        assert!(resp.data.is_empty());
        assert_eq!(resp.status, StatusCode::NotFound);
        assert!(resp.error.is_some());
    }

    #[test]
    fn test_error_response_generic() {
        let resp =
            SupabaseResponse::<i32>::error(SupabaseError::Http("connection failed".to_string()));
        assert!(resp.data.is_empty());
        assert_eq!(resp.status, StatusCode::InternalError);
        assert!(resp.error.is_some());
    }

    #[test]
    fn test_no_content_response() {
        let resp = SupabaseResponse::<String>::no_content();
        assert!(resp.data.is_empty());
        assert_eq!(resp.status, StatusCode::NoContent);
        assert!(resp.error.is_none());
        assert_eq!(resp.count, None);
    }

    #[test]
    fn test_is_ok_for_ok_response() {
        let resp = SupabaseResponse::ok(vec![1]);
        assert!(resp.is_ok());
        assert!(!resp.is_err());
    }

    #[test]
    fn test_is_err_for_error_response() {
        let resp = SupabaseResponse::<i32>::error(SupabaseError::NoRows);
        assert!(resp.is_err());
        assert!(!resp.is_ok());
    }

    #[test]
    fn test_into_result_ok_path() {
        let resp = SupabaseResponse::ok(vec![10, 20, 30]);
        let result = resp.into_result();
        assert_eq!(result.unwrap(), vec![10, 20, 30]);
    }

    #[test]
    fn test_into_result_error_path() {
        let resp = SupabaseResponse::<i32>::error(SupabaseError::NoRows);
        let result = resp.into_result();
        assert!(result.is_err());
    }

    #[test]
    fn test_first_non_empty() {
        let resp = SupabaseResponse::ok(vec![100, 200]);
        assert_eq!(resp.first(), Some(&100));
    }

    #[test]
    fn test_first_empty() {
        let resp = SupabaseResponse::<i32>::ok(vec![]);
        assert_eq!(resp.first(), None);
    }

    #[test]
    fn test_into_single_with_one_row() {
        let resp = SupabaseResponse::ok(vec![42]);
        let result = resp.into_single();
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_into_single_with_zero_rows() {
        let resp = SupabaseResponse::<i32>::ok(vec![]);
        let result = resp.into_single();
        match result {
            Err(SupabaseError::NoRows) => {} // expected
            other => panic!("Expected NoRows, got {:?}", other),
        }
    }

    #[test]
    fn test_into_single_with_multiple_rows() {
        let resp = SupabaseResponse::ok(vec![1, 2, 3]);
        let result = resp.into_single();
        match result {
            Err(SupabaseError::MultipleRows(n)) => assert_eq!(n, 3),
            other => panic!("Expected MultipleRows(3), got {:?}", other),
        }
    }

    #[test]
    fn test_into_single_with_error_set() {
        let resp = SupabaseResponse::<i32>::error(SupabaseError::Config("bad".to_string()));
        let result = resp.into_single();
        match result {
            Err(SupabaseError::Config(msg)) => assert_eq!(msg, "bad"),
            other => panic!("Expected Config error, got {:?}", other),
        }
    }

    #[test]
    fn test_into_maybe_single_with_zero_rows() {
        let resp = SupabaseResponse::<i32>::ok(vec![]);
        let result = resp.into_maybe_single();
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_into_maybe_single_with_one_row() {
        let resp = SupabaseResponse::ok(vec![99]);
        let result = resp.into_maybe_single();
        assert_eq!(result.unwrap(), Some(99));
    }

    #[test]
    fn test_into_maybe_single_with_multiple_rows() {
        let resp = SupabaseResponse::ok(vec![1, 2, 3]);
        let result = resp.into_maybe_single();
        match result {
            Err(SupabaseError::MultipleRows(n)) => assert_eq!(n, 3),
            other => panic!("Expected MultipleRows(3), got {:?}", other),
        }
    }

    #[test]
    fn test_into_maybe_single_with_error_set() {
        let resp =
            SupabaseResponse::<i32>::error(SupabaseError::Storage("no bucket".to_string()));
        let result = resp.into_maybe_single();
        match result {
            Err(SupabaseError::Storage(msg)) => assert_eq!(msg, "no bucket"),
            other => panic!("Expected Storage error, got {:?}", other),
        }
    }

    #[test]
    fn test_with_status_changes_status() {
        let resp = SupabaseResponse::ok(vec![1i32]).with_status(StatusCode::Created);
        assert_eq!(resp.status, StatusCode::Created);
    }

    #[test]
    fn test_with_count_sets_count() {
        let resp = SupabaseResponse::ok(vec![1i32]).with_count(42);
        assert_eq!(resp.count, Some(42));
    }
}
