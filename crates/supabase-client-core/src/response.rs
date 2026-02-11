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
