use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
#[cfg(feature = "direct-sql")]
use sqlx::Row as SqlxRow;
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};

/// A dynamic row type wrapping a HashMap of column name to JSON value.
/// Used for the string-based (dynamic) API when not using typed structs.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Row(pub HashMap<String, JsonValue>);

impl Row {
    /// Create an empty row.
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    /// Create a row with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self(HashMap::with_capacity(capacity))
    }

    /// Set a column value.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<JsonValue>) -> &mut Self {
        self.0.insert(key.into(), value.into());
        self
    }

    /// Get a column value.
    pub fn get_value(&self, key: &str) -> Option<&JsonValue> {
        self.0.get(key)
    }

    /// Check if a column exists.
    pub fn contains(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    /// Get a typed value from a column, returning None if missing or wrong type.
    pub fn get_as<T: serde::de::DeserializeOwned>(&self, key: &str) -> Option<T> {
        self.0
            .get(key)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// Get column names.
    pub fn columns(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }

    /// Get the number of columns.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the row is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consume the row and return the inner HashMap.
    pub fn into_inner(self) -> HashMap<String, JsonValue> {
        self.0
    }
}

impl Deref for Row {
    type Target = HashMap<String, JsonValue>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Row {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<K: Into<String>, V: Into<JsonValue>> FromIterator<(K, V)> for Row {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let map = iter
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        Self(map)
    }
}

impl<K: Into<String>, V: Into<JsonValue>, const N: usize> From<[(K, V); N]> for Row {
    fn from(arr: [(K, V); N]) -> Self {
        arr.into_iter().collect()
    }
}

#[cfg(feature = "direct-sql")]
impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for Row {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        use sqlx::Column;
        let mut map = Row::new();
        for col in row.columns() {
            let name = col.name();
            // Try types in order of likelihood
            if let Ok(v) = row.try_get::<JsonValue, _>(name) {
                map.set(name, v);
            } else if let Ok(v) = row.try_get::<String, _>(name) {
                map.set(name, JsonValue::String(v));
            } else if let Ok(v) = row.try_get::<i64, _>(name) {
                map.set(name, JsonValue::Number(v.into()));
            } else if let Ok(v) = row.try_get::<i32, _>(name) {
                map.set(name, JsonValue::Number(v.into()));
            } else if let Ok(v) = row.try_get::<f64, _>(name) {
                if let Some(n) = serde_json::Number::from_f64(v) {
                    map.set(name, JsonValue::Number(n));
                } else {
                    map.set(name, JsonValue::Null);
                }
            } else if let Ok(v) = row.try_get::<bool, _>(name) {
                map.set(name, JsonValue::Bool(v));
            } else if let Ok(v) = row.try_get::<uuid::Uuid, _>(name) {
                map.set(name, JsonValue::String(v.to_string()));
            } else if let Ok(v) = row.try_get::<chrono::NaiveDateTime, _>(name) {
                map.set(name, JsonValue::String(v.to_string()));
            } else if let Ok(v) = row.try_get::<chrono::DateTime<chrono::Utc>, _>(name) {
                map.set(name, JsonValue::String(v.to_rfc3339()));
            } else {
                map.set(name, JsonValue::Null);
            }
        }
        Ok(map)
    }
}

/// Macro for constructing a `Row` with key-value pairs.
///
/// # Examples
/// ```
/// use supabase_client_core::row;
/// let row = row![("name", "Auckland"), ("country_id", 554)];
/// ```
#[macro_export]
macro_rules! row {
    () => {
        $crate::Row::new()
    };
    ($(($key:expr, $val:expr)),+ $(,)?) => {{
        let mut row = $crate::Row::new();
        $(
            row.set($key, serde_json::json!($val));
        )+
        row
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_row_new() {
        let row = Row::new();
        assert!(row.is_empty());
    }

    #[test]
    fn test_row_set_get() {
        let mut row = Row::new();
        row.set("name", JsonValue::String("Auckland".to_string()));
        assert_eq!(
            row.get_value("name"),
            Some(&JsonValue::String("Auckland".to_string()))
        );
        assert!(row.contains("name"));
        assert!(!row.contains("missing"));
    }

    #[test]
    fn test_row_macro() {
        let row = row![("name", "Auckland"), ("id", 1)];
        assert_eq!(row.len(), 2);
        assert!(row.contains("name"));
        assert!(row.contains("id"));
    }

    #[test]
    fn test_row_get_as() {
        let row = row![("count", 42)];
        assert_eq!(row.get_as::<i64>("count"), Some(42));
        assert_eq!(row.get_as::<String>("count"), None);
    }
}
