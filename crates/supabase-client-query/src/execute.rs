use serde::de::DeserializeOwned;
use sqlx::postgres::PgArguments;
use sqlx::{Arguments, PgPool};

use supabase_client_core::{Row, StatusCode, SupabaseError, SupabaseResponse};

use crate::sql::{CountOption, ParamStore, SqlParam, SqlParts};

/// Bind all SqlParam values into PgArguments.
pub fn bind_params(params: &ParamStore) -> Result<PgArguments, SupabaseError> {
    let mut args = PgArguments::default();
    for param in params.params() {
        let err_map = |e: sqlx::error::BoxDynError| SupabaseError::QueryBuilder(e.to_string());
        match param {
            SqlParam::Null => args.add(Option::<String>::None).map_err(err_map)?,
            SqlParam::Bool(v) => args.add(v).map_err(err_map)?,
            SqlParam::I16(v) => args.add(v).map_err(err_map)?,
            SqlParam::I32(v) => args.add(v).map_err(err_map)?,
            SqlParam::I64(v) => args.add(v).map_err(err_map)?,
            SqlParam::F32(v) => args.add(v).map_err(err_map)?,
            SqlParam::F64(v) => args.add(v).map_err(err_map)?,
            SqlParam::Text(v) => args.add(v.as_str()).map_err(err_map)?,
            SqlParam::Uuid(v) => args.add(v).map_err(err_map)?,
            SqlParam::Timestamp(v) => args.add(v).map_err(err_map)?,
            SqlParam::TimestampTz(v) => args.add(v).map_err(err_map)?,
            SqlParam::Date(v) => args.add(v).map_err(err_map)?,
            SqlParam::Time(v) => args.add(v).map_err(err_map)?,
            SqlParam::Json(v) => args.add(v).map_err(err_map)?,
            SqlParam::ByteArray(v) => args.add(v.as_slice()).map_err(err_map)?,
            SqlParam::TextArray(v) => args.add(v).map_err(err_map)?,
            SqlParam::I32Array(v) => args.add(v).map_err(err_map)?,
            SqlParam::I64Array(v) => args.add(v).map_err(err_map)?,
        }
    }
    Ok(args)
}

/// Execute a typed query and return `SupabaseResponse<T>`.
///
/// Queries rows as `Row` (which implements `sqlx::FromRow`) and then
/// deserializes each row to `T` via serde, so callers don't need
/// `FromRow + Unpin` bounds.
pub async fn execute_typed<T>(
    pool: &PgPool,
    parts: &SqlParts,
    params: &ParamStore,
) -> SupabaseResponse<T>
where
    T: DeserializeOwned + Send,
{
    let sql = match parts.build_sql() {
        Ok(s) => s,
        Err(e) => return SupabaseResponse::error(e),
    };

    tracing::debug!(sql = %sql, "Executing query");

    let args = match bind_params(params) {
        Ok(a) => a,
        Err(e) => return SupabaseResponse::error(e),
    };

    // For operations without RETURNING that don't need rows back
    if parts.returning.is_none()
        && matches!(
            parts.operation,
            crate::sql::SqlOperation::Insert
                | crate::sql::SqlOperation::Update
                | crate::sql::SqlOperation::Delete
                | crate::sql::SqlOperation::Upsert
        )
    {
        match sqlx::query_with(&sql, args).execute(pool).await {
            Ok(result) => {
                let mut resp = SupabaseResponse::<T>::no_content();
                resp.count = Some(result.rows_affected() as i64);
                resp
            }
            Err(e) => SupabaseResponse::error(SupabaseError::Database(e)),
        }
    } else {
        // Query as Row (which implements FromRow), then deserialize to T via serde.
        // This makes direct-sql behavior consistent with REST mode (both go through serde).
        match sqlx::query_as_with::<_, Row, _>(&sql, args)
            .fetch_all(pool)
            .await
        {
            Ok(rows) => {
                let mut objects: Vec<serde_json::Map<String, serde_json::Value>> = rows
                    .into_iter()
                    .map(|row| row.into_inner().into_iter().collect())
                    .collect();
                let window_count = take_window_count(parts, &mut objects);

                let mut data = Vec::with_capacity(objects.len());
                for obj in objects {
                    match serde_json::from_value::<T>(serde_json::Value::Object(obj)) {
                        Ok(val) => data.push(val),
                        Err(e) => {
                            return SupabaseResponse::error(SupabaseError::QueryBuilder(format!(
                                "Failed to deserialize row: {}",
                                e
                            )))
                        }
                    }
                }
                let mut resp = build_response(data, parts);
                if resp.error.is_none() && parts.count == CountOption::Exact {
                    resp.count = match window_count {
                        Some(n) => Some(n),
                        // No rows and no offset: nothing matches.
                        None if parts.operation == crate::sql::SqlOperation::Select
                            && parts.offset.unwrap_or(0) <= 0 =>
                        {
                            Some(0)
                        }
                        // No rows past an offset: the window count is unknown,
                        // so count the matching rows separately.
                        None if parts.operation == crate::sql::SqlOperation::Select => {
                            match count_matching_rows(pool, parts, params).await {
                                Ok(n) => Some(n),
                                Err(e) => return SupabaseResponse::error(e),
                            }
                        }
                        None => resp.count,
                    };
                }
                resp
            }
            Err(e) => SupabaseResponse::error(SupabaseError::Database(e)),
        }
    }
}

/// Name of the `COUNT(*) OVER()` column added to `count=exact` selects.
pub(crate) const COUNT_COLUMN: &str = "__count";

/// For a `count=exact` SELECT, remove the [`COUNT_COLUMN`] window column from
/// every row and return its value (the total number of matching rows,
/// ignoring LIMIT/OFFSET). Returns `None` when there are no rows or the
/// query is not a counted SELECT.
pub(crate) fn take_window_count(
    parts: &SqlParts,
    rows: &mut [serde_json::Map<String, serde_json::Value>],
) -> Option<i64> {
    if parts.count != CountOption::Exact
        || parts.operation != crate::sql::SqlOperation::Select
        || parts.head
        || parts.explain.is_some()
    {
        return None;
    }
    let mut count = None;
    for row in rows.iter_mut() {
        if let Some(v) = row.remove(COUNT_COLUMN) {
            count = count.or_else(|| v.as_i64());
        }
    }
    count
}

/// Run `SELECT count(*)` with the same filters as `parts`.
async fn count_matching_rows(
    pool: &PgPool,
    parts: &SqlParts,
    params: &ParamStore,
) -> Result<i64, SupabaseError> {
    let mut head = parts.clone();
    head.head = true;
    head.orders.clear();
    head.limit = None;
    head.offset = None;
    let sql = head.build_sql()?;
    let args = bind_params(params)?;
    sqlx::query_scalar_with::<_, i64, _>(&sql, args)
        .fetch_one(pool)
        .await
        .map_err(SupabaseError::Database)
}

/// Build a response applying single/maybe_single/count semantics.
fn build_response<T>(data: Vec<T>, parts: &SqlParts) -> SupabaseResponse<T> {
    let status = match parts.operation {
        crate::sql::SqlOperation::Insert | crate::sql::SqlOperation::Upsert => StatusCode::Created,
        _ => StatusCode::Ok,
    };

    if parts.single {
        match data.len() {
            0 => return SupabaseResponse::error(SupabaseError::NoRows),
            1 => {}
            n => return SupabaseResponse::error(SupabaseError::MultipleRows(n)),
        }
    }

    if parts.maybe_single {
        match data.len() {
            0 | 1 => {}
            n => return SupabaseResponse::error(SupabaseError::MultipleRows(n)),
        }
    }

    let mut resp = SupabaseResponse {
        data,
        error: None,
        count: None,
        status,
    };

    if parts.count == CountOption::Exact {
        resp.count = Some(resp.data.len() as i64);
    }

    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql::SqlOperation;
    use serde_json::json;

    fn rows(values: Vec<serde_json::Value>) -> Vec<serde_json::Map<String, serde_json::Value>> {
        values
            .into_iter()
            .map(|v| v.as_object().unwrap().clone())
            .collect()
    }

    #[test]
    fn test_take_window_count_strips_column_and_returns_total() {
        // Audit: count=exact returned data.len() and leaked __count into rows.
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "t");
        parts.count = CountOption::Exact;
        parts.limit = Some(2);
        let mut data = rows(vec![
            json!({"id": 1, "__count": 57}),
            json!({"id": 2, "__count": 57}),
        ]);
        assert_eq!(take_window_count(&parts, &mut data), Some(57));
        assert!(data.iter().all(|r| !r.contains_key(COUNT_COLUMN)));
    }

    #[test]
    fn test_take_window_count_ignores_uncounted_queries() {
        let parts = SqlParts::new(SqlOperation::Select, "public", "t");
        let mut data = rows(vec![json!({"id": 1, "__count": 3})]);
        assert_eq!(take_window_count(&parts, &mut data), None);
        assert!(data[0].contains_key(COUNT_COLUMN));
    }

    #[test]
    fn test_take_window_count_no_rows() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "t");
        parts.count = CountOption::Exact;
        assert_eq!(take_window_count(&parts, &mut []), None);
    }
}
