use sqlx::postgres::PgArguments;
use sqlx::{Arguments, PgPool};

use supabase_client_core::{StatusCode, SupabaseError, SupabaseResponse};

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
pub async fn execute_typed<T>(
    pool: &PgPool,
    parts: &SqlParts,
    params: &ParamStore,
) -> SupabaseResponse<T>
where
    T: Send + Unpin + for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow>,
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
        match sqlx::query_as_with::<_, T, _>(&sql, args)
            .fetch_all(pool)
            .await
        {
            Ok(data) => build_response(data, parts),
            Err(e) => SupabaseResponse::error(SupabaseError::Database(e)),
        }
    }
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
