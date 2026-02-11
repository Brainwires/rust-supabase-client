use std::marker::PhantomData;
use std::sync::Arc;

use serde_json::Value as JsonValue;
use sqlx::PgPool;

use supabase_client_core::{Row, SupabaseError, SupabaseResponse};

use crate::execute;
use crate::sql::{ParamStore, SqlParam, validate_identifier};


/// Builder for RPC (function call) queries.
///
/// Generates: `SELECT * FROM "schema"."function"(param := $1, ...)`
pub struct RpcBuilder {
    pool: Arc<PgPool>,
    schema: String,
    function: String,
    params: ParamStore,
    /// (param_name, param_index) pairs
    named_params: Vec<(String, usize)>,
}

impl RpcBuilder {
    pub fn new(
        pool: Arc<PgPool>,
        schema: String,
        function: String,
        args: JsonValue,
    ) -> Result<Self, SupabaseError> {
        validate_identifier(&function, "Function")?;

        let mut param_store = ParamStore::new();
        let mut named_params = Vec::new();

        if let JsonValue::Object(map) = args {
            for (key, value) in map {
                validate_identifier(&key, "Parameter")?;
                let sql_param = json_value_to_param(value);
                let idx = param_store.push(sql_param);
                named_params.push((key, idx));
            }
        } else if !args.is_null() {
            return Err(SupabaseError::query_builder(
                "RPC arguments must be a JSON object or null",
            ));
        }

        Ok(Self {
            pool,
            schema,
            function,
            params: param_store,
            named_params,
        })
    }

    fn build_sql(&self) -> Result<String, SupabaseError> {
        validate_identifier(&self.schema, "Schema")?;
        validate_identifier(&self.function, "Function")?;

        if self.named_params.is_empty() {
            Ok(format!(
                "SELECT * FROM \"{}\".\"{}\"()",
                self.schema, self.function
            ))
        } else {
            let param_list: Vec<String> = self
                .named_params
                .iter()
                .map(|(name, idx)| format!("\"{}\" := ${}", name, idx))
                .collect();
            Ok(format!(
                "SELECT * FROM \"{}\".\"{}\"({})",
                self.schema,
                self.function,
                param_list.join(", ")
            ))
        }
    }

    /// Execute the RPC call and return dynamic rows.
    pub async fn execute(self) -> SupabaseResponse<Row> {
        let sql = match self.build_sql() {
            Ok(s) => s,
            Err(e) => return SupabaseResponse::error(e),
        };

        tracing::debug!(sql = %sql, "Executing RPC call");

        let args = match execute::bind_params(&self.params) {
            Ok(a) => a,
            Err(e) => return SupabaseResponse::error(e),
        };

        match sqlx::query_with(&sql, args).fetch_all(&*self.pool).await {
            Ok(rows) => {
                use sqlx::{Column, Row as PgRowTrait};
                let data: Vec<Row> = rows
                    .iter()
                    .map(|row| {
                        let mut map = Row::new();
                        for col in row.columns() {
                            let name = col.name();
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
                            } else {
                                map.set(name, JsonValue::Null);
                            }
                        }
                        map
                    })
                    .collect();
                SupabaseResponse::ok(data)
            }
            Err(e) => SupabaseResponse::error(SupabaseError::Database(e)),
        }
    }
}

/// Typed RPC builder that deserializes results into `T`.
pub struct TypedRpcBuilder<T> {
    pool: Arc<PgPool>,
    schema: String,
    function: String,
    params: ParamStore,
    named_params: Vec<(String, usize)>,
    _marker: PhantomData<T>,
}

impl<T> TypedRpcBuilder<T>
where
    T: Send + Unpin + for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow>,
{
    pub fn new(
        pool: Arc<PgPool>,
        schema: String,
        function: String,
        args: JsonValue,
    ) -> Result<Self, SupabaseError> {
        validate_identifier(&function, "Function")?;

        let mut param_store = ParamStore::new();
        let mut named_params = Vec::new();

        if let JsonValue::Object(map) = args {
            for (key, value) in map {
                validate_identifier(&key, "Parameter")?;
                let sql_param = json_value_to_param(value);
                let idx = param_store.push(sql_param);
                named_params.push((key, idx));
            }
        } else if !args.is_null() {
            return Err(SupabaseError::query_builder(
                "RPC arguments must be a JSON object or null",
            ));
        }

        Ok(Self {
            pool,
            schema,
            function,
            params: param_store,
            named_params,
            _marker: PhantomData,
        })
    }

    fn build_sql(&self) -> Result<String, SupabaseError> {
        validate_identifier(&self.schema, "Schema")?;
        validate_identifier(&self.function, "Function")?;

        if self.named_params.is_empty() {
            Ok(format!(
                "SELECT * FROM \"{}\".\"{}\"()",
                self.schema, self.function
            ))
        } else {
            let param_list: Vec<String> = self
                .named_params
                .iter()
                .map(|(name, idx)| format!("\"{}\" := ${}", name, idx))
                .collect();
            Ok(format!(
                "SELECT * FROM \"{}\".\"{}\"({})",
                self.schema,
                self.function,
                param_list.join(", ")
            ))
        }
    }

    /// Execute the typed RPC call.
    pub async fn execute(self) -> SupabaseResponse<T> {
        let sql = match self.build_sql() {
            Ok(s) => s,
            Err(e) => return SupabaseResponse::error(e),
        };

        tracing::debug!(sql = %sql, "Executing typed RPC call");

        let args = match execute::bind_params(&self.params) {
            Ok(a) => a,
            Err(e) => return SupabaseResponse::error(e),
        };

        match sqlx::query_as_with::<_, T, _>(&sql, args)
            .fetch_all(&*self.pool)
            .await
        {
            Ok(data) => SupabaseResponse::ok(data),
            Err(e) => SupabaseResponse::error(SupabaseError::Database(e)),
        }
    }
}

fn json_value_to_param(value: JsonValue) -> SqlParam {
    match value {
        JsonValue::Null => SqlParam::Null,
        JsonValue::Bool(b) => SqlParam::Bool(b),
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                if i >= i32::MIN as i64 && i <= i32::MAX as i64 {
                    SqlParam::I32(i as i32)
                } else {
                    SqlParam::I64(i)
                }
            } else if let Some(f) = n.as_f64() {
                SqlParam::F64(f)
            } else {
                SqlParam::Text(n.to_string())
            }
        }
        JsonValue::String(s) => SqlParam::Text(s),
        other => SqlParam::Json(other),
    }
}
