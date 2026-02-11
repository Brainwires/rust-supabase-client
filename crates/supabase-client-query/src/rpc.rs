use std::marker::PhantomData;

use serde::de::DeserializeOwned;
use serde_json::Value as JsonValue;

use supabase_client_core::{Row, SupabaseError, SupabaseResponse};

use crate::backend::QueryBackend;
#[cfg(feature = "direct-sql")]
use crate::sql::{ParamStore, SqlParam};
use crate::sql::{SqlParts, SqlOperation, validate_identifier};

/// Builder for RPC (function call) queries.
pub struct RpcBuilder {
    backend: QueryBackend,
    schema: String,
    function: String,
    args: JsonValue,
    #[cfg(feature = "direct-sql")]
    params: ParamStore,
    #[cfg(feature = "direct-sql")]
    named_params: Vec<(String, usize)>,
}

impl RpcBuilder {
    pub fn new(
        backend: QueryBackend,
        schema: String,
        function: String,
        args: JsonValue,
    ) -> Result<Self, SupabaseError> {
        validate_identifier(&function, "Function")?;

        #[cfg(feature = "direct-sql")]
        let (params, named_params) = {
            let mut param_store = ParamStore::new();
            let mut named = Vec::new();

            if let JsonValue::Object(ref map) = args {
                for (key, value) in map {
                    validate_identifier(key, "Parameter")?;
                    let sql_param = json_value_to_param(value.clone());
                    let idx = param_store.push(sql_param);
                    named.push((key.clone(), idx));
                }
            } else if !args.is_null() {
                return Err(SupabaseError::query_builder(
                    "RPC arguments must be a JSON object or null",
                ));
            }

            (param_store, named)
        };

        #[cfg(not(feature = "direct-sql"))]
        {
            if let JsonValue::Object(ref map) = args {
                for key in map.keys() {
                    validate_identifier(key, "Parameter")?;
                }
            } else if !args.is_null() {
                return Err(SupabaseError::query_builder(
                    "RPC arguments must be a JSON object or null",
                ));
            }
        }

        Ok(Self {
            backend,
            schema,
            function,
            args,
            #[cfg(feature = "direct-sql")]
            params,
            #[cfg(feature = "direct-sql")]
            named_params,
        })
    }

    #[cfg(feature = "direct-sql")]
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
}

// REST-only mode: no sqlx needed
#[cfg(not(feature = "direct-sql"))]
impl RpcBuilder {
    /// Execute the RPC call and return dynamic rows.
    pub async fn execute(self) -> SupabaseResponse<Row> {
        let QueryBackend::Rest { ref http, ref base_url, ref api_key, ref schema } = self.backend;
        let (url, headers, body) = crate::postgrest::build_postgrest_rpc(
            base_url, &self.function, &self.args,
        );
        let parts = SqlParts::new(SqlOperation::Select, &self.schema, &self.function);
        crate::postgrest_execute::execute_rest(
            http, reqwest::Method::POST, &url, headers, Some(body), api_key, schema, &parts,
        ).await
    }
}

// Direct-SQL mode: dispatch on backend variant
#[cfg(feature = "direct-sql")]
impl RpcBuilder {
    /// Execute the RPC call and return dynamic rows.
    pub async fn execute(self) -> SupabaseResponse<Row> {
        match &self.backend {
            QueryBackend::Rest { http, base_url, api_key, schema } => {
                let (url, headers, body) = crate::postgrest::build_postgrest_rpc(
                    base_url, &self.function, &self.args,
                );
                let parts = SqlParts::new(SqlOperation::Select, &self.schema, &self.function);
                crate::postgrest_execute::execute_rest(
                    http, reqwest::Method::POST, &url, headers, Some(body), api_key, schema, &parts,
                ).await
            }
            QueryBackend::DirectSql { pool } => {
                let sql = match self.build_sql() {
                    Ok(s) => s,
                    Err(e) => return SupabaseResponse::error(e),
                };

                tracing::debug!(sql = %sql, "Executing RPC call");

                let args = match crate::execute::bind_params(&self.params) {
                    Ok(a) => a,
                    Err(e) => return SupabaseResponse::error(e),
                };

                match sqlx::query_with(&sql, args).fetch_all(pool.as_ref()).await {
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
    }
}

/// Typed RPC builder that deserializes results into `T`.
pub struct TypedRpcBuilder<T> {
    backend: QueryBackend,
    schema: String,
    function: String,
    args: JsonValue,
    #[cfg(feature = "direct-sql")]
    params: ParamStore,
    #[cfg(feature = "direct-sql")]
    named_params: Vec<(String, usize)>,
    _marker: PhantomData<T>,
}

impl<T> TypedRpcBuilder<T>
where
    T: DeserializeOwned + Send,
{
    pub fn new(
        backend: QueryBackend,
        schema: String,
        function: String,
        args: JsonValue,
    ) -> Result<Self, SupabaseError> {
        validate_identifier(&function, "Function")?;

        #[cfg(feature = "direct-sql")]
        let (params, named_params) = {
            let mut param_store = ParamStore::new();
            let mut named = Vec::new();

            if let JsonValue::Object(ref map) = args {
                for (key, value) in map {
                    validate_identifier(key, "Parameter")?;
                    let sql_param = json_value_to_param(value.clone());
                    let idx = param_store.push(sql_param);
                    named.push((key.clone(), idx));
                }
            } else if !args.is_null() {
                return Err(SupabaseError::query_builder(
                    "RPC arguments must be a JSON object or null",
                ));
            }

            (param_store, named)
        };

        #[cfg(not(feature = "direct-sql"))]
        {
            if let JsonValue::Object(ref map) = args {
                for key in map.keys() {
                    validate_identifier(key, "Parameter")?;
                }
            } else if !args.is_null() {
                return Err(SupabaseError::query_builder(
                    "RPC arguments must be a JSON object or null",
                ));
            }
        }

        Ok(Self {
            backend,
            schema,
            function,
            args,
            #[cfg(feature = "direct-sql")]
            params,
            #[cfg(feature = "direct-sql")]
            named_params,
            _marker: PhantomData,
        })
    }

    #[cfg(feature = "direct-sql")]
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
}

// REST-only mode: only DeserializeOwned + Send needed
#[cfg(not(feature = "direct-sql"))]
impl<T> TypedRpcBuilder<T>
where
    T: DeserializeOwned + Send,
{
    /// Execute the typed RPC call.
    pub async fn execute(self) -> SupabaseResponse<T> {
        let QueryBackend::Rest { ref http, ref base_url, ref api_key, ref schema } = self.backend;
        let (url, headers, body) = crate::postgrest::build_postgrest_rpc(
            base_url, &self.function, &self.args,
        );
        let parts = SqlParts::new(SqlOperation::Select, &self.schema, &self.function);
        crate::postgrest_execute::execute_rest(
            http, reqwest::Method::POST, &url, headers, Some(body), api_key, schema, &parts,
        ).await
    }
}

// Direct-SQL mode: additional FromRow + Unpin bounds
#[cfg(feature = "direct-sql")]
impl<T> TypedRpcBuilder<T>
where
    T: DeserializeOwned + Send + Unpin + for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow>,
{
    /// Execute the typed RPC call.
    pub async fn execute(self) -> SupabaseResponse<T> {
        match &self.backend {
            QueryBackend::Rest { http, base_url, api_key, schema } => {
                let (url, headers, body) = crate::postgrest::build_postgrest_rpc(
                    base_url, &self.function, &self.args,
                );
                let parts = SqlParts::new(SqlOperation::Select, &self.schema, &self.function);
                crate::postgrest_execute::execute_rest(
                    http, reqwest::Method::POST, &url, headers, Some(body), api_key, schema, &parts,
                ).await
            }
            QueryBackend::DirectSql { pool } => {
                let sql = match self.build_sql() {
                    Ok(s) => s,
                    Err(e) => return SupabaseResponse::error(e),
                };

                tracing::debug!(sql = %sql, "Executing typed RPC call");

                let args = match crate::execute::bind_params(&self.params) {
                    Ok(a) => a,
                    Err(e) => return SupabaseResponse::error(e),
                };

                match sqlx::query_as_with::<_, T, _>(&sql, args)
                    .fetch_all(pool.as_ref())
                    .await
                {
                    Ok(data) => SupabaseResponse::ok(data),
                    Err(e) => SupabaseResponse::error(SupabaseError::Database(e)),
                }
            }
        }
    }
}

#[cfg(feature = "direct-sql")]
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
