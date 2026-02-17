use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
use serde_json::Value as JsonValue;
use uuid::Uuid;

/// Type-erased SQL parameter for dynamic query building.
#[derive(Debug, Clone)]
pub enum SqlParam {
    Null,
    Bool(bool),
    I16(i16),
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    Text(String),
    Uuid(Uuid),
    Timestamp(NaiveDateTime),
    TimestampTz(chrono::DateTime<chrono::Utc>),
    Date(NaiveDate),
    Time(NaiveTime),
    Json(JsonValue),
    ByteArray(Vec<u8>),
    TextArray(Vec<String>),
    I32Array(Vec<i32>),
    I64Array(Vec<i64>),
}

/// Trait for converting Rust types into `SqlParam`.
pub trait IntoSqlParam {
    fn into_sql_param(self) -> SqlParam;
}

// Implementations for all common types

impl IntoSqlParam for SqlParam {
    fn into_sql_param(self) -> SqlParam {
        self
    }
}

impl IntoSqlParam for bool {
    fn into_sql_param(self) -> SqlParam {
        SqlParam::Bool(self)
    }
}

impl IntoSqlParam for i16 {
    fn into_sql_param(self) -> SqlParam {
        SqlParam::I16(self)
    }
}

impl IntoSqlParam for i32 {
    fn into_sql_param(self) -> SqlParam {
        SqlParam::I32(self)
    }
}

impl IntoSqlParam for i64 {
    fn into_sql_param(self) -> SqlParam {
        SqlParam::I64(self)
    }
}

impl IntoSqlParam for f32 {
    fn into_sql_param(self) -> SqlParam {
        SqlParam::F32(self)
    }
}

impl IntoSqlParam for f64 {
    fn into_sql_param(self) -> SqlParam {
        SqlParam::F64(self)
    }
}

impl IntoSqlParam for String {
    fn into_sql_param(self) -> SqlParam {
        SqlParam::Text(self)
    }
}

impl IntoSqlParam for &str {
    fn into_sql_param(self) -> SqlParam {
        SqlParam::Text(self.to_string())
    }
}

impl IntoSqlParam for Uuid {
    fn into_sql_param(self) -> SqlParam {
        SqlParam::Uuid(self)
    }
}

impl IntoSqlParam for NaiveDateTime {
    fn into_sql_param(self) -> SqlParam {
        SqlParam::Timestamp(self)
    }
}

impl IntoSqlParam for chrono::DateTime<chrono::Utc> {
    fn into_sql_param(self) -> SqlParam {
        SqlParam::TimestampTz(self)
    }
}

impl IntoSqlParam for NaiveDate {
    fn into_sql_param(self) -> SqlParam {
        SqlParam::Date(self)
    }
}

impl IntoSqlParam for NaiveTime {
    fn into_sql_param(self) -> SqlParam {
        SqlParam::Time(self)
    }
}

impl IntoSqlParam for JsonValue {
    fn into_sql_param(self) -> SqlParam {
        SqlParam::Json(self)
    }
}

impl IntoSqlParam for Vec<u8> {
    fn into_sql_param(self) -> SqlParam {
        SqlParam::ByteArray(self)
    }
}

impl IntoSqlParam for Vec<String> {
    fn into_sql_param(self) -> SqlParam {
        SqlParam::TextArray(self)
    }
}

impl IntoSqlParam for Vec<i32> {
    fn into_sql_param(self) -> SqlParam {
        SqlParam::I32Array(self)
    }
}

impl IntoSqlParam for Vec<i64> {
    fn into_sql_param(self) -> SqlParam {
        SqlParam::I64Array(self)
    }
}

impl<T: IntoSqlParam> IntoSqlParam for Option<T> {
    fn into_sql_param(self) -> SqlParam {
        match self {
            Some(v) => v.into_sql_param(),
            None => SqlParam::Null,
        }
    }
}

/// Store for collecting parameters during query building.
#[derive(Debug, Clone, Default)]
pub struct ParamStore {
    params: Vec<SqlParam>,
}

impl ParamStore {
    pub fn new() -> Self {
        Self { params: Vec::new() }
    }

    /// Push a parameter and return its 1-based index (for `$N` placeholders).
    pub fn push(&mut self, param: SqlParam) -> usize {
        self.params.push(param);
        self.params.len()
    }

    /// Push a value that implements IntoSqlParam.
    pub fn push_value(&mut self, value: impl IntoSqlParam) -> usize {
        self.push(value.into_sql_param())
    }

    /// Get a parameter by 0-based index.
    pub fn get(&self, index: usize) -> Option<&SqlParam> {
        self.params.get(index)
    }

    /// Get all parameters.
    pub fn params(&self) -> &[SqlParam] {
        &self.params
    }

    /// Consume and return all parameters.
    pub fn into_params(self) -> Vec<SqlParam> {
        self.params
    }

    /// Number of parameters stored.
    pub fn len(&self) -> usize {
        self.params.len()
    }

    pub fn is_empty(&self) -> bool {
        self.params.is_empty()
    }
}

// --- Filter types ---

/// A single filter condition in a WHERE clause.
#[derive(Debug, Clone)]
pub enum FilterCondition {
    /// column op $N (e.g. "name" = $1)
    Comparison {
        column: String,
        operator: FilterOperator,
        param_index: usize,
    },
    /// column IS NULL / IS NOT NULL / IS TRUE / IS FALSE
    Is {
        column: String,
        value: IsValue,
    },
    /// column IN ($1, $2, ...)
    In {
        column: String,
        param_indices: Vec<usize>,
    },
    /// column LIKE/ILIKE $N
    Pattern {
        column: String,
        operator: PatternOperator,
        param_index: usize,
    },
    /// Full-text search: column @@ to_tsquery(config, $N)
    TextSearch {
        column: String,
        query_param_index: usize,
        config: Option<String>,
        search_type: TextSearchType,
    },
    /// Array/range operators (e.g. @>, <@, &&)
    ArrayRange {
        column: String,
        operator: ArrayRangeOperator,
        param_index: usize,
    },
    /// NOT (condition)
    Not(Box<FilterCondition>),
    /// (condition OR condition OR ...)
    Or(Vec<FilterCondition>),
    /// (condition AND condition AND ...) - used inside or_filter
    And(Vec<FilterCondition>),
    /// Raw SQL fragment (escape hatch)
    Raw(String),
    /// Match multiple column=value conditions (AND)
    Match {
        conditions: Vec<(String, usize)>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterOperator {
    Eq,
    Neq,
    Gt,
    Gte,
    Lt,
    Lte,
}

impl FilterOperator {
    pub fn as_sql(&self) -> &'static str {
        match self {
            Self::Eq => "=",
            Self::Neq => "!=",
            Self::Gt => ">",
            Self::Gte => ">=",
            Self::Lt => "<",
            Self::Lte => "<=",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternOperator {
    Like,
    ILike,
}

impl PatternOperator {
    pub fn as_sql(&self) -> &'static str {
        match self {
            Self::Like => "LIKE",
            Self::ILike => "ILIKE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsValue {
    Null,
    NotNull,
    True,
    False,
}

impl IsValue {
    pub fn as_sql(&self) -> &'static str {
        match self {
            Self::Null => "IS NULL",
            Self::NotNull => "IS NOT NULL",
            Self::True => "IS TRUE",
            Self::False => "IS FALSE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextSearchType {
    Plain,
    Phrase,
    Websearch,
}

impl TextSearchType {
    pub fn function_name(&self) -> &'static str {
        match self {
            Self::Plain => "plainto_tsquery",
            Self::Phrase => "phraseto_tsquery",
            Self::Websearch => "websearch_to_tsquery",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArrayRangeOperator {
    Contains,
    ContainedBy,
    Overlaps,
    RangeGt,
    RangeGte,
    RangeLt,
    RangeLte,
    RangeAdjacent,
}

impl ArrayRangeOperator {
    pub fn as_sql(&self) -> &'static str {
        match self {
            Self::Contains => "@>",
            Self::ContainedBy => "<@",
            Self::Overlaps => "&&",
            Self::RangeGt => ">>",
            Self::RangeGte => "&>",   // in PostGIS/range context
            Self::RangeLt => "<<",
            Self::RangeLte => "&<",
            Self::RangeAdjacent => "-|-",
        }
    }
}

// --- Order / Modifier types ---

#[derive(Debug, Clone)]
pub struct OrderClause {
    pub column: String,
    pub direction: OrderDirection,
    pub nulls: Option<NullsPosition>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderDirection {
    Ascending,
    Descending,
}

impl OrderDirection {
    pub fn as_sql(&self) -> &'static str {
        match self {
            Self::Ascending => "ASC",
            Self::Descending => "DESC",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NullsPosition {
    First,
    Last,
}

impl NullsPosition {
    pub fn as_sql(&self) -> &'static str {
        match self {
            Self::First => "NULLS FIRST",
            Self::Last => "NULLS LAST",
        }
    }
}

/// Count mode for responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CountOption {
    /// No count requested.
    None,
    /// Exact count via COUNT(*).
    Exact,
    /// Planned count from query planner (fast, approximate).
    Planned,
    /// Estimated count using statistics (fast, approximate).
    Estimated,
}

// --- SQL Parts ---

/// The type of SQL operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlOperation {
    Select,
    Insert,
    Update,
    Delete,
    Upsert,
}

/// Collects all the components of a SQL query being built.
#[derive(Debug, Clone)]
pub struct SqlParts {
    pub operation: SqlOperation,
    pub schema: String,
    pub table: String,
    /// Columns to select (None = *)
    pub select_columns: Option<String>,
    /// Filter conditions (WHERE)
    pub filters: Vec<FilterCondition>,
    /// ORDER BY clauses
    pub orders: Vec<OrderClause>,
    /// LIMIT
    pub limit: Option<i64>,
    /// OFFSET (from range)
    pub offset: Option<i64>,
    /// Whether to return a single row (enforced at execution)
    pub single: bool,
    /// Whether to return zero or one row
    pub maybe_single: bool,
    /// Count option
    pub count: CountOption,
    /// Insert/Update column-value pairs: Vec<(column, param_index)>
    pub set_clauses: Vec<(String, usize)>,
    /// For insert_many/upsert_many: Vec of rows, each is Vec<(column, param_index)>
    pub many_rows: Vec<Vec<(String, usize)>>,
    /// RETURNING columns (None = don't return, Some("*") = all)
    pub returning: Option<String>,
    /// ON CONFLICT columns (for upsert)
    pub conflict_columns: Vec<String>,
    /// ON CONFLICT constraint name (alternative to columns)
    pub conflict_constraint: Option<String>,
    /// When true, upsert generates ON CONFLICT DO NOTHING instead of DO UPDATE
    pub ignore_duplicates: bool,
    /// Schema override for per-query schema qualification
    pub schema_override: Option<String>,
    /// EXPLAIN options (only for SELECT)
    pub explain: Option<ExplainOptions>,
    /// Head mode: SELECT count(*) only, no rows
    pub head: bool,
}

/// Options for the EXPLAIN modifier.
#[derive(Debug, Clone)]
pub struct ExplainOptions {
    pub analyze: bool,
    pub verbose: bool,
    pub format: ExplainFormat,
}

impl Default for ExplainOptions {
    fn default() -> Self {
        Self {
            analyze: true,
            verbose: false,
            format: ExplainFormat::Json,
        }
    }
}

/// Output format for EXPLAIN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExplainFormat {
    Text,
    Json,
    Xml,
    Yaml,
}

impl ExplainFormat {
    pub fn as_sql(&self) -> &'static str {
        match self {
            Self::Text => "TEXT",
            Self::Json => "JSON",
            Self::Xml => "XML",
            Self::Yaml => "YAML",
        }
    }
}

impl SqlParts {
    pub fn new(operation: SqlOperation, schema: impl Into<String>, table: impl Into<String>) -> Self {
        Self {
            operation,
            schema: schema.into(),
            table: table.into(),
            select_columns: None,
            filters: Vec::new(),
            orders: Vec::new(),
            limit: None,
            offset: None,
            single: false,
            maybe_single: false,
            count: CountOption::None,
            set_clauses: Vec::new(),
            many_rows: Vec::new(),
            returning: None,
            conflict_columns: Vec::new(),
            conflict_constraint: None,
            ignore_duplicates: false,
            schema_override: None,
            explain: None,
            head: false,
        }
    }

    /// Get the fully-qualified table name, using schema_override if set.
    pub fn qualified_table(&self) -> String {
        let schema = self.schema_override.as_deref().unwrap_or(&self.schema);
        format!("\"{}\".\"{}\"", schema, self.table)
    }
}

/// Validate that a column name is safe (no SQL injection).
pub fn validate_column_name(name: &str) -> Result<(), supabase_client_core::SupabaseError> {
    if name.is_empty() {
        return Err(supabase_client_core::SupabaseError::query_builder(
            "Column name cannot be empty",
        ));
    }
    if name.contains('"') || name.contains(';') || name.contains("--") {
        return Err(supabase_client_core::SupabaseError::query_builder(format!(
            "Invalid column name: {name:?} (contains prohibited characters)"
        )));
    }
    Ok(())
}

/// Validate a table or schema name.
pub fn validate_identifier(name: &str, kind: &str) -> Result<(), supabase_client_core::SupabaseError> {
    if name.is_empty() {
        return Err(supabase_client_core::SupabaseError::query_builder(format!(
            "{kind} name cannot be empty"
        )));
    }
    if name.contains('"') || name.contains(';') || name.contains("--") {
        return Err(supabase_client_core::SupabaseError::query_builder(format!(
            "Invalid {kind} name: {name:?} (contains prohibited characters)"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{NaiveDate, NaiveTime, Utc};
    use serde_json::json;
    use uuid::Uuid;

    // ---- IntoSqlParam conversions ----

    #[test]
    fn test_bool_into_sql_param() {
        let param = true.into_sql_param();
        assert!(matches!(param, SqlParam::Bool(true)));
        let param = false.into_sql_param();
        assert!(matches!(param, SqlParam::Bool(false)));
    }

    #[test]
    fn test_i16_into_sql_param() {
        let param = 42i16.into_sql_param();
        assert!(matches!(param, SqlParam::I16(42)));
    }

    #[test]
    fn test_i32_into_sql_param() {
        let param = 100i32.into_sql_param();
        assert!(matches!(param, SqlParam::I32(100)));
    }

    #[test]
    fn test_i64_into_sql_param() {
        let param = 999_999_999_999i64.into_sql_param();
        assert!(matches!(param, SqlParam::I64(999_999_999_999)));
    }

    #[test]
    fn test_f32_into_sql_param() {
        let param = 3.14f32.into_sql_param();
        match param {
            SqlParam::F32(v) => assert!((v - 3.14).abs() < 0.001),
            _ => panic!("expected F32"),
        }
    }

    #[test]
    fn test_f64_into_sql_param() {
        let param = 2.71828f64.into_sql_param();
        match param {
            SqlParam::F64(v) => assert!((v - 2.71828).abs() < 0.00001),
            _ => panic!("expected F64"),
        }
    }

    #[test]
    fn test_string_into_sql_param() {
        let param = String::from("hello").into_sql_param();
        match param {
            SqlParam::Text(s) => assert_eq!(s, "hello"),
            _ => panic!("expected Text"),
        }
    }

    #[test]
    fn test_str_into_sql_param() {
        let param = "world".into_sql_param();
        match param {
            SqlParam::Text(s) => assert_eq!(s, "world"),
            _ => panic!("expected Text"),
        }
    }

    #[test]
    fn test_uuid_into_sql_param() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let param = uuid.into_sql_param();
        match param {
            SqlParam::Uuid(u) => assert_eq!(u.to_string(), "550e8400-e29b-41d4-a716-446655440000"),
            _ => panic!("expected Uuid"),
        }
    }

    #[test]
    fn test_naive_datetime_into_sql_param() {
        let dt = NaiveDate::from_ymd_opt(2024, 1, 15)
            .unwrap()
            .and_hms_opt(10, 30, 0)
            .unwrap();
        let param = dt.into_sql_param();
        assert!(matches!(param, SqlParam::Timestamp(_)));
    }

    #[test]
    fn test_datetime_utc_into_sql_param() {
        let dt = Utc::now();
        let param = dt.into_sql_param();
        assert!(matches!(param, SqlParam::TimestampTz(_)));
    }

    #[test]
    fn test_naive_date_into_sql_param() {
        let d = NaiveDate::from_ymd_opt(2024, 6, 15).unwrap();
        let param = d.into_sql_param();
        assert!(matches!(param, SqlParam::Date(_)));
    }

    #[test]
    fn test_naive_time_into_sql_param() {
        let t = NaiveTime::from_hms_opt(14, 30, 0).unwrap();
        let param = t.into_sql_param();
        assert!(matches!(param, SqlParam::Time(_)));
    }

    #[test]
    fn test_json_value_into_sql_param() {
        let val = json!({"key": "value"});
        let param = val.into_sql_param();
        assert!(matches!(param, SqlParam::Json(_)));
    }

    #[test]
    fn test_vec_u8_into_sql_param() {
        let bytes = vec![1u8, 2, 3];
        let param = bytes.into_sql_param();
        match param {
            SqlParam::ByteArray(b) => assert_eq!(b, vec![1, 2, 3]),
            _ => panic!("expected ByteArray"),
        }
    }

    #[test]
    fn test_vec_string_into_sql_param() {
        let strs = vec!["a".to_string(), "b".to_string()];
        let param = strs.into_sql_param();
        match param {
            SqlParam::TextArray(a) => assert_eq!(a, vec!["a", "b"]),
            _ => panic!("expected TextArray"),
        }
    }

    #[test]
    fn test_vec_i32_into_sql_param() {
        let nums = vec![1i32, 2, 3];
        let param = nums.into_sql_param();
        match param {
            SqlParam::I32Array(a) => assert_eq!(a, vec![1, 2, 3]),
            _ => panic!("expected I32Array"),
        }
    }

    #[test]
    fn test_vec_i64_into_sql_param() {
        let nums = vec![10i64, 20, 30];
        let param = nums.into_sql_param();
        match param {
            SqlParam::I64Array(a) => assert_eq!(a, vec![10, 20, 30]),
            _ => panic!("expected I64Array"),
        }
    }

    #[test]
    fn test_option_some_into_sql_param() {
        let param = Some(42i32).into_sql_param();
        assert!(matches!(param, SqlParam::I32(42)));
    }

    #[test]
    fn test_option_none_into_sql_param() {
        let param: Option<i32> = None;
        let param = param.into_sql_param();
        assert!(matches!(param, SqlParam::Null));
    }

    #[test]
    fn test_sql_param_passthrough() {
        let original = SqlParam::Bool(true);
        let param = original.into_sql_param();
        assert!(matches!(param, SqlParam::Bool(true)));
    }

    // ---- ParamStore ----

    #[test]
    fn test_param_store_new() {
        let store = ParamStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_param_store_push_returns_1_based_index() {
        let mut store = ParamStore::new();
        let idx1 = store.push(SqlParam::I32(1));
        assert_eq!(idx1, 1);
        let idx2 = store.push(SqlParam::I32(2));
        assert_eq!(idx2, 2);
        let idx3 = store.push(SqlParam::I32(3));
        assert_eq!(idx3, 3);
    }

    #[test]
    fn test_param_store_push_value() {
        let mut store = ParamStore::new();
        let idx = store.push_value(42i32);
        assert_eq!(idx, 1);
        assert!(matches!(store.get(0), Some(SqlParam::I32(42))));
    }

    #[test]
    fn test_param_store_get() {
        let mut store = ParamStore::new();
        store.push(SqlParam::Text("hello".to_string()));
        assert!(store.get(0).is_some());
        assert!(store.get(1).is_none());
    }

    #[test]
    fn test_param_store_params() {
        let mut store = ParamStore::new();
        store.push(SqlParam::Bool(true));
        store.push(SqlParam::I32(42));
        assert_eq!(store.params().len(), 2);
    }

    #[test]
    fn test_param_store_into_params() {
        let mut store = ParamStore::new();
        store.push(SqlParam::Bool(true));
        let params = store.into_params();
        assert_eq!(params.len(), 1);
        assert!(matches!(params[0], SqlParam::Bool(true)));
    }

    #[test]
    fn test_param_store_len_and_is_empty() {
        let mut store = ParamStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        store.push(SqlParam::Null);
        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);
    }

    // ---- FilterOperator ----

    #[test]
    fn test_filter_operator_as_sql() {
        assert_eq!(FilterOperator::Eq.as_sql(), "=");
        assert_eq!(FilterOperator::Neq.as_sql(), "!=");
        assert_eq!(FilterOperator::Gt.as_sql(), ">");
        assert_eq!(FilterOperator::Gte.as_sql(), ">=");
        assert_eq!(FilterOperator::Lt.as_sql(), "<");
        assert_eq!(FilterOperator::Lte.as_sql(), "<=");
    }

    // ---- PatternOperator ----

    #[test]
    fn test_pattern_operator_as_sql() {
        assert_eq!(PatternOperator::Like.as_sql(), "LIKE");
        assert_eq!(PatternOperator::ILike.as_sql(), "ILIKE");
    }

    // ---- IsValue ----

    #[test]
    fn test_is_value_as_sql() {
        assert_eq!(IsValue::Null.as_sql(), "IS NULL");
        assert_eq!(IsValue::NotNull.as_sql(), "IS NOT NULL");
        assert_eq!(IsValue::True.as_sql(), "IS TRUE");
        assert_eq!(IsValue::False.as_sql(), "IS FALSE");
    }

    // ---- TextSearchType ----

    #[test]
    fn test_text_search_type_function_name() {
        assert_eq!(TextSearchType::Plain.function_name(), "plainto_tsquery");
        assert_eq!(TextSearchType::Phrase.function_name(), "phraseto_tsquery");
        assert_eq!(TextSearchType::Websearch.function_name(), "websearch_to_tsquery");
    }

    // ---- ArrayRangeOperator ----

    #[test]
    fn test_array_range_operator_as_sql() {
        assert_eq!(ArrayRangeOperator::Contains.as_sql(), "@>");
        assert_eq!(ArrayRangeOperator::ContainedBy.as_sql(), "<@");
        assert_eq!(ArrayRangeOperator::Overlaps.as_sql(), "&&");
        assert_eq!(ArrayRangeOperator::RangeGt.as_sql(), ">>");
        assert_eq!(ArrayRangeOperator::RangeGte.as_sql(), "&>");
        assert_eq!(ArrayRangeOperator::RangeLt.as_sql(), "<<");
        assert_eq!(ArrayRangeOperator::RangeLte.as_sql(), "&<");
        assert_eq!(ArrayRangeOperator::RangeAdjacent.as_sql(), "-|-");
    }

    // ---- OrderDirection ----

    #[test]
    fn test_order_direction_as_sql() {
        assert_eq!(OrderDirection::Ascending.as_sql(), "ASC");
        assert_eq!(OrderDirection::Descending.as_sql(), "DESC");
    }

    // ---- NullsPosition ----

    #[test]
    fn test_nulls_position_as_sql() {
        assert_eq!(NullsPosition::First.as_sql(), "NULLS FIRST");
        assert_eq!(NullsPosition::Last.as_sql(), "NULLS LAST");
    }

    // ---- ExplainFormat ----

    #[test]
    fn test_explain_format_as_sql() {
        assert_eq!(ExplainFormat::Text.as_sql(), "TEXT");
        assert_eq!(ExplainFormat::Json.as_sql(), "JSON");
        assert_eq!(ExplainFormat::Xml.as_sql(), "XML");
        assert_eq!(ExplainFormat::Yaml.as_sql(), "YAML");
    }

    // ---- validate_column_name ----

    #[test]
    fn test_validate_column_name_valid() {
        assert!(validate_column_name("name").is_ok());
        assert!(validate_column_name("user_id").is_ok());
        assert!(validate_column_name("CamelCase").is_ok());
    }

    #[test]
    fn test_validate_column_name_empty() {
        assert!(validate_column_name("").is_err());
    }

    #[test]
    fn test_validate_column_name_with_quotes() {
        assert!(validate_column_name("col\"name").is_err());
    }

    #[test]
    fn test_validate_column_name_with_semicolons() {
        assert!(validate_column_name("col;DROP TABLE").is_err());
    }

    #[test]
    fn test_validate_column_name_with_comment() {
        assert!(validate_column_name("col--comment").is_err());
    }

    // ---- validate_identifier ----

    #[test]
    fn test_validate_identifier_valid() {
        assert!(validate_identifier("my_table", "table").is_ok());
        assert!(validate_identifier("public", "schema").is_ok());
    }

    #[test]
    fn test_validate_identifier_empty() {
        assert!(validate_identifier("", "table").is_err());
    }

    #[test]
    fn test_validate_identifier_prohibited_chars() {
        assert!(validate_identifier("bad\"name", "table").is_err());
        assert!(validate_identifier("bad;name", "table").is_err());
        assert!(validate_identifier("bad--name", "table").is_err());
    }

    // ---- SqlParts ----

    #[test]
    fn test_sql_parts_new_defaults() {
        let parts = SqlParts::new(SqlOperation::Select, "public", "users");
        assert_eq!(parts.operation, SqlOperation::Select);
        assert_eq!(parts.schema, "public");
        assert_eq!(parts.table, "users");
        assert!(parts.select_columns.is_none());
        assert!(parts.filters.is_empty());
        assert!(parts.orders.is_empty());
        assert!(parts.limit.is_none());
        assert!(parts.offset.is_none());
        assert!(!parts.single);
        assert!(!parts.maybe_single);
        assert_eq!(parts.count, CountOption::None);
        assert!(parts.set_clauses.is_empty());
        assert!(parts.many_rows.is_empty());
        assert!(parts.returning.is_none());
        assert!(parts.conflict_columns.is_empty());
        assert!(parts.conflict_constraint.is_none());
        assert!(!parts.ignore_duplicates);
        assert!(parts.schema_override.is_none());
        assert!(parts.explain.is_none());
        assert!(!parts.head);
    }

    #[test]
    fn test_sql_parts_qualified_table_no_override() {
        let parts = SqlParts::new(SqlOperation::Select, "public", "users");
        assert_eq!(parts.qualified_table(), "\"public\".\"users\"");
    }

    #[test]
    fn test_sql_parts_qualified_table_with_override() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "users");
        parts.schema_override = Some("custom_schema".to_string());
        assert_eq!(parts.qualified_table(), "\"custom_schema\".\"users\"");
    }

    // ---- ExplainOptions ----

    #[test]
    fn test_explain_options_default() {
        let opts = ExplainOptions::default();
        assert!(opts.analyze);
        assert!(!opts.verbose);
        assert_eq!(opts.format, ExplainFormat::Json);
    }

    // ---- CountOption ----

    #[test]
    fn test_count_option_construction() {
        let _ = CountOption::None;
        let _ = CountOption::Exact;
        let _ = CountOption::Planned;
        let _ = CountOption::Estimated;
        // Verify equality
        assert_eq!(CountOption::None, CountOption::None);
        assert_eq!(CountOption::Exact, CountOption::Exact);
        assert_eq!(CountOption::Planned, CountOption::Planned);
        assert_eq!(CountOption::Estimated, CountOption::Estimated);
        assert_ne!(CountOption::None, CountOption::Exact);
    }
}
