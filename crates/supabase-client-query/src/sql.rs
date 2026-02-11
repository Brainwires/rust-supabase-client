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
        }
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
