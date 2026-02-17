use serde_json::{json, Value};

/// Filter operators supported by pg_graphql.
#[derive(Debug, Clone, PartialEq)]
pub enum FilterOp {
    Eq,
    Neq,
    Gt,
    Gte,
    Lt,
    Lte,
    In,
    Is,
    Like,
    Ilike,
    StartsWith,
}

impl FilterOp {
    /// The pg_graphql filter key name.
    pub fn as_str(&self) -> &'static str {
        match self {
            FilterOp::Eq => "eq",
            FilterOp::Neq => "neq",
            FilterOp::Gt => "gt",
            FilterOp::Gte => "gte",
            FilterOp::Lt => "lt",
            FilterOp::Lte => "lte",
            FilterOp::In => "in",
            FilterOp::Is => "is",
            FilterOp::Like => "like",
            FilterOp::Ilike => "ilike",
            FilterOp::StartsWith => "startsWith",
        }
    }
}

/// Values that can be used with the `is` filter operator.
#[derive(Debug, Clone, PartialEq)]
pub enum IsValue {
    Null,
    NotNull,
    True,
    False,
}

impl IsValue {
    /// Convert to the pg_graphql enum literal.
    pub fn as_graphql_literal(&self) -> &'static str {
        match self {
            IsValue::Null => "NULL",
            IsValue::NotNull => "NOT_NULL",
            IsValue::True => "TRUE",
            IsValue::False => "FALSE",
        }
    }
}

/// A filter expression for GraphQL queries.
///
/// Maps to pg_graphql's filter argument structure.
///
/// # Examples
///
/// ```
/// use supabase_client_graphql::GqlFilter;
///
/// // Simple equality: { "title": { "eq": "hello" } }
/// let filter = GqlFilter::eq("title", "hello");
///
/// // Compound: { "and": [{ "age": { "gte": 18 } }, { "status": { "eq": "active" } }] }
/// let filter = GqlFilter::and(vec![
///     GqlFilter::gte("age", 18),
///     GqlFilter::eq("status", "active"),
/// ]);
/// ```
#[derive(Debug, Clone)]
pub enum GqlFilter {
    /// A field-level comparison: `{ column: { op: value } }`.
    Field {
        column: String,
        op: FilterOp,
        value: Value,
    },
    /// An `is` filter for null/boolean checks: `{ column: { is: NULL } }`.
    Is {
        column: String,
        value: IsValue,
    },
    /// Logical AND of multiple filters.
    And(Vec<GqlFilter>),
    /// Logical OR of multiple filters.
    Or(Vec<GqlFilter>),
    /// Logical NOT of a filter.
    Not(Box<GqlFilter>),
}

impl GqlFilter {
    /// Create an equality filter: `{ column: { eq: value } }`.
    pub fn eq(column: impl Into<String>, value: impl Into<Value>) -> Self {
        GqlFilter::Field {
            column: column.into(),
            op: FilterOp::Eq,
            value: value.into(),
        }
    }

    /// Create a not-equal filter: `{ column: { neq: value } }`.
    pub fn neq(column: impl Into<String>, value: impl Into<Value>) -> Self {
        GqlFilter::Field {
            column: column.into(),
            op: FilterOp::Neq,
            value: value.into(),
        }
    }

    /// Create a greater-than filter: `{ column: { gt: value } }`.
    pub fn gt(column: impl Into<String>, value: impl Into<Value>) -> Self {
        GqlFilter::Field {
            column: column.into(),
            op: FilterOp::Gt,
            value: value.into(),
        }
    }

    /// Create a greater-than-or-equal filter: `{ column: { gte: value } }`.
    pub fn gte(column: impl Into<String>, value: impl Into<Value>) -> Self {
        GqlFilter::Field {
            column: column.into(),
            op: FilterOp::Gte,
            value: value.into(),
        }
    }

    /// Create a less-than filter: `{ column: { lt: value } }`.
    pub fn lt(column: impl Into<String>, value: impl Into<Value>) -> Self {
        GqlFilter::Field {
            column: column.into(),
            op: FilterOp::Lt,
            value: value.into(),
        }
    }

    /// Create a less-than-or-equal filter: `{ column: { lte: value } }`.
    pub fn lte(column: impl Into<String>, value: impl Into<Value>) -> Self {
        GqlFilter::Field {
            column: column.into(),
            op: FilterOp::Lte,
            value: value.into(),
        }
    }

    /// Create an `in` filter: `{ column: { in: [values] } }`.
    pub fn in_(column: impl Into<String>, values: Vec<Value>) -> Self {
        GqlFilter::Field {
            column: column.into(),
            op: FilterOp::In,
            value: Value::Array(values),
        }
    }

    /// Create an `is null` filter: `{ column: { is: NULL } }`.
    pub fn is_null(column: impl Into<String>) -> Self {
        GqlFilter::Is {
            column: column.into(),
            value: IsValue::Null,
        }
    }

    /// Create an `is not null` filter: `{ column: { is: NOT_NULL } }`.
    pub fn is_not_null(column: impl Into<String>) -> Self {
        GqlFilter::Is {
            column: column.into(),
            value: IsValue::NotNull,
        }
    }

    /// Create a `like` filter: `{ column: { like: pattern } }`.
    pub fn like(column: impl Into<String>, pattern: impl Into<String>) -> Self {
        GqlFilter::Field {
            column: column.into(),
            op: FilterOp::Like,
            value: Value::String(pattern.into()),
        }
    }

    /// Create an `ilike` (case-insensitive like) filter.
    pub fn ilike(column: impl Into<String>, pattern: impl Into<String>) -> Self {
        GqlFilter::Field {
            column: column.into(),
            op: FilterOp::Ilike,
            value: Value::String(pattern.into()),
        }
    }

    /// Create a `startsWith` filter.
    pub fn starts_with(column: impl Into<String>, prefix: impl Into<String>) -> Self {
        GqlFilter::Field {
            column: column.into(),
            op: FilterOp::StartsWith,
            value: Value::String(prefix.into()),
        }
    }

    /// Logical AND of multiple filters.
    pub fn and(filters: Vec<GqlFilter>) -> Self {
        GqlFilter::And(filters)
    }

    /// Logical OR of multiple filters.
    pub fn or(filters: Vec<GqlFilter>) -> Self {
        GqlFilter::Or(filters)
    }

    /// Logical NOT of a filter.
    pub fn not(filter: GqlFilter) -> Self {
        GqlFilter::Not(Box::new(filter))
    }

    /// Convert this filter to a `serde_json::Value` for inlining into the query.
    pub fn to_value(&self) -> Value {
        match self {
            GqlFilter::Field { column, op, value } => {
                json!({ column.as_str(): { op.as_str(): value } })
            }
            GqlFilter::Is { column, value } => {
                // Is values are GraphQL enums — they'll be rendered as unquoted literals
                // by the render module. Store them as strings here.
                json!({ column.as_str(): { "is": value.as_graphql_literal() } })
            }
            GqlFilter::And(filters) => {
                let arr: Vec<Value> = filters.iter().map(|f| f.to_value()).collect();
                json!({ "and": arr })
            }
            GqlFilter::Or(filters) => {
                let arr: Vec<Value> = filters.iter().map(|f| f.to_value()).collect();
                json!({ "or": arr })
            }
            GqlFilter::Not(filter) => {
                json!({ "not": filter.to_value() })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_eq_string() {
        let f = GqlFilter::eq("title", json!("hello"));
        let v = f.to_value();
        assert_eq!(v, json!({"title": {"eq": "hello"}}));
    }

    #[test]
    fn filter_eq_number() {
        let f = GqlFilter::eq("age", json!(25));
        let v = f.to_value();
        assert_eq!(v, json!({"age": {"eq": 25}}));
    }

    #[test]
    fn filter_neq() {
        let f = GqlFilter::neq("status", json!("draft"));
        let v = f.to_value();
        assert_eq!(v, json!({"status": {"neq": "draft"}}));
    }

    #[test]
    fn filter_gt_gte_lt_lte() {
        assert_eq!(
            GqlFilter::gt("x", json!(10)).to_value(),
            json!({"x": {"gt": 10}})
        );
        assert_eq!(
            GqlFilter::gte("x", json!(10)).to_value(),
            json!({"x": {"gte": 10}})
        );
        assert_eq!(
            GqlFilter::lt("x", json!(10)).to_value(),
            json!({"x": {"lt": 10}})
        );
        assert_eq!(
            GqlFilter::lte("x", json!(10)).to_value(),
            json!({"x": {"lte": 10}})
        );
    }

    #[test]
    fn filter_in() {
        let f = GqlFilter::in_("id", vec![json!(1), json!(2), json!(3)]);
        let v = f.to_value();
        assert_eq!(v, json!({"id": {"in": [1, 2, 3]}}));
    }

    #[test]
    fn filter_is_null() {
        let f = GqlFilter::is_null("deleted_at");
        let v = f.to_value();
        assert_eq!(v, json!({"deleted_at": {"is": "NULL"}}));
    }

    #[test]
    fn filter_is_not_null() {
        let f = GqlFilter::is_not_null("email");
        let v = f.to_value();
        assert_eq!(v, json!({"email": {"is": "NOT_NULL"}}));
    }

    #[test]
    fn filter_like() {
        let f = GqlFilter::like("name", "%test%");
        let v = f.to_value();
        assert_eq!(v, json!({"name": {"like": "%test%"}}));
    }

    #[test]
    fn filter_ilike() {
        let f = GqlFilter::ilike("name", "%TEST%");
        let v = f.to_value();
        assert_eq!(v, json!({"name": {"ilike": "%TEST%"}}));
    }

    #[test]
    fn filter_starts_with() {
        let f = GqlFilter::starts_with("name", "foo");
        let v = f.to_value();
        assert_eq!(v, json!({"name": {"startsWith": "foo"}}));
    }

    #[test]
    fn filter_and() {
        let f = GqlFilter::and(vec![
            GqlFilter::gte("age", json!(18)),
            GqlFilter::eq("status", json!("active")),
        ]);
        let v = f.to_value();
        assert_eq!(
            v,
            json!({"and": [{"age": {"gte": 18}}, {"status": {"eq": "active"}}]})
        );
    }

    #[test]
    fn filter_or() {
        let f = GqlFilter::or(vec![
            GqlFilter::eq("role", json!("admin")),
            GqlFilter::eq("role", json!("moderator")),
        ]);
        let v = f.to_value();
        assert_eq!(
            v,
            json!({"or": [{"role": {"eq": "admin"}}, {"role": {"eq": "moderator"}}]})
        );
    }

    #[test]
    fn filter_not() {
        let f = GqlFilter::not(GqlFilter::eq("deleted", json!(true)));
        let v = f.to_value();
        assert_eq!(v, json!({"not": {"deleted": {"eq": true}}}));
    }

    #[test]
    fn filter_nested_compound() {
        let f = GqlFilter::and(vec![
            GqlFilter::eq("active", json!(true)),
            GqlFilter::or(vec![
                GqlFilter::eq("role", json!("admin")),
                GqlFilter::gte("level", json!(5)),
            ]),
        ]);
        let v = f.to_value();
        assert_eq!(
            v,
            json!({
                "and": [
                    {"active": {"eq": true}},
                    {"or": [
                        {"role": {"eq": "admin"}},
                        {"level": {"gte": 5}}
                    ]}
                ]
            })
        );
    }
}
