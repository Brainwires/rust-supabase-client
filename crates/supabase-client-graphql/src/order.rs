use serde_json::{json, Value};

/// Ordering direction for GraphQL queries.
///
/// Maps to pg_graphql's `OrderByDirection` enum which includes null ordering.
#[derive(Debug, Clone, PartialEq)]
pub enum OrderByDirection {
    AscNullsFirst,
    AscNullsLast,
    DescNullsFirst,
    DescNullsLast,
}

impl OrderByDirection {
    /// The pg_graphql enum literal value (e.g., `AscNullsFirst`).
    pub fn as_graphql_literal(&self) -> &'static str {
        match self {
            OrderByDirection::AscNullsFirst => "AscNullsFirst",
            OrderByDirection::AscNullsLast => "AscNullsLast",
            OrderByDirection::DescNullsFirst => "DescNullsFirst",
            OrderByDirection::DescNullsLast => "DescNullsLast",
        }
    }
}

/// An order-by clause entry.
#[derive(Debug, Clone)]
pub struct OrderByEntry {
    pub column: String,
    pub direction: OrderByDirection,
}

impl OrderByEntry {
    /// Convert to a `serde_json::Value` for rendering.
    ///
    /// Produces `{ "column": "AscNullsLast" }` where the value is a GraphQL enum literal
    /// that will be rendered unquoted by the render module.
    pub fn to_value(&self) -> Value {
        json!({ self.column.as_str(): self.direction.as_graphql_literal() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_by_asc_nulls_last() {
        let entry = OrderByEntry {
            column: "createdAt".into(),
            direction: OrderByDirection::AscNullsLast,
        };
        assert_eq!(entry.to_value(), json!({"createdAt": "AscNullsLast"}));
    }

    #[test]
    fn order_by_desc_nulls_first() {
        let entry = OrderByEntry {
            column: "name".into(),
            direction: OrderByDirection::DescNullsFirst,
        };
        assert_eq!(entry.to_value(), json!({"name": "DescNullsFirst"}));
    }

    #[test]
    fn graphql_literal_values() {
        assert_eq!(OrderByDirection::AscNullsFirst.as_graphql_literal(), "AscNullsFirst");
        assert_eq!(OrderByDirection::AscNullsLast.as_graphql_literal(), "AscNullsLast");
        assert_eq!(OrderByDirection::DescNullsFirst.as_graphql_literal(), "DescNullsFirst");
        assert_eq!(OrderByDirection::DescNullsLast.as_graphql_literal(), "DescNullsLast");
    }
}
