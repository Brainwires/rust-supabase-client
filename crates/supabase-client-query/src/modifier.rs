use crate::sql::{CountOption, NullsPosition, OrderClause, OrderDirection, SqlParts, validate_column_name};

/// Trait providing modifier methods (order, limit, range, single, count).
pub trait Modifiable: Sized {
    /// Get a mutable reference to the SQL parts.
    fn parts_mut(&mut self) -> &mut SqlParts;

    /// Order by a column.
    fn order(mut self, column: &str, direction: OrderDirection) -> Self {
        if let Err(e) = validate_column_name(column) {
            tracing::error!("Invalid column name in order: {e}");
            return self;
        }
        self.parts_mut().orders.push(OrderClause {
            column: column.to_string(),
            direction,
            nulls: None,
        });
        self
    }

    /// Order by a column with explicit nulls positioning.
    fn order_with_nulls(
        mut self,
        column: &str,
        direction: OrderDirection,
        nulls: NullsPosition,
    ) -> Self {
        if let Err(e) = validate_column_name(column) {
            tracing::error!("Invalid column name in order_with_nulls: {e}");
            return self;
        }
        self.parts_mut().orders.push(OrderClause {
            column: column.to_string(),
            direction,
            nulls: Some(nulls),
        });
        self
    }

    /// Limit the number of rows returned.
    fn limit(mut self, count: i64) -> Self {
        self.parts_mut().limit = Some(count);
        self
    }

    /// Set the range of rows to return (offset..offset+limit).
    fn range(mut self, from: i64, to: i64) -> Self {
        self.parts_mut().offset = Some(from);
        self.parts_mut().limit = Some(to - from + 1);
        self
    }

    /// Expect exactly one row. Returns error if 0 or >1 rows.
    fn single(mut self) -> Self {
        self.parts_mut().single = true;
        self.parts_mut().limit = Some(2); // Fetch 2 to detect >1
        self
    }

    /// Expect zero or one row. Returns error if >1 rows.
    fn maybe_single(mut self) -> Self {
        self.parts_mut().maybe_single = true;
        self.parts_mut().limit = Some(2);
        self
    }

    /// Request an exact row count.
    fn count(mut self) -> Self {
        self.parts_mut().count = CountOption::Exact;
        self
    }

    /// Request a row count with a specific counting strategy.
    fn count_option(mut self, option: CountOption) -> Self {
        self.parts_mut().count = option;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::QueryBackend;
    use crate::select::SelectBuilder;
    use crate::sql::*;
    use std::marker::PhantomData;
    use std::sync::Arc;

    fn make_select() -> SelectBuilder<supabase_client_core::Row> {
        SelectBuilder {
            backend: QueryBackend::Rest {
                http: reqwest::Client::new(),
                base_url: Arc::from("http://localhost"),
                api_key: Arc::from("key"),
                schema: "public".to_string(),
            },
            parts: SqlParts::new(SqlOperation::Select, "public", "test"),
            params: ParamStore::new(),
            _marker: PhantomData,
        }
    }

    #[test]
    fn test_order_ascending() {
        let builder = make_select().order("name", OrderDirection::Ascending);
        assert_eq!(builder.parts.orders.len(), 1);
        assert_eq!(builder.parts.orders[0].column, "name");
        assert_eq!(builder.parts.orders[0].direction, OrderDirection::Ascending);
        assert!(builder.parts.orders[0].nulls.is_none());
    }

    #[test]
    fn test_order_descending() {
        let builder = make_select().order("created_at", OrderDirection::Descending);
        assert_eq!(builder.parts.orders.len(), 1);
        assert_eq!(builder.parts.orders[0].column, "created_at");
        assert_eq!(builder.parts.orders[0].direction, OrderDirection::Descending);
    }

    #[test]
    fn test_order_with_nulls_first() {
        let builder = make_select().order_with_nulls(
            "score",
            OrderDirection::Descending,
            NullsPosition::First,
        );
        assert_eq!(builder.parts.orders.len(), 1);
        assert_eq!(builder.parts.orders[0].column, "score");
        assert_eq!(builder.parts.orders[0].direction, OrderDirection::Descending);
        assert_eq!(builder.parts.orders[0].nulls, Some(NullsPosition::First));
    }

    #[test]
    fn test_order_with_nulls_last() {
        let builder = make_select().order_with_nulls(
            "score",
            OrderDirection::Ascending,
            NullsPosition::Last,
        );
        assert_eq!(builder.parts.orders[0].nulls, Some(NullsPosition::Last));
    }

    #[test]
    fn test_order_invalid_column_ignored() {
        let builder = make_select().order("bad;col", OrderDirection::Ascending);
        assert!(builder.parts.orders.is_empty());
    }

    #[test]
    fn test_order_with_nulls_invalid_column_ignored() {
        let builder = make_select().order_with_nulls(
            "bad\"col",
            OrderDirection::Ascending,
            NullsPosition::First,
        );
        assert!(builder.parts.orders.is_empty());
    }

    #[test]
    fn test_limit() {
        let builder = make_select().limit(10);
        assert_eq!(builder.parts.limit, Some(10));
    }

    #[test]
    fn test_range() {
        let builder = make_select().range(5, 14);
        assert_eq!(builder.parts.offset, Some(5));
        assert_eq!(builder.parts.limit, Some(10)); // 14 - 5 + 1 = 10
    }

    #[test]
    fn test_range_single_row() {
        let builder = make_select().range(0, 0);
        assert_eq!(builder.parts.offset, Some(0));
        assert_eq!(builder.parts.limit, Some(1)); // 0 - 0 + 1 = 1
    }

    #[test]
    fn test_single() {
        let builder = make_select().single();
        assert!(builder.parts.single);
        assert_eq!(builder.parts.limit, Some(2));
    }

    #[test]
    fn test_maybe_single() {
        let builder = make_select().maybe_single();
        assert!(builder.parts.maybe_single);
        assert_eq!(builder.parts.limit, Some(2));
    }

    #[test]
    fn test_count() {
        let builder = make_select().count();
        assert_eq!(builder.parts.count, CountOption::Exact);
    }

    #[test]
    fn test_count_option_exact() {
        let builder = make_select().count_option(CountOption::Exact);
        assert_eq!(builder.parts.count, CountOption::Exact);
    }

    #[test]
    fn test_count_option_planned() {
        let builder = make_select().count_option(CountOption::Planned);
        assert_eq!(builder.parts.count, CountOption::Planned);
    }

    #[test]
    fn test_count_option_estimated() {
        let builder = make_select().count_option(CountOption::Estimated);
        assert_eq!(builder.parts.count, CountOption::Estimated);
    }

    #[test]
    fn test_count_option_none() {
        let builder = make_select().count_option(CountOption::None);
        assert_eq!(builder.parts.count, CountOption::None);
    }
}
