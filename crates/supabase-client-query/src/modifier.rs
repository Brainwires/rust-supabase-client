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
