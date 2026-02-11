use crate::sql::{
    ArrayRangeOperator, FilterCondition, FilterOperator, IntoSqlParam, IsValue, ParamStore,
    PatternOperator, TextSearchType, validate_column_name,
};
/// Trait providing all filter methods for query builders.
///
/// Implementors must provide access to the internal filter list and param store.
pub trait Filterable: Sized {
    /// Get a mutable reference to the filter list.
    fn filters_mut(&mut self) -> &mut Vec<FilterCondition>;
    /// Get a mutable reference to the parameter store.
    fn params_mut(&mut self) -> &mut ParamStore;

    /// Filter: column = value
    fn eq(mut self, column: &str, value: impl IntoSqlParam) -> Self {
        if let Err(e) = validate_column_name(column) {
            tracing::error!("Invalid column name in eq filter: {e}");
            return self;
        }
        let idx = self.params_mut().push_value(value);
        self.filters_mut().push(FilterCondition::Comparison {
            column: column.to_string(),
            operator: FilterOperator::Eq,
            param_index: idx,
        });
        self
    }

    /// Filter: column != value
    fn neq(mut self, column: &str, value: impl IntoSqlParam) -> Self {
        if let Err(e) = validate_column_name(column) {
            tracing::error!("Invalid column name in neq filter: {e}");
            return self;
        }
        let idx = self.params_mut().push_value(value);
        self.filters_mut().push(FilterCondition::Comparison {
            column: column.to_string(),
            operator: FilterOperator::Neq,
            param_index: idx,
        });
        self
    }

    /// Filter: column > value
    fn gt(mut self, column: &str, value: impl IntoSqlParam) -> Self {
        if let Err(e) = validate_column_name(column) {
            tracing::error!("Invalid column name in gt filter: {e}");
            return self;
        }
        let idx = self.params_mut().push_value(value);
        self.filters_mut().push(FilterCondition::Comparison {
            column: column.to_string(),
            operator: FilterOperator::Gt,
            param_index: idx,
        });
        self
    }

    /// Filter: column >= value
    fn gte(mut self, column: &str, value: impl IntoSqlParam) -> Self {
        if let Err(e) = validate_column_name(column) {
            tracing::error!("Invalid column name in gte filter: {e}");
            return self;
        }
        let idx = self.params_mut().push_value(value);
        self.filters_mut().push(FilterCondition::Comparison {
            column: column.to_string(),
            operator: FilterOperator::Gte,
            param_index: idx,
        });
        self
    }

    /// Filter: column < value
    fn lt(mut self, column: &str, value: impl IntoSqlParam) -> Self {
        if let Err(e) = validate_column_name(column) {
            tracing::error!("Invalid column name in lt filter: {e}");
            return self;
        }
        let idx = self.params_mut().push_value(value);
        self.filters_mut().push(FilterCondition::Comparison {
            column: column.to_string(),
            operator: FilterOperator::Lt,
            param_index: idx,
        });
        self
    }

    /// Filter: column <= value
    fn lte(mut self, column: &str, value: impl IntoSqlParam) -> Self {
        if let Err(e) = validate_column_name(column) {
            tracing::error!("Invalid column name in lte filter: {e}");
            return self;
        }
        let idx = self.params_mut().push_value(value);
        self.filters_mut().push(FilterCondition::Comparison {
            column: column.to_string(),
            operator: FilterOperator::Lte,
            param_index: idx,
        });
        self
    }

    /// Filter: column LIKE pattern
    fn like(mut self, column: &str, pattern: impl IntoSqlParam) -> Self {
        if let Err(e) = validate_column_name(column) {
            tracing::error!("Invalid column name in like filter: {e}");
            return self;
        }
        let idx = self.params_mut().push_value(pattern);
        self.filters_mut().push(FilterCondition::Pattern {
            column: column.to_string(),
            operator: PatternOperator::Like,
            param_index: idx,
        });
        self
    }

    /// Filter: column ILIKE pattern (case-insensitive)
    fn ilike(mut self, column: &str, pattern: impl IntoSqlParam) -> Self {
        if let Err(e) = validate_column_name(column) {
            tracing::error!("Invalid column name in ilike filter: {e}");
            return self;
        }
        let idx = self.params_mut().push_value(pattern);
        self.filters_mut().push(FilterCondition::Pattern {
            column: column.to_string(),
            operator: PatternOperator::ILike,
            param_index: idx,
        });
        self
    }

    /// Filter: column IS NULL / IS NOT NULL / IS TRUE / IS FALSE
    fn is(mut self, column: &str, value: IsValue) -> Self {
        if let Err(e) = validate_column_name(column) {
            tracing::error!("Invalid column name in is filter: {e}");
            return self;
        }
        self.filters_mut().push(FilterCondition::Is {
            column: column.to_string(),
            value,
        });
        self
    }

    /// Filter: column IN (val1, val2, ...)
    fn in_<V: IntoSqlParam>(mut self, column: &str, values: Vec<V>) -> Self {
        if let Err(e) = validate_column_name(column) {
            tracing::error!("Invalid column name in in_ filter: {e}");
            return self;
        }
        let indices: Vec<usize> = values
            .into_iter()
            .map(|v| self.params_mut().push_value(v))
            .collect();
        self.filters_mut().push(FilterCondition::In {
            column: column.to_string(),
            param_indices: indices,
        });
        self
    }

    /// Filter: column @> value (contains)
    fn contains(mut self, column: &str, value: impl IntoSqlParam) -> Self {
        if let Err(e) = validate_column_name(column) {
            tracing::error!("Invalid column name in contains filter: {e}");
            return self;
        }
        let idx = self.params_mut().push_value(value);
        self.filters_mut().push(FilterCondition::ArrayRange {
            column: column.to_string(),
            operator: ArrayRangeOperator::Contains,
            param_index: idx,
        });
        self
    }

    /// Filter: column <@ value (contained by)
    fn contained_by(mut self, column: &str, value: impl IntoSqlParam) -> Self {
        if let Err(e) = validate_column_name(column) {
            tracing::error!("Invalid column name in contained_by filter: {e}");
            return self;
        }
        let idx = self.params_mut().push_value(value);
        self.filters_mut().push(FilterCondition::ArrayRange {
            column: column.to_string(),
            operator: ArrayRangeOperator::ContainedBy,
            param_index: idx,
        });
        self
    }

    /// Filter: column && value (overlaps)
    fn overlaps(mut self, column: &str, value: impl IntoSqlParam) -> Self {
        if let Err(e) = validate_column_name(column) {
            tracing::error!("Invalid column name in overlaps filter: {e}");
            return self;
        }
        let idx = self.params_mut().push_value(value);
        self.filters_mut().push(FilterCondition::ArrayRange {
            column: column.to_string(),
            operator: ArrayRangeOperator::Overlaps,
            param_index: idx,
        });
        self
    }

    /// Filter: column >> value (range strictly greater than)
    fn range_gt(mut self, column: &str, value: impl IntoSqlParam) -> Self {
        if let Err(e) = validate_column_name(column) {
            tracing::error!("Invalid column name in range_gt filter: {e}");
            return self;
        }
        let idx = self.params_mut().push_value(value);
        self.filters_mut().push(FilterCondition::ArrayRange {
            column: column.to_string(),
            operator: ArrayRangeOperator::RangeGt,
            param_index: idx,
        });
        self
    }

    /// Filter: column &> value (range greater than or equal)
    fn range_gte(mut self, column: &str, value: impl IntoSqlParam) -> Self {
        if let Err(e) = validate_column_name(column) {
            tracing::error!("Invalid column name in range_gte filter: {e}");
            return self;
        }
        let idx = self.params_mut().push_value(value);
        self.filters_mut().push(FilterCondition::ArrayRange {
            column: column.to_string(),
            operator: ArrayRangeOperator::RangeGte,
            param_index: idx,
        });
        self
    }

    /// Filter: column << value (range strictly less than)
    fn range_lt(mut self, column: &str, value: impl IntoSqlParam) -> Self {
        if let Err(e) = validate_column_name(column) {
            tracing::error!("Invalid column name in range_lt filter: {e}");
            return self;
        }
        let idx = self.params_mut().push_value(value);
        self.filters_mut().push(FilterCondition::ArrayRange {
            column: column.to_string(),
            operator: ArrayRangeOperator::RangeLt,
            param_index: idx,
        });
        self
    }

    /// Filter: column &< value (range less than or equal)
    fn range_lte(mut self, column: &str, value: impl IntoSqlParam) -> Self {
        if let Err(e) = validate_column_name(column) {
            tracing::error!("Invalid column name in range_lte filter: {e}");
            return self;
        }
        let idx = self.params_mut().push_value(value);
        self.filters_mut().push(FilterCondition::ArrayRange {
            column: column.to_string(),
            operator: ArrayRangeOperator::RangeLte,
            param_index: idx,
        });
        self
    }

    /// Filter: column -|- value (range adjacent)
    fn range_adjacent(mut self, column: &str, value: impl IntoSqlParam) -> Self {
        if let Err(e) = validate_column_name(column) {
            tracing::error!("Invalid column name in range_adjacent filter: {e}");
            return self;
        }
        let idx = self.params_mut().push_value(value);
        self.filters_mut().push(FilterCondition::ArrayRange {
            column: column.to_string(),
            operator: ArrayRangeOperator::RangeAdjacent,
            param_index: idx,
        });
        self
    }

    /// Full-text search filter.
    fn text_search(
        mut self,
        column: &str,
        query: impl IntoSqlParam,
        search_type: TextSearchType,
        config: Option<&str>,
    ) -> Self {
        if let Err(e) = validate_column_name(column) {
            tracing::error!("Invalid column name in text_search filter: {e}");
            return self;
        }
        let idx = self.params_mut().push_value(query);
        self.filters_mut().push(FilterCondition::TextSearch {
            column: column.to_string(),
            query_param_index: idx,
            config: config.map(|s| s.to_string()),
            search_type,
        });
        self
    }

    /// Negate a filter condition using a closure.
    fn not(mut self, f: impl FnOnce(FilterCollector) -> FilterCollector) -> Self {
        let collector = f(FilterCollector::new(self.params_mut()));
        if let Some(condition) = collector.into_single_condition() {
            self.filters_mut().push(FilterCondition::Not(Box::new(condition)));
        }
        self
    }

    /// OR filter: combine multiple conditions with OR.
    fn or_filter(mut self, f: impl FnOnce(FilterCollector) -> FilterCollector) -> Self {
        let collector = f(FilterCollector::new(self.params_mut()));
        let conditions = collector.into_conditions();
        if !conditions.is_empty() {
            self.filters_mut().push(FilterCondition::Or(conditions));
        }
        self
    }

    /// Match multiple column=value pairs (all must match).
    fn match_filter(mut self, pairs: Vec<(&str, impl IntoSqlParam + Clone)>) -> Self {
        let conditions: Vec<(String, usize)> = pairs
            .into_iter()
            .filter_map(|(col, val)| {
                if let Err(e) = validate_column_name(col) {
                    tracing::error!("Invalid column name in match_filter: {e}");
                    return None;
                }
                let idx = self.params_mut().push_value(val);
                Some((col.to_string(), idx))
            })
            .collect();
        if !conditions.is_empty() {
            self.filters_mut().push(FilterCondition::Match { conditions });
        }
        self
    }

    /// Raw filter escape hatch. The string should be a valid SQL boolean expression.
    fn filter(mut self, raw_sql: &str) -> Self {
        self.filters_mut()
            .push(FilterCondition::Raw(raw_sql.to_string()));
        self
    }
}

/// Temporary collector used in closures for `not()` and `or_filter()`.
pub struct FilterCollector<'a> {
    filters: Vec<FilterCondition>,
    params: &'a mut ParamStore,
}

impl<'a> FilterCollector<'a> {
    pub fn new(params: &'a mut ParamStore) -> Self {
        Self {
            filters: Vec::new(),
            params,
        }
    }

    pub fn eq(mut self, column: &str, value: impl IntoSqlParam) -> Self {
        if validate_column_name(column).is_ok() {
            let idx = self.params.push_value(value);
            self.filters.push(FilterCondition::Comparison {
                column: column.to_string(),
                operator: FilterOperator::Eq,
                param_index: idx,
            });
        }
        self
    }

    pub fn neq(mut self, column: &str, value: impl IntoSqlParam) -> Self {
        if validate_column_name(column).is_ok() {
            let idx = self.params.push_value(value);
            self.filters.push(FilterCondition::Comparison {
                column: column.to_string(),
                operator: FilterOperator::Neq,
                param_index: idx,
            });
        }
        self
    }

    pub fn gt(mut self, column: &str, value: impl IntoSqlParam) -> Self {
        if validate_column_name(column).is_ok() {
            let idx = self.params.push_value(value);
            self.filters.push(FilterCondition::Comparison {
                column: column.to_string(),
                operator: FilterOperator::Gt,
                param_index: idx,
            });
        }
        self
    }

    pub fn gte(mut self, column: &str, value: impl IntoSqlParam) -> Self {
        if validate_column_name(column).is_ok() {
            let idx = self.params.push_value(value);
            self.filters.push(FilterCondition::Comparison {
                column: column.to_string(),
                operator: FilterOperator::Gte,
                param_index: idx,
            });
        }
        self
    }

    pub fn lt(mut self, column: &str, value: impl IntoSqlParam) -> Self {
        if validate_column_name(column).is_ok() {
            let idx = self.params.push_value(value);
            self.filters.push(FilterCondition::Comparison {
                column: column.to_string(),
                operator: FilterOperator::Lt,
                param_index: idx,
            });
        }
        self
    }

    pub fn lte(mut self, column: &str, value: impl IntoSqlParam) -> Self {
        if validate_column_name(column).is_ok() {
            let idx = self.params.push_value(value);
            self.filters.push(FilterCondition::Comparison {
                column: column.to_string(),
                operator: FilterOperator::Lte,
                param_index: idx,
            });
        }
        self
    }

    pub fn like(mut self, column: &str, pattern: impl IntoSqlParam) -> Self {
        if validate_column_name(column).is_ok() {
            let idx = self.params.push_value(pattern);
            self.filters.push(FilterCondition::Pattern {
                column: column.to_string(),
                operator: PatternOperator::Like,
                param_index: idx,
            });
        }
        self
    }

    pub fn ilike(mut self, column: &str, pattern: impl IntoSqlParam) -> Self {
        if validate_column_name(column).is_ok() {
            let idx = self.params.push_value(pattern);
            self.filters.push(FilterCondition::Pattern {
                column: column.to_string(),
                operator: PatternOperator::ILike,
                param_index: idx,
            });
        }
        self
    }

    pub fn is(mut self, column: &str, value: IsValue) -> Self {
        if validate_column_name(column).is_ok() {
            self.filters.push(FilterCondition::Is {
                column: column.to_string(),
                value,
            });
        }
        self
    }

    pub fn into_conditions(self) -> Vec<FilterCondition> {
        self.filters
    }

    pub fn into_single_condition(self) -> Option<FilterCondition> {
        let mut filters = self.filters;
        if filters.len() == 1 {
            Some(filters.remove(0))
        } else if filters.is_empty() {
            None
        } else {
            Some(FilterCondition::And(filters))
        }
    }
}
