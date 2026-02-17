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
    fn test_eq_adds_comparison_filter() {
        let builder = make_select().eq("name", "Alice");
        assert_eq!(builder.parts.filters.len(), 1);
        match &builder.parts.filters[0] {
            FilterCondition::Comparison { column, operator, param_index } => {
                assert_eq!(column, "name");
                assert_eq!(*operator, FilterOperator::Eq);
                assert_eq!(*param_index, 1);
            }
            _ => panic!("expected Comparison filter"),
        }
    }

    #[test]
    fn test_neq_adds_comparison_filter() {
        let builder = make_select().neq("status", "inactive");
        assert_eq!(builder.parts.filters.len(), 1);
        match &builder.parts.filters[0] {
            FilterCondition::Comparison { column, operator, .. } => {
                assert_eq!(column, "status");
                assert_eq!(*operator, FilterOperator::Neq);
            }
            _ => panic!("expected Comparison filter"),
        }
    }

    #[test]
    fn test_gt_adds_comparison_filter() {
        let builder = make_select().gt("age", 18i32);
        match &builder.parts.filters[0] {
            FilterCondition::Comparison { column, operator, .. } => {
                assert_eq!(column, "age");
                assert_eq!(*operator, FilterOperator::Gt);
            }
            _ => panic!("expected Comparison filter"),
        }
    }

    #[test]
    fn test_gte_adds_comparison_filter() {
        let builder = make_select().gte("score", 90i32);
        match &builder.parts.filters[0] {
            FilterCondition::Comparison { column, operator, .. } => {
                assert_eq!(column, "score");
                assert_eq!(*operator, FilterOperator::Gte);
            }
            _ => panic!("expected Comparison filter"),
        }
    }

    #[test]
    fn test_lt_adds_comparison_filter() {
        let builder = make_select().lt("price", 100i32);
        match &builder.parts.filters[0] {
            FilterCondition::Comparison { column, operator, .. } => {
                assert_eq!(column, "price");
                assert_eq!(*operator, FilterOperator::Lt);
            }
            _ => panic!("expected Comparison filter"),
        }
    }

    #[test]
    fn test_lte_adds_comparison_filter() {
        let builder = make_select().lte("count", 50i32);
        match &builder.parts.filters[0] {
            FilterCondition::Comparison { column, operator, .. } => {
                assert_eq!(column, "count");
                assert_eq!(*operator, FilterOperator::Lte);
            }
            _ => panic!("expected Comparison filter"),
        }
    }

    #[test]
    fn test_like_adds_pattern_filter() {
        let builder = make_select().like("name", "%test%");
        assert_eq!(builder.parts.filters.len(), 1);
        match &builder.parts.filters[0] {
            FilterCondition::Pattern { column, operator, .. } => {
                assert_eq!(column, "name");
                assert_eq!(*operator, PatternOperator::Like);
            }
            _ => panic!("expected Pattern filter"),
        }
    }

    #[test]
    fn test_ilike_adds_pattern_filter() {
        let builder = make_select().ilike("name", "%TEST%");
        match &builder.parts.filters[0] {
            FilterCondition::Pattern { column, operator, .. } => {
                assert_eq!(column, "name");
                assert_eq!(*operator, PatternOperator::ILike);
            }
            _ => panic!("expected Pattern filter"),
        }
    }

    #[test]
    fn test_is_null() {
        let builder = make_select().is("deleted_at", IsValue::Null);
        match &builder.parts.filters[0] {
            FilterCondition::Is { column, value } => {
                assert_eq!(column, "deleted_at");
                assert_eq!(*value, IsValue::Null);
            }
            _ => panic!("expected Is filter"),
        }
    }

    #[test]
    fn test_is_not_null() {
        let builder = make_select().is("name", IsValue::NotNull);
        match &builder.parts.filters[0] {
            FilterCondition::Is { value, .. } => assert_eq!(*value, IsValue::NotNull),
            _ => panic!("expected Is filter"),
        }
    }

    #[test]
    fn test_is_true() {
        let builder = make_select().is("active", IsValue::True);
        match &builder.parts.filters[0] {
            FilterCondition::Is { value, .. } => assert_eq!(*value, IsValue::True),
            _ => panic!("expected Is filter"),
        }
    }

    #[test]
    fn test_is_false() {
        let builder = make_select().is("active", IsValue::False);
        match &builder.parts.filters[0] {
            FilterCondition::Is { value, .. } => assert_eq!(*value, IsValue::False),
            _ => panic!("expected Is filter"),
        }
    }

    #[test]
    fn test_in_with_values() {
        let builder = make_select().in_("id", vec![1i32, 2, 3]);
        assert_eq!(builder.parts.filters.len(), 1);
        match &builder.parts.filters[0] {
            FilterCondition::In { column, param_indices } => {
                assert_eq!(column, "id");
                assert_eq!(param_indices.len(), 3);
                assert_eq!(param_indices[0], 1);
                assert_eq!(param_indices[1], 2);
                assert_eq!(param_indices[2], 3);
            }
            _ => panic!("expected In filter"),
        }
    }

    #[test]
    fn test_contains_adds_array_range_filter() {
        let builder = make_select().contains("tags", "rust");
        match &builder.parts.filters[0] {
            FilterCondition::ArrayRange { column, operator, .. } => {
                assert_eq!(column, "tags");
                assert_eq!(*operator, ArrayRangeOperator::Contains);
            }
            _ => panic!("expected ArrayRange filter"),
        }
    }

    #[test]
    fn test_contained_by_adds_array_range_filter() {
        let builder = make_select().contained_by("tags", "all_tags");
        match &builder.parts.filters[0] {
            FilterCondition::ArrayRange { column, operator, .. } => {
                assert_eq!(column, "tags");
                assert_eq!(*operator, ArrayRangeOperator::ContainedBy);
            }
            _ => panic!("expected ArrayRange filter"),
        }
    }

    #[test]
    fn test_overlaps_adds_array_range_filter() {
        let builder = make_select().overlaps("tags", "some_tags");
        match &builder.parts.filters[0] {
            FilterCondition::ArrayRange { column, operator, .. } => {
                assert_eq!(column, "tags");
                assert_eq!(*operator, ArrayRangeOperator::Overlaps);
            }
            _ => panic!("expected ArrayRange filter"),
        }
    }

    #[test]
    fn test_range_gt() {
        let builder = make_select().range_gt("period", "[2024-01-01,2024-12-31]");
        match &builder.parts.filters[0] {
            FilterCondition::ArrayRange { operator, .. } => {
                assert_eq!(*operator, ArrayRangeOperator::RangeGt);
            }
            _ => panic!("expected ArrayRange filter"),
        }
    }

    #[test]
    fn test_range_gte() {
        let builder = make_select().range_gte("period", "[2024-01-01,2024-12-31]");
        match &builder.parts.filters[0] {
            FilterCondition::ArrayRange { operator, .. } => {
                assert_eq!(*operator, ArrayRangeOperator::RangeGte);
            }
            _ => panic!("expected ArrayRange filter"),
        }
    }

    #[test]
    fn test_range_lt() {
        let builder = make_select().range_lt("period", "[2024-01-01,2024-12-31]");
        match &builder.parts.filters[0] {
            FilterCondition::ArrayRange { operator, .. } => {
                assert_eq!(*operator, ArrayRangeOperator::RangeLt);
            }
            _ => panic!("expected ArrayRange filter"),
        }
    }

    #[test]
    fn test_range_lte() {
        let builder = make_select().range_lte("period", "[2024-01-01,2024-12-31]");
        match &builder.parts.filters[0] {
            FilterCondition::ArrayRange { operator, .. } => {
                assert_eq!(*operator, ArrayRangeOperator::RangeLte);
            }
            _ => panic!("expected ArrayRange filter"),
        }
    }

    #[test]
    fn test_range_adjacent() {
        let builder = make_select().range_adjacent("period", "[2024-01-01,2024-12-31]");
        match &builder.parts.filters[0] {
            FilterCondition::ArrayRange { operator, .. } => {
                assert_eq!(*operator, ArrayRangeOperator::RangeAdjacent);
            }
            _ => panic!("expected ArrayRange filter"),
        }
    }

    #[test]
    fn test_text_search_without_config() {
        let builder = make_select().text_search("body", "hello world", TextSearchType::Plain, None);
        match &builder.parts.filters[0] {
            FilterCondition::TextSearch { column, config, search_type, .. } => {
                assert_eq!(column, "body");
                assert!(config.is_none());
                assert_eq!(*search_type, TextSearchType::Plain);
            }
            _ => panic!("expected TextSearch filter"),
        }
    }

    #[test]
    fn test_text_search_with_config() {
        let builder = make_select().text_search(
            "body",
            "hello world",
            TextSearchType::Websearch,
            Some("english"),
        );
        match &builder.parts.filters[0] {
            FilterCondition::TextSearch { config, search_type, .. } => {
                assert_eq!(config.as_deref(), Some("english"));
                assert_eq!(*search_type, TextSearchType::Websearch);
            }
            _ => panic!("expected TextSearch filter"),
        }
    }

    #[test]
    fn test_not_wraps_in_not() {
        let builder = make_select().not(|f| f.eq("active", true));
        assert_eq!(builder.parts.filters.len(), 1);
        match &builder.parts.filters[0] {
            FilterCondition::Not(inner) => {
                assert!(matches!(inner.as_ref(), FilterCondition::Comparison { .. }));
            }
            _ => panic!("expected Not filter"),
        }
    }

    #[test]
    fn test_or_filter_wraps_in_or() {
        let builder = make_select().or_filter(|f| f.eq("a", 1i32).eq("b", 2i32));
        assert_eq!(builder.parts.filters.len(), 1);
        match &builder.parts.filters[0] {
            FilterCondition::Or(conditions) => {
                assert_eq!(conditions.len(), 2);
            }
            _ => panic!("expected Or filter"),
        }
    }

    #[test]
    fn test_match_filter_creates_match_conditions() {
        let builder = make_select().match_filter(vec![("name", "Alice"), ("age", "30")]);
        assert_eq!(builder.parts.filters.len(), 1);
        match &builder.parts.filters[0] {
            FilterCondition::Match { conditions } => {
                assert_eq!(conditions.len(), 2);
                assert_eq!(conditions[0].0, "name");
                assert_eq!(conditions[1].0, "age");
            }
            _ => panic!("expected Match filter"),
        }
    }

    #[test]
    fn test_filter_raw_sql() {
        let builder = make_select().filter("age > 18 AND status = 'active'");
        match &builder.parts.filters[0] {
            FilterCondition::Raw(sql) => {
                assert_eq!(sql, "age > 18 AND status = 'active'");
            }
            _ => panic!("expected Raw filter"),
        }
    }

    #[test]
    fn test_invalid_column_name_silently_ignored() {
        let builder = make_select().eq("bad;col", "value");
        assert!(builder.parts.filters.is_empty());
    }

    #[test]
    fn test_invalid_column_name_in_neq_silently_ignored() {
        let builder = make_select().neq("bad\"col", "value");
        assert!(builder.parts.filters.is_empty());
    }

    #[test]
    fn test_invalid_column_name_in_like_silently_ignored() {
        let builder = make_select().like("bad--col", "%test%");
        assert!(builder.parts.filters.is_empty());
    }

    #[test]
    fn test_invalid_column_name_in_is_silently_ignored() {
        let builder = make_select().is("", IsValue::Null);
        assert!(builder.parts.filters.is_empty());
    }

    // ---- FilterCollector ----

    #[test]
    fn test_filter_collector_into_conditions() {
        let mut params = ParamStore::new();
        let collector = FilterCollector::new(&mut params)
            .eq("a", 1i32)
            .eq("b", 2i32);
        let conditions = collector.into_conditions();
        assert_eq!(conditions.len(), 2);
    }

    #[test]
    fn test_filter_collector_into_single_condition_single() {
        let mut params = ParamStore::new();
        let collector = FilterCollector::new(&mut params).eq("a", 1i32);
        let condition = collector.into_single_condition();
        assert!(condition.is_some());
        assert!(matches!(condition.unwrap(), FilterCondition::Comparison { .. }));
    }

    #[test]
    fn test_filter_collector_into_single_condition_empty() {
        let mut params = ParamStore::new();
        let collector = FilterCollector::new(&mut params);
        let condition = collector.into_single_condition();
        assert!(condition.is_none());
    }

    #[test]
    fn test_filter_collector_into_single_condition_multiple() {
        let mut params = ParamStore::new();
        let collector = FilterCollector::new(&mut params)
            .eq("a", 1i32)
            .neq("b", 2i32);
        let condition = collector.into_single_condition();
        assert!(condition.is_some());
        assert!(matches!(condition.unwrap(), FilterCondition::And(_)));
    }

    #[test]
    fn test_filter_collector_all_methods() {
        let mut params = ParamStore::new();
        let collector = FilterCollector::new(&mut params)
            .gt("a", 1i32)
            .gte("b", 2i32)
            .lt("c", 3i32)
            .lte("d", 4i32)
            .like("e", "%test%")
            .ilike("f", "%TEST%")
            .is("g", IsValue::Null);
        let conditions = collector.into_conditions();
        assert_eq!(conditions.len(), 7);
    }

    #[test]
    fn test_filter_collector_invalid_column_skipped() {
        let mut params = ParamStore::new();
        let collector = FilterCollector::new(&mut params)
            .eq("good_col", 1i32)
            .eq("bad;col", 2i32);
        let conditions = collector.into_conditions();
        assert_eq!(conditions.len(), 1);
    }
}
