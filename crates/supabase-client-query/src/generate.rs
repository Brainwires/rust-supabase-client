use crate::sql::{
    CountOption, FilterCondition, SqlOperation, SqlParts, validate_column_name, validate_identifier,
};
use supabase_client_core::SupabaseError;

impl SqlParts {
    /// Build the complete SQL query string.
    pub fn build_sql(&self) -> Result<String, SupabaseError> {
        validate_identifier(&self.schema, "Schema")?;
        validate_identifier(&self.table, "Table")?;
        if let Some(ref s) = self.schema_override {
            validate_identifier(s, "Schema override")?;
        }

        match self.operation {
            SqlOperation::Select => self.build_select(),
            SqlOperation::Insert => self.build_insert(),
            SqlOperation::Update => self.build_update(),
            SqlOperation::Delete => self.build_delete(),
            SqlOperation::Upsert => self.build_upsert(),
        }
    }

    fn build_select(&self) -> Result<String, SupabaseError> {
        let table = self.qualified_table();

        let mut sql = if self.head {
            // Head mode: count only, no rows
            let mut s = format!("SELECT count(*) FROM {}", table);
            self.append_where_clause(&mut s)?;
            return self.maybe_wrap_explain(s);
        } else if self.count == CountOption::Exact {
            let cols = self.select_columns.as_deref().unwrap_or("*");
            format!(
                "SELECT {cols}, COUNT(*) OVER() AS \"__count\" FROM {}",
                table
            )
        } else {
            let cols = self.select_columns.as_deref().unwrap_or("*");
            format!("SELECT {cols} FROM {}", table)
        };

        self.append_where_clause(&mut sql)?;
        self.append_order_clause(&mut sql)?;
        self.append_limit_offset(&mut sql);

        self.maybe_wrap_explain(sql)
    }

    fn build_insert(&self) -> Result<String, SupabaseError> {
        if self.many_rows.is_empty() && self.set_clauses.is_empty() {
            return Err(SupabaseError::query_builder("No values to insert"));
        }

        let rows = if self.many_rows.is_empty() {
            vec![&self.set_clauses]
        } else {
            self.many_rows.iter().collect()
        };

        // Use columns from the first row
        let columns: Vec<&str> = rows[0].iter().map(|(c, _)| c.as_str()).collect();
        for col in &columns {
            validate_column_name(col)?;
        }

        let col_list = columns
            .iter()
            .map(|c| format!("\"{}\"", c))
            .collect::<Vec<_>>()
            .join(", ");

        let value_groups: Vec<String> = rows
            .iter()
            .map(|row| {
                let placeholders: Vec<String> =
                    row.iter().map(|(_, idx)| format!("${}", idx)).collect();
                format!("({})", placeholders.join(", "))
            })
            .collect();

        let table = self.qualified_table();
        let mut sql = format!(
            "INSERT INTO {} ({}) VALUES {}",
            table,
            col_list,
            value_groups.join(", ")
        );

        self.append_returning(&mut sql);
        Ok(sql)
    }

    fn build_update(&self) -> Result<String, SupabaseError> {
        if self.set_clauses.is_empty() {
            return Err(SupabaseError::query_builder("No values to update"));
        }

        let set_parts: Vec<String> = self
            .set_clauses
            .iter()
            .map(|(col, idx)| {
                validate_column_name(col)?;
                Ok(format!("\"{}\" = ${}", col, idx))
            })
            .collect::<Result<Vec<_>, SupabaseError>>()?;

        let table = self.qualified_table();
        let mut sql = format!(
            "UPDATE {} SET {}",
            table,
            set_parts.join(", ")
        );

        self.append_where_clause(&mut sql)?;
        self.append_returning(&mut sql);
        Ok(sql)
    }

    fn build_delete(&self) -> Result<String, SupabaseError> {
        let table = self.qualified_table();
        let mut sql = format!("DELETE FROM {}", table);
        self.append_where_clause(&mut sql)?;
        self.append_returning(&mut sql);
        Ok(sql)
    }

    fn build_upsert(&self) -> Result<String, SupabaseError> {
        if self.many_rows.is_empty() && self.set_clauses.is_empty() {
            return Err(SupabaseError::query_builder("No values to upsert"));
        }

        let rows = if self.many_rows.is_empty() {
            vec![&self.set_clauses]
        } else {
            self.many_rows.iter().collect()
        };

        let columns: Vec<&str> = rows[0].iter().map(|(c, _)| c.as_str()).collect();
        for col in &columns {
            validate_column_name(col)?;
        }

        let col_list = columns
            .iter()
            .map(|c| format!("\"{}\"", c))
            .collect::<Vec<_>>()
            .join(", ");

        let value_groups: Vec<String> = rows
            .iter()
            .map(|row| {
                let placeholders: Vec<String> =
                    row.iter().map(|(_, idx)| format!("${}", idx)).collect();
                format!("({})", placeholders.join(", "))
            })
            .collect();

        let table = self.qualified_table();
        let mut sql = format!(
            "INSERT INTO {} ({}) VALUES {}",
            table,
            col_list,
            value_groups.join(", ")
        );

        // ON CONFLICT clause
        if let Some(ref constraint) = self.conflict_constraint {
            sql.push_str(&format!(" ON CONFLICT ON CONSTRAINT \"{}\"", constraint));
        } else if !self.conflict_columns.is_empty() {
            let conflict_cols: Vec<String> =
                self.conflict_columns.iter().map(|c| format!("\"{}\"", c)).collect();
            sql.push_str(&format!(" ON CONFLICT ({})", conflict_cols.join(", ")));
        } else {
            // Default: use primary key columns if we have them, otherwise just use all columns
            // The caller should set conflict_columns
            sql.push_str(" ON CONFLICT");
        }

        // ignore_duplicates → DO NOTHING regardless of columns
        if self.ignore_duplicates {
            sql.push_str(" DO NOTHING");
        } else {
            // DO UPDATE SET for non-conflict columns
            let update_cols: Vec<String> = columns
                .iter()
                .filter(|c| !self.conflict_columns.iter().any(|cc| cc == **c))
                .map(|c| format!("\"{}\" = EXCLUDED.\"{}\"", c, c))
                .collect();

            if update_cols.is_empty() {
                sql.push_str(" DO NOTHING");
            } else {
                sql.push_str(&format!(" DO UPDATE SET {}", update_cols.join(", ")));
            }
        }

        self.append_returning(&mut sql);
        Ok(sql)
    }

    fn append_where_clause(&self, sql: &mut String) -> Result<(), SupabaseError> {
        if self.filters.is_empty() {
            return Ok(());
        }

        let conditions: Vec<String> = self
            .filters
            .iter()
            .map(|f| build_filter_sql(f))
            .collect::<Result<Vec<_>, _>>()?;

        sql.push_str(" WHERE ");
        sql.push_str(&conditions.join(" AND "));
        Ok(())
    }

    fn append_order_clause(&self, sql: &mut String) -> Result<(), SupabaseError> {
        if self.orders.is_empty() {
            return Ok(());
        }

        let parts: Vec<String> = self
            .orders
            .iter()
            .map(|o| {
                validate_column_name(&o.column)?;
                let mut s = format!("\"{}\" {}", o.column, o.direction.as_sql());
                if let Some(nulls) = &o.nulls {
                    s.push(' ');
                    s.push_str(nulls.as_sql());
                }
                Ok(s)
            })
            .collect::<Result<Vec<_>, SupabaseError>>()?;

        sql.push_str(" ORDER BY ");
        sql.push_str(&parts.join(", "));
        Ok(())
    }

    fn append_limit_offset(&self, sql: &mut String) {
        if let Some(limit) = self.limit {
            sql.push_str(&format!(" LIMIT {}", limit));
        }
        if let Some(offset) = self.offset {
            sql.push_str(&format!(" OFFSET {}", offset));
        }
    }

    fn append_returning(&self, sql: &mut String) {
        if let Some(ref returning) = self.returning {
            sql.push_str(&format!(" RETURNING {}", returning));
        }
    }

    fn maybe_wrap_explain(&self, sql: String) -> Result<String, SupabaseError> {
        match &self.explain {
            Some(opts) => {
                let mut options = Vec::new();
                if opts.analyze {
                    options.push("ANALYZE".to_string());
                }
                if opts.verbose {
                    options.push("VERBOSE".to_string());
                }
                options.push(format!("FORMAT {}", opts.format.as_sql()));
                Ok(format!("EXPLAIN ({}) {}", options.join(", "), sql))
            }
            None => Ok(sql),
        }
    }
}

/// Build SQL for a single filter condition.
fn build_filter_sql(condition: &FilterCondition) -> Result<String, SupabaseError> {
    match condition {
        FilterCondition::Comparison {
            column,
            operator,
            param_index,
        } => {
            validate_column_name(column)?;
            Ok(format!(
                "\"{}\" {} ${}",
                column,
                operator.as_sql(),
                param_index
            ))
        }
        FilterCondition::Is { column, value } => {
            validate_column_name(column)?;
            Ok(format!("\"{}\" {}", column, value.as_sql()))
        }
        FilterCondition::In {
            column,
            param_indices,
        } => {
            validate_column_name(column)?;
            if param_indices.is_empty() {
                // IN with empty list → always false
                return Ok("FALSE".to_string());
            }
            let placeholders: Vec<String> =
                param_indices.iter().map(|i| format!("${}", i)).collect();
            Ok(format!(
                "\"{}\" IN ({})",
                column,
                placeholders.join(", ")
            ))
        }
        FilterCondition::Pattern {
            column,
            operator,
            param_index,
        } => {
            validate_column_name(column)?;
            Ok(format!(
                "\"{}\" {} ${}",
                column,
                operator.as_sql(),
                param_index
            ))
        }
        FilterCondition::TextSearch {
            column,
            query_param_index,
            config,
            search_type,
        } => {
            validate_column_name(column)?;
            let func = search_type.function_name();
            let ts_query = if let Some(cfg) = config {
                format!("{}('{}', ${})", func, cfg, query_param_index)
            } else {
                format!("{}(${})", func, query_param_index)
            };
            Ok(format!("\"{}\" @@ {}", column, ts_query))
        }
        FilterCondition::ArrayRange {
            column,
            operator,
            param_index,
        } => {
            validate_column_name(column)?;
            Ok(format!(
                "\"{}\" {} ${}",
                column,
                operator.as_sql(),
                param_index
            ))
        }
        FilterCondition::Not(inner) => {
            let inner_sql = build_filter_sql(inner)?;
            Ok(format!("NOT ({})", inner_sql))
        }
        FilterCondition::Or(conditions) => {
            if conditions.is_empty() {
                return Ok("TRUE".to_string());
            }
            let parts: Vec<String> = conditions
                .iter()
                .map(|c| build_filter_sql(c))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(format!("({})", parts.join(" OR ")))
        }
        FilterCondition::And(conditions) => {
            if conditions.is_empty() {
                return Ok("TRUE".to_string());
            }
            let parts: Vec<String> = conditions
                .iter()
                .map(|c| build_filter_sql(c))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(format!("({})", parts.join(" AND ")))
        }
        FilterCondition::Raw(sql) => Ok(sql.clone()),
        FilterCondition::Match { conditions } => {
            let parts: Vec<String> = conditions
                .iter()
                .map(|(col, idx)| {
                    validate_column_name(col)?;
                    Ok(format!("\"{}\" = ${}", col, idx))
                })
                .collect::<Result<Vec<_>, SupabaseError>>()?;
            Ok(format!("({})", parts.join(" AND ")))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::sql::*;

    #[test]
    fn test_build_select_simple() {
        let parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        let sql = parts.build_sql().unwrap();
        assert_eq!(sql, "SELECT * FROM \"public\".\"cities\"");
    }

    #[test]
    fn test_build_select_with_columns() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.select_columns = Some("\"name\", \"country_id\"".to_string());
        let sql = parts.build_sql().unwrap();
        assert_eq!(
            sql,
            "SELECT \"name\", \"country_id\" FROM \"public\".\"cities\""
        );
    }

    #[test]
    fn test_build_select_with_filter() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.filters.push(FilterCondition::Comparison {
            column: "name".to_string(),
            operator: FilterOperator::Eq,
            param_index: 1,
        });
        let sql = parts.build_sql().unwrap();
        assert_eq!(
            sql,
            "SELECT * FROM \"public\".\"cities\" WHERE \"name\" = $1"
        );
    }

    #[test]
    fn test_build_select_with_order_limit() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.orders.push(OrderClause {
            column: "name".to_string(),
            direction: OrderDirection::Ascending,
            nulls: None,
        });
        parts.limit = Some(10);
        parts.offset = Some(5);
        let sql = parts.build_sql().unwrap();
        assert_eq!(
            sql,
            "SELECT * FROM \"public\".\"cities\" ORDER BY \"name\" ASC LIMIT 10 OFFSET 5"
        );
    }

    #[test]
    fn test_build_insert() {
        let mut parts = SqlParts::new(SqlOperation::Insert, "public", "cities");
        parts.set_clauses = vec![
            ("name".to_string(), 1),
            ("country_id".to_string(), 2),
        ];
        parts.returning = Some("*".to_string());
        let sql = parts.build_sql().unwrap();
        assert_eq!(
            sql,
            "INSERT INTO \"public\".\"cities\" (\"name\", \"country_id\") VALUES ($1, $2) RETURNING *"
        );
    }

    #[test]
    fn test_build_insert_many() {
        let mut parts = SqlParts::new(SqlOperation::Insert, "public", "cities");
        parts.many_rows = vec![
            vec![("name".to_string(), 1), ("country_id".to_string(), 2)],
            vec![("name".to_string(), 3), ("country_id".to_string(), 4)],
        ];
        let sql = parts.build_sql().unwrap();
        assert_eq!(
            sql,
            "INSERT INTO \"public\".\"cities\" (\"name\", \"country_id\") VALUES ($1, $2), ($3, $4)"
        );
    }

    #[test]
    fn test_build_update() {
        let mut parts = SqlParts::new(SqlOperation::Update, "public", "cities");
        parts.set_clauses = vec![("name".to_string(), 1)];
        parts.filters.push(FilterCondition::Comparison {
            column: "id".to_string(),
            operator: FilterOperator::Eq,
            param_index: 2,
        });
        parts.returning = Some("*".to_string());
        let sql = parts.build_sql().unwrap();
        assert_eq!(
            sql,
            "UPDATE \"public\".\"cities\" SET \"name\" = $1 WHERE \"id\" = $2 RETURNING *"
        );
    }

    #[test]
    fn test_build_delete() {
        let mut parts = SqlParts::new(SqlOperation::Delete, "public", "cities");
        parts.filters.push(FilterCondition::Comparison {
            column: "id".to_string(),
            operator: FilterOperator::Eq,
            param_index: 1,
        });
        let sql = parts.build_sql().unwrap();
        assert_eq!(
            sql,
            "DELETE FROM \"public\".\"cities\" WHERE \"id\" = $1"
        );
    }

    #[test]
    fn test_build_upsert() {
        let mut parts = SqlParts::new(SqlOperation::Upsert, "public", "cities");
        parts.set_clauses = vec![
            ("id".to_string(), 1),
            ("name".to_string(), 2),
        ];
        parts.conflict_columns = vec!["id".to_string()];
        parts.returning = Some("*".to_string());
        let sql = parts.build_sql().unwrap();
        assert_eq!(
            sql,
            "INSERT INTO \"public\".\"cities\" (\"id\", \"name\") VALUES ($1, $2) ON CONFLICT (\"id\") DO UPDATE SET \"name\" = EXCLUDED.\"name\" RETURNING *"
        );
    }

    #[test]
    fn test_build_or_filter() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.filters.push(FilterCondition::Or(vec![
            FilterCondition::Comparison {
                column: "name".to_string(),
                operator: FilterOperator::Eq,
                param_index: 1,
            },
            FilterCondition::Comparison {
                column: "name".to_string(),
                operator: FilterOperator::Eq,
                param_index: 2,
            },
        ]));
        let sql = parts.build_sql().unwrap();
        assert_eq!(
            sql,
            "SELECT * FROM \"public\".\"cities\" WHERE (\"name\" = $1 OR \"name\" = $2)"
        );
    }

    #[test]
    fn test_build_not_filter() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.filters.push(FilterCondition::Not(Box::new(
            FilterCondition::Comparison {
                column: "active".to_string(),
                operator: FilterOperator::Eq,
                param_index: 1,
            },
        )));
        let sql = parts.build_sql().unwrap();
        assert_eq!(
            sql,
            "SELECT * FROM \"public\".\"cities\" WHERE NOT (\"active\" = $1)"
        );
    }

    #[test]
    fn test_build_in_filter() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.filters.push(FilterCondition::In {
            column: "id".to_string(),
            param_indices: vec![1, 2, 3],
        });
        let sql = parts.build_sql().unwrap();
        assert_eq!(
            sql,
            "SELECT * FROM \"public\".\"cities\" WHERE \"id\" IN ($1, $2, $3)"
        );
    }

    #[test]
    fn test_build_is_null() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.filters.push(FilterCondition::Is {
            column: "deleted_at".to_string(),
            value: crate::sql::IsValue::Null,
        });
        let sql = parts.build_sql().unwrap();
        assert_eq!(
            sql,
            "SELECT * FROM \"public\".\"cities\" WHERE \"deleted_at\" IS NULL"
        );
    }

    #[test]
    fn test_build_text_search() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.filters.push(FilterCondition::TextSearch {
            column: "fts".to_string(),
            query_param_index: 1,
            config: Some("english".to_string()),
            search_type: crate::sql::TextSearchType::Plain,
        });
        let sql = parts.build_sql().unwrap();
        assert_eq!(
            sql,
            "SELECT * FROM \"public\".\"cities\" WHERE \"fts\" @@ plainto_tsquery('english', $1)"
        );
    }

    #[test]
    fn test_build_select_with_count() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.count = CountOption::Exact;
        let sql = parts.build_sql().unwrap();
        assert_eq!(
            sql,
            "SELECT *, COUNT(*) OVER() AS \"__count\" FROM \"public\".\"cities\""
        );
    }

    #[test]
    fn test_invalid_column_name_rejected() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.filters.push(FilterCondition::Comparison {
            column: "name\"; DROP TABLE cities; --".to_string(),
            operator: FilterOperator::Eq,
            param_index: 1,
        });
        assert!(parts.build_sql().is_err());
    }

    // ─── Phase 10: New Feature Tests ─────────────────────────

    #[test]
    fn test_upsert_ignore_duplicates() {
        let mut parts = SqlParts::new(SqlOperation::Upsert, "public", "cities");
        parts.set_clauses = vec![
            ("id".to_string(), 1),
            ("name".to_string(), 2),
        ];
        parts.conflict_columns = vec!["id".to_string()];
        parts.ignore_duplicates = true;
        let sql = parts.build_sql().unwrap();
        assert_eq!(
            sql,
            "INSERT INTO \"public\".\"cities\" (\"id\", \"name\") VALUES ($1, $2) ON CONFLICT (\"id\") DO NOTHING"
        );
    }

    #[test]
    fn test_upsert_ignore_duplicates_no_conflict_cols() {
        let mut parts = SqlParts::new(SqlOperation::Upsert, "public", "cities");
        parts.set_clauses = vec![
            ("id".to_string(), 1),
            ("name".to_string(), 2),
        ];
        parts.ignore_duplicates = true;
        let sql = parts.build_sql().unwrap();
        assert_eq!(
            sql,
            "INSERT INTO \"public\".\"cities\" (\"id\", \"name\") VALUES ($1, $2) ON CONFLICT DO NOTHING"
        );
    }

    #[test]
    fn test_upsert_ignore_duplicates_with_constraint() {
        let mut parts = SqlParts::new(SqlOperation::Upsert, "public", "cities");
        parts.set_clauses = vec![
            ("id".to_string(), 1),
            ("name".to_string(), 2),
        ];
        parts.conflict_constraint = Some("cities_pkey".to_string());
        parts.ignore_duplicates = true;
        let sql = parts.build_sql().unwrap();
        assert_eq!(
            sql,
            "INSERT INTO \"public\".\"cities\" (\"id\", \"name\") VALUES ($1, $2) ON CONFLICT ON CONSTRAINT \"cities_pkey\" DO NOTHING"
        );
    }

    #[test]
    fn test_schema_override_select() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.schema_override = Some("custom_schema".to_string());
        let sql = parts.build_sql().unwrap();
        assert_eq!(sql, "SELECT * FROM \"custom_schema\".\"cities\"");
    }

    #[test]
    fn test_schema_override_insert() {
        let mut parts = SqlParts::new(SqlOperation::Insert, "public", "cities");
        parts.schema_override = Some("myschema".to_string());
        parts.set_clauses = vec![("name".to_string(), 1)];
        let sql = parts.build_sql().unwrap();
        assert_eq!(
            sql,
            "INSERT INTO \"myschema\".\"cities\" (\"name\") VALUES ($1)"
        );
    }

    #[test]
    fn test_schema_override_update() {
        let mut parts = SqlParts::new(SqlOperation::Update, "public", "cities");
        parts.schema_override = Some("myschema".to_string());
        parts.set_clauses = vec![("name".to_string(), 1)];
        let sql = parts.build_sql().unwrap();
        assert_eq!(
            sql,
            "UPDATE \"myschema\".\"cities\" SET \"name\" = $1"
        );
    }

    #[test]
    fn test_schema_override_delete() {
        let mut parts = SqlParts::new(SqlOperation::Delete, "public", "cities");
        parts.schema_override = Some("myschema".to_string());
        parts.filters.push(FilterCondition::Comparison {
            column: "id".to_string(),
            operator: FilterOperator::Eq,
            param_index: 1,
        });
        let sql = parts.build_sql().unwrap();
        assert_eq!(
            sql,
            "DELETE FROM \"myschema\".\"cities\" WHERE \"id\" = $1"
        );
    }

    #[test]
    fn test_schema_override_upsert() {
        let mut parts = SqlParts::new(SqlOperation::Upsert, "public", "cities");
        parts.schema_override = Some("myschema".to_string());
        parts.set_clauses = vec![
            ("id".to_string(), 1),
            ("name".to_string(), 2),
        ];
        parts.conflict_columns = vec!["id".to_string()];
        let sql = parts.build_sql().unwrap();
        assert!(sql.starts_with("INSERT INTO \"myschema\".\"cities\""));
    }

    #[test]
    fn test_explain_default() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.explain = Some(ExplainOptions::default());
        let sql = parts.build_sql().unwrap();
        assert_eq!(
            sql,
            "EXPLAIN (ANALYZE, FORMAT JSON) SELECT * FROM \"public\".\"cities\""
        );
    }

    #[test]
    fn test_explain_with_verbose() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.explain = Some(ExplainOptions {
            analyze: true,
            verbose: true,
            format: ExplainFormat::Text,
        });
        let sql = parts.build_sql().unwrap();
        assert_eq!(
            sql,
            "EXPLAIN (ANALYZE, VERBOSE, FORMAT TEXT) SELECT * FROM \"public\".\"cities\""
        );
    }

    #[test]
    fn test_explain_no_analyze() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.explain = Some(ExplainOptions {
            analyze: false,
            verbose: false,
            format: ExplainFormat::Json,
        });
        let sql = parts.build_sql().unwrap();
        assert_eq!(
            sql,
            "EXPLAIN (FORMAT JSON) SELECT * FROM \"public\".\"cities\""
        );
    }

    #[test]
    fn test_head_mode() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.head = true;
        let sql = parts.build_sql().unwrap();
        assert_eq!(
            sql,
            "SELECT count(*) FROM \"public\".\"cities\""
        );
    }

    #[test]
    fn test_head_mode_with_filters() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.head = true;
        parts.filters.push(FilterCondition::Comparison {
            column: "country".to_string(),
            operator: FilterOperator::Eq,
            param_index: 1,
        });
        let sql = parts.build_sql().unwrap();
        assert_eq!(
            sql,
            "SELECT count(*) FROM \"public\".\"cities\" WHERE \"country\" = $1"
        );
    }

    #[test]
    fn test_head_mode_ignores_columns_and_order() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.head = true;
        parts.select_columns = Some("\"name\"".to_string());
        parts.orders.push(OrderClause {
            column: "name".to_string(),
            direction: OrderDirection::Ascending,
            nulls: None,
        });
        parts.limit = Some(10);
        let sql = parts.build_sql().unwrap();
        // head mode should not include columns, order, or limit
        assert_eq!(
            sql,
            "SELECT count(*) FROM \"public\".\"cities\""
        );
    }

    #[test]
    fn test_schema_override_validation() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.schema_override = Some("bad;schema".to_string());
        assert!(parts.build_sql().is_err());
    }
}
