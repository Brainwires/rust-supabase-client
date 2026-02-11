use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::Value as JsonValue;

use crate::sql::{
    ArrayRangeOperator, CountOption, ExplainOptions, FilterCondition, FilterOperator, IsValue,
    OrderDirection, ParamStore, PatternOperator, SqlParam, SqlParts, TextSearchType,
};

/// Build PostgREST URL and headers for a SELECT query.
pub fn build_postgrest_select(
    base_url: &str,
    parts: &SqlParts,
    params: &ParamStore,
) -> Result<(String, HeaderMap), String> {
    let table = &parts.table;
    let mut url = format!("{}/rest/v1/{}", base_url.trim_end_matches('/'), table);
    let mut headers = HeaderMap::new();
    let mut query_params = Vec::new();

    // Select columns
    if let Some(ref cols) = parts.select_columns {
        // Strip double-quotes from column names for PostgREST
        let cleaned = cols
            .split(',')
            .map(|c| c.trim().trim_matches('"'))
            .collect::<Vec<_>>()
            .join(",");
        query_params.push(format!("select={}", cleaned));
    }

    // Filters
    render_filters_to_params(&parts.filters, params, &mut query_params)?;

    // Order
    if !parts.orders.is_empty() {
        let order_parts: Vec<String> = parts
            .orders
            .iter()
            .map(|o| {
                let dir = match o.direction {
                    OrderDirection::Ascending => "asc",
                    OrderDirection::Descending => "desc",
                };
                let nulls = match &o.nulls {
                    Some(crate::sql::NullsPosition::First) => ".nullsfirst",
                    Some(crate::sql::NullsPosition::Last) => ".nullslast",
                    None => "",
                };
                format!("{}.{}{}", o.column, dir, nulls)
            })
            .collect();
        query_params.push(format!("order={}", order_parts.join(",")));
    }

    // Limit
    if let Some(limit) = parts.limit {
        query_params.push(format!("limit={}", limit));
    }

    // Offset
    if let Some(offset) = parts.offset {
        query_params.push(format!("offset={}", offset));
    }

    // Range header
    if parts.limit.is_some() || parts.offset.is_some() {
        let from = parts.offset.unwrap_or(0);
        let to = match parts.limit {
            Some(limit) => from + limit - 1,
            None => i64::MAX,
        };
        headers.insert(
            "Range",
            HeaderValue::from_str(&format!("{}-{}", from, to)).unwrap(),
        );
        headers.insert("Range-Unit", HeaderValue::from_static("items"));
    }

    // Single row
    if parts.single {
        headers.insert(
            "Accept",
            HeaderValue::from_static("application/vnd.pgrst.object+json"),
        );
    }

    // Prefer header (compose count + head)
    {
        let mut prefer_parts = Vec::new();
        if parts.head {
            // Head mode always implies count=exact
            prefer_parts.push("count=exact".to_string());
        } else if let Some(count_val) = count_option_prefer(parts.count) {
            prefer_parts.push(count_val.to_string());
        }
        if !prefer_parts.is_empty() {
            headers.insert(
                "Prefer",
                HeaderValue::from_str(&prefer_parts.join(",")).unwrap(),
            );
        }
    }

    // Explain
    if let Some(ref opts) = parts.explain {
        headers.insert("Accept", build_explain_accept(opts));
    }

    // Schema override
    if let Some(ref schema) = parts.schema_override {
        headers.insert(
            "Accept-Profile",
            HeaderValue::from_str(schema).unwrap(),
        );
    }

    // Build URL
    if !query_params.is_empty() {
        url.push('?');
        url.push_str(&query_params.join("&"));
    }

    Ok((url, headers))
}

/// Build PostgREST URL, headers, and body for an INSERT query.
pub fn build_postgrest_insert(
    base_url: &str,
    parts: &SqlParts,
    params: &ParamStore,
) -> Result<(String, HeaderMap, JsonValue), String> {
    let table = &parts.table;
    let url = format!("{}/rest/v1/{}", base_url.trim_end_matches('/'), table);
    let mut headers = HeaderMap::new();

    headers.insert("Content-Type", HeaderValue::from_static("application/json"));

    // Prefer header (compose return + count)
    {
        let mut prefer_parts = Vec::new();
        if parts.returning.is_some() {
            prefer_parts.push("return=representation");
        } else {
            prefer_parts.push("return=minimal");
        }
        if let Some(count_val) = count_option_prefer(parts.count) {
            prefer_parts.push(count_val);
        }
        headers.insert(
            "Prefer",
            HeaderValue::from_str(&prefer_parts.join(",")).unwrap(),
        );
    }

    // Schema override
    if let Some(ref schema) = parts.schema_override {
        headers.insert(
            "Content-Profile",
            HeaderValue::from_str(schema).unwrap(),
        );
    }

    // Build body
    let body = build_insert_body(parts, params)?;

    Ok((url, headers, body))
}

/// Build PostgREST URL, headers, and body for an UPDATE query.
pub fn build_postgrest_update(
    base_url: &str,
    parts: &SqlParts,
    params: &ParamStore,
) -> Result<(String, HeaderMap, JsonValue), String> {
    let table = &parts.table;
    let mut url = format!("{}/rest/v1/{}", base_url.trim_end_matches('/'), table);
    let mut headers = HeaderMap::new();
    let mut query_params = Vec::new();

    headers.insert("Content-Type", HeaderValue::from_static("application/json"));

    // Prefer header (compose return + count)
    {
        let mut prefer_parts = Vec::new();
        if parts.returning.is_some() {
            prefer_parts.push("return=representation");
        } else {
            prefer_parts.push("return=minimal");
        }
        if let Some(count_val) = count_option_prefer(parts.count) {
            prefer_parts.push(count_val);
        }
        headers.insert(
            "Prefer",
            HeaderValue::from_str(&prefer_parts.join(",")).unwrap(),
        );
    }

    // Schema override
    if let Some(ref schema) = parts.schema_override {
        headers.insert(
            "Content-Profile",
            HeaderValue::from_str(schema).unwrap(),
        );
    }

    // Filters
    render_filters_to_params(&parts.filters, params, &mut query_params)?;

    if !query_params.is_empty() {
        url.push('?');
        url.push_str(&query_params.join("&"));
    }

    // Build SET body
    let body = build_set_body(&parts.set_clauses, params)?;

    Ok((url, headers, body))
}

/// Build PostgREST URL and headers for a DELETE query.
pub fn build_postgrest_delete(
    base_url: &str,
    parts: &SqlParts,
    params: &ParamStore,
) -> Result<(String, HeaderMap), String> {
    let table = &parts.table;
    let mut url = format!("{}/rest/v1/{}", base_url.trim_end_matches('/'), table);
    let mut headers = HeaderMap::new();
    let mut query_params = Vec::new();

    // Prefer header (compose return + count)
    {
        let mut prefer_parts = Vec::new();
        if parts.returning.is_some() {
            prefer_parts.push("return=representation");
        } else {
            prefer_parts.push("return=minimal");
        }
        if let Some(count_val) = count_option_prefer(parts.count) {
            prefer_parts.push(count_val);
        }
        headers.insert(
            "Prefer",
            HeaderValue::from_str(&prefer_parts.join(",")).unwrap(),
        );
    }

    // Schema override
    if let Some(ref schema) = parts.schema_override {
        headers.insert(
            "Content-Profile",
            HeaderValue::from_str(schema).unwrap(),
        );
    }

    // Filters
    render_filters_to_params(&parts.filters, params, &mut query_params)?;

    if !query_params.is_empty() {
        url.push('?');
        url.push_str(&query_params.join("&"));
    }

    Ok((url, headers))
}

/// Build PostgREST URL, headers, and body for an UPSERT query.
pub fn build_postgrest_upsert(
    base_url: &str,
    parts: &SqlParts,
    params: &ParamStore,
) -> Result<(String, HeaderMap, JsonValue), String> {
    let table = &parts.table;
    let mut url = format!("{}/rest/v1/{}", base_url.trim_end_matches('/'), table);
    let mut headers = HeaderMap::new();

    headers.insert("Content-Type", HeaderValue::from_static("application/json"));

    // Upsert resolution preference (compose resolution + return + count)
    let mut prefer_parts: Vec<&str> = Vec::new();

    if parts.ignore_duplicates {
        prefer_parts.push("resolution=ignore-duplicates");
    } else {
        prefer_parts.push("resolution=merge-duplicates");
    }

    if parts.returning.is_some() {
        prefer_parts.push("return=representation");
    } else {
        prefer_parts.push("return=minimal");
    }

    // We need to handle count separately since count_option_prefer returns &'static str
    let count_str = count_option_prefer(parts.count);
    if let Some(cv) = count_str {
        prefer_parts.push(cv);
    }

    headers.insert(
        "Prefer",
        HeaderValue::from_str(&prefer_parts.join(",")).unwrap(),
    );

    // Conflict columns as on_conflict query param
    if !parts.conflict_columns.is_empty() {
        let conflict = parts.conflict_columns.join(",");
        url.push_str(&format!(
            "{}on_conflict={}",
            if url.contains('?') { "&" } else { "?" },
            conflict
        ));
    }

    // Schema override
    if let Some(ref schema) = parts.schema_override {
        headers.insert(
            "Content-Profile",
            HeaderValue::from_str(schema).unwrap(),
        );
    }

    // Build body (same as insert)
    let body = build_insert_body(parts, params)?;

    Ok((url, headers, body))
}

/// Build PostgREST URL and headers for an RPC call.
pub fn build_postgrest_rpc(
    base_url: &str,
    function: &str,
    args: &JsonValue,
    rollback: bool,
) -> (String, HeaderMap, JsonValue) {
    let url = format!("{}/rest/v1/rpc/{}", base_url.trim_end_matches('/'), function);
    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", HeaderValue::from_static("application/json"));

    if rollback {
        headers.insert("Prefer", HeaderValue::from_static("tx=rollback"));
    }

    let body = if args.is_null() {
        JsonValue::Object(serde_json::Map::new())
    } else {
        args.clone()
    };

    (url, headers, body)
}

// ─── Internal Helpers ──────────────────────────────────────

/// Convert a CountOption to its PostgREST Prefer header value.
fn count_option_prefer(option: CountOption) -> Option<&'static str> {
    match option {
        CountOption::None => None,
        CountOption::Exact => Some("count=exact"),
        CountOption::Planned => Some("count=planned"),
        CountOption::Estimated => Some("count=estimated"),
    }
}

/// Render a SqlParam value as a PostgREST string.
pub fn render_param_value(param: &SqlParam) -> String {
    match param {
        SqlParam::Null => "null".to_string(),
        SqlParam::Bool(b) => b.to_string(),
        SqlParam::I16(n) => n.to_string(),
        SqlParam::I32(n) => n.to_string(),
        SqlParam::I64(n) => n.to_string(),
        SqlParam::F32(n) => n.to_string(),
        SqlParam::F64(n) => n.to_string(),
        SqlParam::Text(s) => s.clone(),
        SqlParam::Uuid(u) => u.to_string(),
        SqlParam::Timestamp(t) => t.to_string(),
        SqlParam::TimestampTz(t) => t.to_rfc3339(),
        SqlParam::Date(d) => d.to_string(),
        SqlParam::Time(t) => t.to_string(),
        SqlParam::Json(v) => v.to_string(),
        SqlParam::ByteArray(b) => format!("\\x{}", hex_encode(b)),
        SqlParam::TextArray(arr) => format!("{{{}}}", arr.iter().map(|s| format!("\"{}\"", s)).collect::<Vec<_>>().join(",")),
        SqlParam::I32Array(arr) => format!("{{{}}}", arr.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(",")),
        SqlParam::I64Array(arr) => format!("{{{}}}", arr.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(",")),
    }
}

/// Render a SqlParam value as a JSON value (for request bodies).
fn param_to_json(param: &SqlParam) -> JsonValue {
    match param {
        SqlParam::Null => JsonValue::Null,
        SqlParam::Bool(b) => JsonValue::Bool(*b),
        SqlParam::I16(n) => JsonValue::Number((*n as i64).into()),
        SqlParam::I32(n) => JsonValue::Number((*n as i64).into()),
        SqlParam::I64(n) => JsonValue::Number((*n).into()),
        SqlParam::F32(n) => serde_json::Number::from_f64(*n as f64)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        SqlParam::F64(n) => serde_json::Number::from_f64(*n)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        SqlParam::Text(s) => JsonValue::String(s.clone()),
        SqlParam::Uuid(u) => JsonValue::String(u.to_string()),
        SqlParam::Timestamp(t) => JsonValue::String(t.to_string()),
        SqlParam::TimestampTz(t) => JsonValue::String(t.to_rfc3339()),
        SqlParam::Date(d) => JsonValue::String(d.to_string()),
        SqlParam::Time(t) => JsonValue::String(t.to_string()),
        SqlParam::Json(v) => v.clone(),
        SqlParam::ByteArray(b) => JsonValue::String(format!("\\x{}", hex_encode(b))),
        SqlParam::TextArray(arr) => JsonValue::Array(arr.iter().map(|s| JsonValue::String(s.clone())).collect()),
        SqlParam::I32Array(arr) => JsonValue::Array(arr.iter().map(|n| JsonValue::Number((*n as i64).into())).collect()),
        SqlParam::I64Array(arr) => JsonValue::Array(arr.iter().map(|n| JsonValue::Number((*n).into())).collect()),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Render a single filter condition as PostgREST query parameter(s).
fn render_filter(
    condition: &FilterCondition,
    params: &ParamStore,
    output: &mut Vec<String>,
) -> Result<(), String> {
    match condition {
        FilterCondition::Comparison { column, operator, param_index } => {
            let op = match operator {
                FilterOperator::Eq => "eq",
                FilterOperator::Neq => "neq",
                FilterOperator::Gt => "gt",
                FilterOperator::Gte => "gte",
                FilterOperator::Lt => "lt",
                FilterOperator::Lte => "lte",
            };
            let param = params.get(*param_index - 1)
                .ok_or_else(|| format!("Missing param at index {}", param_index))?;
            let val = render_param_value(param);
            output.push(format!("{}={}.{}", column, op, val));
        }
        FilterCondition::Is { column, value } => {
            let val = match value {
                IsValue::Null => "null",
                IsValue::NotNull => "not.null",  // not.is.null would be more accurate
                IsValue::True => "true",
                IsValue::False => "false",
            };
            output.push(format!("{}=is.{}", column, val));
        }
        FilterCondition::In { column, param_indices } => {
            let vals: Result<Vec<String>, String> = param_indices
                .iter()
                .map(|idx| {
                    let param = params.get(*idx - 1)
                        .ok_or_else(|| format!("Missing param at index {}", idx))?;
                    Ok(render_param_value(param))
                })
                .collect();
            let val_list = vals?.join(",");
            output.push(format!("{}=in.({})", column, val_list));
        }
        FilterCondition::Pattern { column, operator, param_index } => {
            let op = match operator {
                PatternOperator::Like => "like",
                PatternOperator::ILike => "ilike",
            };
            let param = params.get(*param_index - 1)
                .ok_or_else(|| format!("Missing param at index {}", param_index))?;
            let val = render_param_value(param);
            output.push(format!("{}={}.{}", column, op, val));
        }
        FilterCondition::TextSearch { column, query_param_index, config, search_type } => {
            let op = match search_type {
                TextSearchType::Plain => "plfts",
                TextSearchType::Phrase => "phfts",
                TextSearchType::Websearch => "wfts",
            };
            let param = params.get(*query_param_index - 1)
                .ok_or_else(|| format!("Missing param at index {}", query_param_index))?;
            let val = render_param_value(param);
            if let Some(cfg) = config {
                output.push(format!("{}={}({}).{}", column, op, cfg, val));
            } else {
                output.push(format!("{}={}.{}", column, op, val));
            }
        }
        FilterCondition::ArrayRange { column, operator, param_index } => {
            let op = match operator {
                ArrayRangeOperator::Contains => "cs",
                ArrayRangeOperator::ContainedBy => "cd",
                ArrayRangeOperator::Overlaps => "ov",
                ArrayRangeOperator::RangeGt => "sl",   // strictly left → right of
                ArrayRangeOperator::RangeGte => "nxl",
                ArrayRangeOperator::RangeLt => "sr",    // strictly right → left of
                ArrayRangeOperator::RangeLte => "nxr",
                ArrayRangeOperator::RangeAdjacent => "adj",
            };
            let param = params.get(*param_index - 1)
                .ok_or_else(|| format!("Missing param at index {}", param_index))?;
            let val = render_param_value(param);
            output.push(format!("{}={}.{}", column, op, val));
        }
        FilterCondition::Not(inner) => {
            // Render inner, then prefix with not.
            let mut inner_params = Vec::new();
            render_filter(inner, params, &mut inner_params)?;
            for p in inner_params {
                if let Some(eq_pos) = p.find('=') {
                    let col = &p[..eq_pos];
                    let rest = &p[eq_pos + 1..];
                    output.push(format!("{}=not.{}", col, rest));
                }
            }
        }
        FilterCondition::Or(conditions) => {
            let mut inner_parts = Vec::new();
            for cond in conditions {
                let mut sub = Vec::new();
                render_filter(cond, params, &mut sub)?;
                inner_parts.extend(sub);
            }
            // PostgREST or syntax: or=(filter1,filter2)
            let or_items: Vec<String> = inner_parts
                .iter()
                .map(|p| {
                    // Convert "col=op.val" to "col.op.val"
                    if let Some(eq_pos) = p.find('=') {
                        let col = &p[..eq_pos];
                        let rest = &p[eq_pos + 1..];
                        format!("{}.{}", col, rest)
                    } else {
                        p.clone()
                    }
                })
                .collect();
            output.push(format!("or=({})", or_items.join(",")));
        }
        FilterCondition::And(conditions) => {
            let mut inner_parts = Vec::new();
            for cond in conditions {
                let mut sub = Vec::new();
                render_filter(cond, params, &mut sub)?;
                inner_parts.extend(sub);
            }
            let and_items: Vec<String> = inner_parts
                .iter()
                .map(|p| {
                    if let Some(eq_pos) = p.find('=') {
                        let col = &p[..eq_pos];
                        let rest = &p[eq_pos + 1..];
                        format!("{}.{}", col, rest)
                    } else {
                        p.clone()
                    }
                })
                .collect();
            output.push(format!("and=({})", and_items.join(",")));
        }
        FilterCondition::Raw(sql) => {
            // Raw SQL cannot be directly translated to PostgREST
            return Err(format!("Raw SQL filter '{}' cannot be used with PostgREST backend", sql));
        }
        FilterCondition::Match { conditions } => {
            for (col, idx) in conditions {
                let param = params.get(*idx - 1)
                    .ok_or_else(|| format!("Missing param at index {}", idx))?;
                let val = render_param_value(param);
                output.push(format!("{}=eq.{}", col, val));
            }
        }
    }
    Ok(())
}

fn render_filters_to_params(
    filters: &[FilterCondition],
    params: &ParamStore,
    output: &mut Vec<String>,
) -> Result<(), String> {
    for filter in filters {
        render_filter(filter, params, output)?;
    }
    Ok(())
}

/// Build the insert/upsert JSON body from SqlParts.
fn build_insert_body(parts: &SqlParts, params: &ParamStore) -> Result<JsonValue, String> {
    if parts.many_rows.is_empty() {
        // Single row from set_clauses
        let mut obj = serde_json::Map::new();
        for (col, idx) in &parts.set_clauses {
            let param = params.get(*idx - 1)
                .ok_or_else(|| format!("Missing param at index {}", idx))?;
            obj.insert(col.clone(), param_to_json(param));
        }
        Ok(JsonValue::Object(obj))
    } else {
        // Multiple rows
        let rows: Result<Vec<JsonValue>, String> = parts.many_rows.iter().map(|row| {
            let mut obj = serde_json::Map::new();
            for (col, idx) in row {
                let param = params.get(*idx - 1)
                    .ok_or_else(|| format!("Missing param at index {}", idx))?;
                obj.insert(col.clone(), param_to_json(param));
            }
            Ok(JsonValue::Object(obj))
        }).collect();
        Ok(JsonValue::Array(rows?))
    }
}

/// Build the SET body for UPDATE operations.
fn build_set_body(set_clauses: &[(String, usize)], params: &ParamStore) -> Result<JsonValue, String> {
    let mut obj = serde_json::Map::new();
    for (col, idx) in set_clauses {
        let param = params.get(*idx - 1)
            .ok_or_else(|| format!("Missing param at index {}", idx))?;
        obj.insert(col.clone(), param_to_json(param));
    }
    Ok(JsonValue::Object(obj))
}

fn build_explain_accept(opts: &ExplainOptions) -> HeaderValue {
    let mut parts = vec!["application/vnd.pgrst.plan"];
    if opts.analyze {
        parts.push("+json; for=\"application/vnd.pgrst.plan+analyze\"");
    }
    // Simplify: PostgREST uses Accept header for plan format
    HeaderValue::from_static("application/vnd.pgrst.plan+json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql::*;

    fn make_params(values: Vec<SqlParam>) -> ParamStore {
        let mut store = ParamStore::new();
        for v in values {
            store.push(v);
        }
        store
    }

    // ─── SELECT Tests ───────────────────────────────────────

    #[test]
    fn test_select_simple() {
        let parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        let params = ParamStore::new();
        let (url, _headers) = build_postgrest_select("http://localhost:64321", &parts, &params).unwrap();
        assert_eq!(url, "http://localhost:64321/rest/v1/cities");
    }

    #[test]
    fn test_select_with_columns() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.select_columns = Some("\"name\", \"country_id\"".to_string());
        let params = ParamStore::new();
        let (url, _) = build_postgrest_select("http://localhost:64321", &parts, &params).unwrap();
        assert_eq!(url, "http://localhost:64321/rest/v1/cities?select=name,country_id");
    }

    #[test]
    fn test_select_with_eq_filter() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.filters.push(FilterCondition::Comparison {
            column: "name".to_string(),
            operator: FilterOperator::Eq,
            param_index: 1,
        });
        let params = make_params(vec![SqlParam::Text("Auckland".to_string())]);
        let (url, _) = build_postgrest_select("http://localhost:64321", &parts, &params).unwrap();
        assert_eq!(url, "http://localhost:64321/rest/v1/cities?name=eq.Auckland");
    }

    #[test]
    fn test_select_with_multiple_filters() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.filters.push(FilterCondition::Comparison {
            column: "country_id".to_string(),
            operator: FilterOperator::Eq,
            param_index: 1,
        });
        parts.filters.push(FilterCondition::Comparison {
            column: "population".to_string(),
            operator: FilterOperator::Gt,
            param_index: 2,
        });
        let params = make_params(vec![SqlParam::I32(1), SqlParam::I64(100000)]);
        let (url, _) = build_postgrest_select("http://localhost:64321", &parts, &params).unwrap();
        assert!(url.contains("country_id=eq.1"));
        assert!(url.contains("population=gt.100000"));
    }

    #[test]
    fn test_select_with_order() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.orders.push(OrderClause {
            column: "name".to_string(),
            direction: OrderDirection::Ascending,
            nulls: None,
        });
        let params = ParamStore::new();
        let (url, _) = build_postgrest_select("http://localhost:64321", &parts, &params).unwrap();
        assert_eq!(url, "http://localhost:64321/rest/v1/cities?order=name.asc");
    }

    #[test]
    fn test_select_with_order_nulls() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.orders.push(OrderClause {
            column: "name".to_string(),
            direction: OrderDirection::Descending,
            nulls: Some(NullsPosition::Last),
        });
        let params = ParamStore::new();
        let (url, _) = build_postgrest_select("http://localhost:64321", &parts, &params).unwrap();
        assert!(url.contains("order=name.desc.nullslast"));
    }

    #[test]
    fn test_select_with_limit() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.limit = Some(10);
        let params = ParamStore::new();
        let (url, headers) = build_postgrest_select("http://localhost:64321", &parts, &params).unwrap();
        assert!(url.contains("limit=10"));
        assert!(headers.contains_key("Range"));
    }

    #[test]
    fn test_select_with_limit_offset() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.limit = Some(10);
        parts.offset = Some(5);
        let params = ParamStore::new();
        let (url, headers) = build_postgrest_select("http://localhost:64321", &parts, &params).unwrap();
        assert!(url.contains("limit=10"));
        assert!(url.contains("offset=5"));
        assert_eq!(headers.get("Range").unwrap(), "5-14");
    }

    #[test]
    fn test_select_single() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.single = true;
        let params = ParamStore::new();
        let (_, headers) = build_postgrest_select("http://localhost:64321", &parts, &params).unwrap();
        assert_eq!(
            headers.get("Accept").unwrap(),
            "application/vnd.pgrst.object+json"
        );
    }

    #[test]
    fn test_select_count() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.count = CountOption::Exact;
        let params = ParamStore::new();
        let (_, headers) = build_postgrest_select("http://localhost:64321", &parts, &params).unwrap();
        assert_eq!(headers.get("Prefer").unwrap(), "count=exact");
    }

    #[test]
    fn test_select_head_mode() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.head = true;
        let params = ParamStore::new();
        let (_, headers) = build_postgrest_select("http://localhost:64321", &parts, &params).unwrap();
        assert_eq!(headers.get("Prefer").unwrap(), "count=exact");
    }

    // ─── Filter Tests ───────────────────────────────────────

    #[test]
    fn test_filter_is_null() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.filters.push(FilterCondition::Is {
            column: "deleted_at".to_string(),
            value: IsValue::Null,
        });
        let params = ParamStore::new();
        let (url, _) = build_postgrest_select("http://localhost:64321", &parts, &params).unwrap();
        assert!(url.contains("deleted_at=is.null"));
    }

    #[test]
    fn test_filter_in() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.filters.push(FilterCondition::In {
            column: "id".to_string(),
            param_indices: vec![1, 2, 3],
        });
        let params = make_params(vec![
            SqlParam::I32(1),
            SqlParam::I32(2),
            SqlParam::I32(3),
        ]);
        let (url, _) = build_postgrest_select("http://localhost:64321", &parts, &params).unwrap();
        assert!(url.contains("id=in.(1,2,3)"));
    }

    #[test]
    fn test_filter_like() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.filters.push(FilterCondition::Pattern {
            column: "name".to_string(),
            operator: PatternOperator::Like,
            param_index: 1,
        });
        let params = make_params(vec![SqlParam::Text("%auck%".to_string())]);
        let (url, _) = build_postgrest_select("http://localhost:64321", &parts, &params).unwrap();
        assert!(url.contains("name=like.%auck%"));
    }

    #[test]
    fn test_filter_ilike() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.filters.push(FilterCondition::Pattern {
            column: "name".to_string(),
            operator: PatternOperator::ILike,
            param_index: 1,
        });
        let params = make_params(vec![SqlParam::Text("%auck%".to_string())]);
        let (url, _) = build_postgrest_select("http://localhost:64321", &parts, &params).unwrap();
        assert!(url.contains("name=ilike.%auck%"));
    }

    #[test]
    fn test_filter_text_search() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.filters.push(FilterCondition::TextSearch {
            column: "fts".to_string(),
            query_param_index: 1,
            config: Some("english".to_string()),
            search_type: TextSearchType::Plain,
        });
        let params = make_params(vec![SqlParam::Text("hello".to_string())]);
        let (url, _) = build_postgrest_select("http://localhost:64321", &parts, &params).unwrap();
        assert!(url.contains("fts=plfts(english).hello"));
    }

    #[test]
    fn test_filter_contains() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.filters.push(FilterCondition::ArrayRange {
            column: "tags".to_string(),
            operator: ArrayRangeOperator::Contains,
            param_index: 1,
        });
        let params = make_params(vec![SqlParam::TextArray(vec!["a".to_string(), "b".to_string()])]);
        let (url, _) = build_postgrest_select("http://localhost:64321", &parts, &params).unwrap();
        assert!(url.contains("tags=cs.{\"a\",\"b\"}"));
    }

    #[test]
    fn test_filter_not() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.filters.push(FilterCondition::Not(Box::new(
            FilterCondition::Comparison {
                column: "active".to_string(),
                operator: FilterOperator::Eq,
                param_index: 1,
            },
        )));
        let params = make_params(vec![SqlParam::Bool(true)]);
        let (url, _) = build_postgrest_select("http://localhost:64321", &parts, &params).unwrap();
        assert!(url.contains("active=not.eq.true"));
    }

    #[test]
    fn test_filter_or() {
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
        let params = make_params(vec![
            SqlParam::Text("Auckland".to_string()),
            SqlParam::Text("Wellington".to_string()),
        ]);
        let (url, _) = build_postgrest_select("http://localhost:64321", &parts, &params).unwrap();
        assert!(url.contains("or=(name.eq.Auckland,name.eq.Wellington)"));
    }

    #[test]
    fn test_filter_match() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.filters.push(FilterCondition::Match {
            conditions: vec![
                ("name".to_string(), 1),
                ("country_id".to_string(), 2),
            ],
        });
        let params = make_params(vec![
            SqlParam::Text("Auckland".to_string()),
            SqlParam::I32(1),
        ]);
        let (url, _) = build_postgrest_select("http://localhost:64321", &parts, &params).unwrap();
        assert!(url.contains("name=eq.Auckland"));
        assert!(url.contains("country_id=eq.1"));
    }

    #[test]
    fn test_raw_filter_errors() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.filters.push(FilterCondition::Raw("1=1".to_string()));
        let params = ParamStore::new();
        let result = build_postgrest_select("http://localhost:64321", &parts, &params);
        assert!(result.is_err());
    }

    // ─── INSERT Tests ───────────────────────────────────────

    #[test]
    fn test_insert_single() {
        let mut parts = SqlParts::new(SqlOperation::Insert, "public", "cities");
        parts.set_clauses = vec![
            ("name".to_string(), 1),
            ("country_id".to_string(), 2),
        ];
        parts.returning = Some("*".to_string());
        let params = make_params(vec![
            SqlParam::Text("Auckland".to_string()),
            SqlParam::I32(1),
        ]);
        let (url, headers, body) = build_postgrest_insert("http://localhost:64321", &parts, &params).unwrap();
        assert_eq!(url, "http://localhost:64321/rest/v1/cities");
        assert_eq!(headers.get("Prefer").unwrap(), "return=representation");
        assert_eq!(body["name"], "Auckland");
        assert_eq!(body["country_id"], 1);
    }

    #[test]
    fn test_insert_many() {
        let mut parts = SqlParts::new(SqlOperation::Insert, "public", "cities");
        parts.many_rows = vec![
            vec![("name".to_string(), 1), ("country_id".to_string(), 2)],
            vec![("name".to_string(), 3), ("country_id".to_string(), 4)],
        ];
        let params = make_params(vec![
            SqlParam::Text("Auckland".to_string()),
            SqlParam::I32(1),
            SqlParam::Text("Wellington".to_string()),
            SqlParam::I32(1),
        ]);
        let (_, _, body) = build_postgrest_insert("http://localhost:64321", &parts, &params).unwrap();
        assert!(body.is_array());
        assert_eq!(body.as_array().unwrap().len(), 2);
    }

    // ─── UPDATE Tests ───────────────────────────────────────

    #[test]
    fn test_update_with_filter() {
        let mut parts = SqlParts::new(SqlOperation::Update, "public", "cities");
        parts.set_clauses = vec![("name".to_string(), 1)];
        parts.filters.push(FilterCondition::Comparison {
            column: "id".to_string(),
            operator: FilterOperator::Eq,
            param_index: 2,
        });
        parts.returning = Some("*".to_string());
        let params = make_params(vec![
            SqlParam::Text("New Auckland".to_string()),
            SqlParam::I32(1),
        ]);
        let (url, headers, body) = build_postgrest_update("http://localhost:64321", &parts, &params).unwrap();
        assert!(url.contains("id=eq.1"));
        assert_eq!(headers.get("Prefer").unwrap(), "return=representation");
        assert_eq!(body["name"], "New Auckland");
    }

    // ─── DELETE Tests ───────────────────────────────────────

    #[test]
    fn test_delete_with_filter() {
        let mut parts = SqlParts::new(SqlOperation::Delete, "public", "cities");
        parts.filters.push(FilterCondition::Comparison {
            column: "id".to_string(),
            operator: FilterOperator::Eq,
            param_index: 1,
        });
        parts.returning = Some("*".to_string());
        let params = make_params(vec![SqlParam::I32(1)]);
        let (url, headers) = build_postgrest_delete("http://localhost:64321", &parts, &params).unwrap();
        assert!(url.contains("id=eq.1"));
        assert_eq!(headers.get("Prefer").unwrap(), "return=representation");
    }

    // ─── UPSERT Tests ───────────────────────────────────────

    #[test]
    fn test_upsert_merge_duplicates() {
        let mut parts = SqlParts::new(SqlOperation::Upsert, "public", "cities");
        parts.set_clauses = vec![
            ("id".to_string(), 1),
            ("name".to_string(), 2),
        ];
        parts.conflict_columns = vec!["id".to_string()];
        parts.returning = Some("*".to_string());
        let params = make_params(vec![SqlParam::I32(1), SqlParam::Text("Auckland".to_string())]);
        let (url, headers, _) = build_postgrest_upsert("http://localhost:64321", &parts, &params).unwrap();
        assert!(url.contains("on_conflict=id"));
        let prefer = headers.get("Prefer").unwrap().to_str().unwrap();
        assert!(prefer.contains("resolution=merge-duplicates"));
        assert!(prefer.contains("return=representation"));
    }

    #[test]
    fn test_upsert_ignore_duplicates() {
        let mut parts = SqlParts::new(SqlOperation::Upsert, "public", "cities");
        parts.set_clauses = vec![
            ("id".to_string(), 1),
            ("name".to_string(), 2),
        ];
        parts.conflict_columns = vec!["id".to_string()];
        parts.ignore_duplicates = true;
        let params = make_params(vec![SqlParam::I32(1), SqlParam::Text("Auckland".to_string())]);
        let (_, headers, _) = build_postgrest_upsert("http://localhost:64321", &parts, &params).unwrap();
        let prefer = headers.get("Prefer").unwrap().to_str().unwrap();
        assert!(prefer.contains("resolution=ignore-duplicates"));
    }

    // ─── RPC Tests ──────────────────────────────────────────

    #[test]
    fn test_rpc_simple() {
        let args = serde_json::json!({"name": "Auckland"});
        let (url, headers, body) = build_postgrest_rpc("http://localhost:64321", "get_city", &args, false);
        assert_eq!(url, "http://localhost:64321/rest/v1/rpc/get_city");
        assert_eq!(headers.get("Content-Type").unwrap(), "application/json");
        assert_eq!(body["name"], "Auckland");
    }

    #[test]
    fn test_rpc_no_args() {
        let args = serde_json::json!(null);
        let (_, _, body) = build_postgrest_rpc("http://localhost:64321", "get_all", &args, false);
        assert!(body.is_object());
        assert!(body.as_object().unwrap().is_empty());
    }

    #[test]
    fn test_rpc_rollback() {
        let args = serde_json::json!({"name": "Auckland"});
        let (_, headers, _) = build_postgrest_rpc("http://localhost:64321", "get_city", &args, true);
        assert_eq!(headers.get("Prefer").unwrap(), "tx=rollback");
    }

    #[test]
    fn test_rpc_no_rollback_no_prefer() {
        let args = serde_json::json!({"name": "Auckland"});
        let (_, headers, _) = build_postgrest_rpc("http://localhost:64321", "get_city", &args, false);
        assert!(headers.get("Prefer").is_none());
    }

    // ─── Param Value Rendering ──────────────────────────────

    #[test]
    fn test_render_param_null() {
        assert_eq!(render_param_value(&SqlParam::Null), "null");
    }

    #[test]
    fn test_render_param_bool() {
        assert_eq!(render_param_value(&SqlParam::Bool(true)), "true");
        assert_eq!(render_param_value(&SqlParam::Bool(false)), "false");
    }

    #[test]
    fn test_render_param_numbers() {
        assert_eq!(render_param_value(&SqlParam::I32(42)), "42");
        assert_eq!(render_param_value(&SqlParam::I64(1000000)), "1000000");
        assert_eq!(render_param_value(&SqlParam::F64(3.14)), "3.14");
    }

    #[test]
    fn test_render_param_text() {
        assert_eq!(render_param_value(&SqlParam::Text("hello".to_string())), "hello");
    }

    #[test]
    fn test_render_param_uuid() {
        let uuid = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(
            render_param_value(&SqlParam::Uuid(uuid)),
            "550e8400-e29b-41d4-a716-446655440000"
        );
    }

    // ─── CountOption Tests ──────────────────────────────────

    #[test]
    fn test_select_count_planned() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.count = CountOption::Planned;
        let params = ParamStore::new();
        let (_, headers) = build_postgrest_select("http://localhost:64321", &parts, &params).unwrap();
        assert_eq!(headers.get("Prefer").unwrap(), "count=planned");
    }

    #[test]
    fn test_select_count_estimated() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.count = CountOption::Estimated;
        let params = ParamStore::new();
        let (_, headers) = build_postgrest_select("http://localhost:64321", &parts, &params).unwrap();
        assert_eq!(headers.get("Prefer").unwrap(), "count=estimated");
    }

    #[test]
    fn test_select_count_and_head_compose() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.count = CountOption::Exact;
        parts.head = true;
        let params = ParamStore::new();
        let (_, headers) = build_postgrest_select("http://localhost:64321", &parts, &params).unwrap();
        // Head mode forces count=exact
        let prefer = headers.get("Prefer").unwrap().to_str().unwrap();
        assert!(prefer.contains("count=exact"));
    }

    #[test]
    fn test_insert_return_and_count_compose() {
        let mut parts = SqlParts::new(SqlOperation::Insert, "public", "cities");
        parts.set_clauses = vec![("name".to_string(), 1)];
        parts.returning = Some("*".to_string());
        parts.count = CountOption::Exact;
        let params = make_params(vec![SqlParam::Text("Auckland".to_string())]);
        let (_, headers, _) = build_postgrest_insert("http://localhost:64321", &parts, &params).unwrap();
        let prefer = headers.get("Prefer").unwrap().to_str().unwrap();
        assert!(prefer.contains("return=representation"));
        assert!(prefer.contains("count=exact"));
    }

    #[test]
    fn test_update_return_and_count_compose() {
        let mut parts = SqlParts::new(SqlOperation::Update, "public", "cities");
        parts.set_clauses = vec![("name".to_string(), 1)];
        parts.returning = Some("*".to_string());
        parts.count = CountOption::Planned;
        let params = make_params(vec![SqlParam::Text("Auckland".to_string())]);
        let (_, headers, _) = build_postgrest_update("http://localhost:64321", &parts, &params).unwrap();
        let prefer = headers.get("Prefer").unwrap().to_str().unwrap();
        assert!(prefer.contains("return=representation"));
        assert!(prefer.contains("count=planned"));
    }

    #[test]
    fn test_delete_return_and_count_compose() {
        let mut parts = SqlParts::new(SqlOperation::Delete, "public", "cities");
        parts.returning = Some("*".to_string());
        parts.count = CountOption::Estimated;
        let params = ParamStore::new();
        let (_, headers) = build_postgrest_delete("http://localhost:64321", &parts, &params).unwrap();
        let prefer = headers.get("Prefer").unwrap().to_str().unwrap();
        assert!(prefer.contains("return=representation"));
        assert!(prefer.contains("count=estimated"));
    }

    #[test]
    fn test_upsert_with_count() {
        let mut parts = SqlParts::new(SqlOperation::Upsert, "public", "cities");
        parts.set_clauses = vec![("id".to_string(), 1), ("name".to_string(), 2)];
        parts.conflict_columns = vec!["id".to_string()];
        parts.returning = Some("*".to_string());
        parts.count = CountOption::Exact;
        let params = make_params(vec![SqlParam::I32(1), SqlParam::Text("Auckland".to_string())]);
        let (_, headers, _) = build_postgrest_upsert("http://localhost:64321", &parts, &params).unwrap();
        let prefer = headers.get("Prefer").unwrap().to_str().unwrap();
        assert!(prefer.contains("resolution=merge-duplicates"));
        assert!(prefer.contains("return=representation"));
        assert!(prefer.contains("count=exact"));
    }

    #[test]
    fn test_schema_override_select() {
        let mut parts = SqlParts::new(SqlOperation::Select, "public", "cities");
        parts.schema_override = Some("custom".to_string());
        let params = ParamStore::new();
        let (_, headers) = build_postgrest_select("http://localhost:64321", &parts, &params).unwrap();
        assert_eq!(headers.get("Accept-Profile").unwrap(), "custom");
    }

    #[test]
    fn test_schema_override_insert() {
        let mut parts = SqlParts::new(SqlOperation::Insert, "public", "cities");
        parts.schema_override = Some("custom".to_string());
        parts.set_clauses = vec![("name".to_string(), 1)];
        let params = make_params(vec![SqlParam::Text("Auckland".to_string())]);
        let (_, headers, _) = build_postgrest_insert("http://localhost:64321", &parts, &params).unwrap();
        assert_eq!(headers.get("Content-Profile").unwrap(), "custom");
    }
}
