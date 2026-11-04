//! Internal module for rendering GraphQL query strings from builder state.
//!
//! Converts `serde_json::Value` trees into GraphQL literal syntax and
//! assembles complete query/mutation documents.
//!
//! Everything that ends up in the document outside a string literal (the
//! collection name, selected fields, object keys, filter columns, orderBy
//! columns) must be a GraphQL `Name` (`[_A-Za-z][_0-9A-Za-z]*`); anything else
//! is rejected with [`GraphqlError::InvalidInput`], so user-controlled keys
//! cannot inject extra arguments or operations. Every JSON string is rendered
//! as a quoted, escaped string; enum values (`orderBy` directions and the
//! `is` filter) come only from the typed [`OrderByDirection`] and
//! [`IsValue`] enums.
//!
//! [`OrderByDirection`]: crate::order::OrderByDirection
//! [`IsValue`]: crate::filter::IsValue

use serde_json::Value;
use std::fmt::Write;

use crate::error::GraphqlError;
use crate::filter::GqlFilter;
use crate::order::OrderByEntry;

/// Whether `name` is a valid GraphQL `Name`: `^[_A-Za-z][_0-9A-Za-z]*$`.
pub(crate) fn is_graphql_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// Return `name` if it is a valid GraphQL `Name`, otherwise an
/// [`GraphqlError::InvalidInput`] naming `what` it was used as.
pub(crate) fn validate_name<'a>(name: &'a str, what: &str) -> Result<&'a str, GraphqlError> {
    if is_graphql_name(name) {
        Ok(name)
    } else {
        Err(GraphqlError::InvalidInput(format!(
            "invalid GraphQL {what} {name:?}: must match [_A-Za-z][_0-9A-Za-z]*"
        )))
    }
}

/// Convert a `serde_json::Value` into a GraphQL literal string.
///
/// - Strings are always rendered quoted and escaped (never as enum values).
/// - Numbers, booleans, null are rendered as-is.
/// - Arrays become `[elem1, elem2, ...]`.
/// - Objects become `{key1: value1, key2: value2}`; every key must be a
///   valid GraphQL name.
pub(crate) fn value_to_graphql_literal(value: &Value) -> Result<String, GraphqlError> {
    Ok(match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => quote_graphql_string(s),
        Value::Array(arr) => {
            let items = arr
                .iter()
                .map(value_to_graphql_literal)
                .collect::<Result<Vec<_>, _>>()?;
            format!("[{}]", items.join(", "))
        }
        Value::Object(map) => {
            let fields = map
                .iter()
                .map(|(k, v)| {
                    Ok(format!(
                        "{}: {}",
                        validate_name(k, "object key")?,
                        value_to_graphql_literal(v)?
                    ))
                })
                .collect::<Result<Vec<_>, GraphqlError>>()?;
            format!("{{{}}}", fields.join(", "))
        }
    })
}

/// Render a filter as a GraphQL input object literal.
pub(crate) fn filter_to_graphql_literal(filter: &GqlFilter) -> Result<String, GraphqlError> {
    Ok(match filter {
        GqlFilter::Field { column, op, value } => format!(
            "{{{}: {{{}: {}}}}}",
            validate_name(column, "filter column")?,
            op.as_str(),
            value_to_graphql_literal(value)?
        ),
        GqlFilter::Is { column, value } => format!(
            "{{{}: {{is: {}}}}}",
            validate_name(column, "filter column")?,
            value.as_graphql_literal()
        ),
        GqlFilter::And(filters) | GqlFilter::Or(filters) => {
            let key = if matches!(filter, GqlFilter::And(_)) {
                "and"
            } else {
                "or"
            };
            let items = filters
                .iter()
                .map(filter_to_graphql_literal)
                .collect::<Result<Vec<_>, _>>()?;
            format!("{{{}: [{}]}}", key, items.join(", "))
        }
        GqlFilter::Not(inner) => format!("{{not: {}}}", filter_to_graphql_literal(inner)?),
    })
}

/// Render one orderBy entry as `{column: Direction}`.
fn order_entry_to_graphql_literal(entry: &OrderByEntry) -> Result<String, GraphqlError> {
    Ok(format!(
        "{{{}: {}}}",
        validate_name(&entry.column, "orderBy column")?,
        entry.direction.as_graphql_literal()
    ))
}

/// Render a selection set body, validating every field name.
fn render_selection(fields: &[String], what: &str) -> Result<String, GraphqlError> {
    if fields.is_empty() {
        return Ok("__typename".to_string());
    }
    let names = fields
        .iter()
        .map(|f| validate_name(f, what))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(names.join(" "))
}

/// Quote and escape a string as a GraphQL string literal.
fn quote_graphql_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if c.is_control() => {
                // Remaining C0/C1 controls and DEL: not allowed raw in a
                // GraphQL string, so use a \uXXXX escape.
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Render a collection query.
///
/// Produces a query like:
/// ```graphql
/// query {
///   blogCollection(first: 10, filter: {...}, orderBy: [{...}]) {
///     edges { cursor node { id title } }
///     pageInfo { hasNextPage hasPreviousPage startCursor endCursor }
///     totalCount
///   }
/// }
/// ```
#[allow(clippy::too_many_arguments)]
pub(crate) fn render_collection_query(
    collection: &str,
    select_fields: &[String],
    filter: Option<&GqlFilter>,
    order_by: &[OrderByEntry],
    first: Option<i64>,
    last: Option<i64>,
    after: Option<&str>,
    before: Option<&str>,
    offset: Option<i64>,
    include_total_count: bool,
) -> Result<(String, Value), GraphqlError> {
    let collection = validate_name(collection, "collection name")?;
    let mut query = String::with_capacity(256);
    let mut variables = serde_json::Map::new();

    // Build argument list
    let mut args = Vec::new();
    let mut var_defs = Vec::new();

    if let Some(n) = first {
        var_defs.push("$first: Int");
        args.push("first: $first".to_string());
        variables.insert("first".into(), Value::Number(n.into()));
    }

    if let Some(n) = last {
        var_defs.push("$last: Int");
        args.push("last: $last".to_string());
        variables.insert("last".into(), Value::Number(n.into()));
    }

    if let Some(cursor) = after {
        var_defs.push("$after: Cursor");
        args.push("after: $after".to_string());
        variables.insert("after".into(), Value::String(cursor.to_string()));
    }

    if let Some(cursor) = before {
        var_defs.push("$before: Cursor");
        args.push("before: $before".to_string());
        variables.insert("before".into(), Value::String(cursor.to_string()));
    }

    if let Some(n) = offset {
        var_defs.push("$offset: Int");
        args.push("offset: $offset".to_string());
        variables.insert("offset".into(), Value::Number(n.into()));
    }

    if let Some(filter) = filter {
        args.push(format!("filter: {}", filter_to_graphql_literal(filter)?));
    }

    if !order_by.is_empty() {
        let entries = order_by
            .iter()
            .map(order_entry_to_graphql_literal)
            .collect::<Result<Vec<_>, _>>()?;
        args.push(format!("orderBy: [{}]", entries.join(", ")));
    }

    // Selection set
    let node_fields = render_selection(select_fields, "selected field")?;

    // Build query string
    if var_defs.is_empty() {
        query.push_str("query");
    } else {
        let _ = write!(query, "query({})", var_defs.join(", "));
    }

    let _ = write!(query, " {{ {}", collection);

    if !args.is_empty() {
        let _ = write!(query, "({})", args.join(", "));
    }

    let _ = write!(
        query,
        " {{ edges {{ cursor node {{ {} }} }} pageInfo {{ hasNextPage hasPreviousPage startCursor endCursor }}",
        node_fields
    );

    if include_total_count {
        query.push_str(" totalCount");
    }

    query.push_str(" } }");

    Ok((query, Value::Object(variables)))
}

/// The kind of mutation to render.
#[derive(Debug, Clone, Copy)]
pub(crate) enum MutationKind {
    Insert,
    Update,
    Delete,
}

/// Derive the pg_graphql mutation field name from a collection name:
/// `blogCollection` becomes `insertIntoBlogCollection`,
/// `updateBlogCollection` or `deleteFromBlogCollection`.
///
/// The collection must be a valid GraphQL name, so its first character is
/// ASCII and can be upper-cased without slicing inside a UTF-8 sequence.
pub(crate) fn mutation_field_name(
    collection: &str,
    kind: MutationKind,
) -> Result<String, GraphqlError> {
    let collection = validate_name(collection, "collection name")?;
    let mut chars = collection.chars();
    let capitalized = match chars.next() {
        Some(first) => format!("{}{}", first.to_ascii_uppercase(), chars.as_str()),
        None => unreachable!("validate_name rejects empty names"),
    };
    let prefix = match kind {
        MutationKind::Insert => "insertInto",
        MutationKind::Update => "update",
        MutationKind::Delete => "deleteFrom",
    };
    Ok(format!("{prefix}{capitalized}"))
}

/// Render a mutation query.
///
/// The collection name should match the pg_graphql convention (e.g., `blogCollection`).
/// See [`mutation_field_name`] for the mutation field derived from it.
pub(crate) fn render_mutation(
    collection: &str,
    kind: MutationKind,
    returning_fields: &[String],
    filter: Option<&GqlFilter>,
    set: Option<&Value>,
    objects: Option<&Value>,
    at_most: Option<i64>,
) -> Result<(String, Value), GraphqlError> {
    let mut query = String::with_capacity(256);
    let variables = serde_json::Map::new();

    let mutation_field = mutation_field_name(collection, kind)?;

    // Build argument list
    let mut args = Vec::new();

    match kind {
        MutationKind::Insert => {
            if let Some(objs) = objects {
                args.push(format!("objects: {}", value_to_graphql_literal(objs)?));
            }
        }
        MutationKind::Update => {
            if let Some(set_val) = set {
                args.push(format!("set: {}", value_to_graphql_literal(set_val)?));
            }
            if let Some(filter) = filter {
                args.push(format!("filter: {}", filter_to_graphql_literal(filter)?));
            }
            if let Some(n) = at_most {
                args.push(format!("atMost: {}", n));
            }
        }
        MutationKind::Delete => {
            if let Some(filter) = filter {
                args.push(format!("filter: {}", filter_to_graphql_literal(filter)?));
            }
            if let Some(n) = at_most {
                args.push(format!("atMost: {}", n));
            }
        }
    }

    // Selection set for mutations: affectedCount + records
    let record_fields = render_selection(returning_fields, "returning field")?;

    let _ = write!(query, "mutation {{ {}", mutation_field);

    if !args.is_empty() {
        let _ = write!(query, "({})", args.join(", "));
    }

    let _ = write!(
        query,
        " {{ affectedCount records {{ {} }} }} }}",
        record_fields
    );

    Ok((query, Value::Object(variables)))
}

#[cfg(test)]
#[allow(clippy::approx_constant)]
mod tests {
    use super::*;
    use crate::filter::GqlFilter;
    use crate::order::OrderByDirection;
    use serde_json::json;

    fn lit(v: &Value) -> String {
        value_to_graphql_literal(v).unwrap()
    }

    #[test]
    fn value_to_literal_string() {
        assert_eq!(lit(&json!("hello")), "\"hello\"");
    }

    #[test]
    fn value_to_literal_string_escaped() {
        assert_eq!(lit(&json!("say \"hi\"")), "\"say \\\"hi\\\"\"");
    }

    #[test]
    fn value_to_literal_control_chars_escaped() {
        assert_eq!(
            lit(&json!("a\u{0}b\u{8}c\u{c}d\u{1f}e\u{7f}")),
            "\"a\\u0000b\\bc\\fd\\u001Fe\\u007F\""
        );
    }

    #[test]
    fn value_to_literal_number() {
        assert_eq!(lit(&json!(42)), "42");
        assert_eq!(lit(&json!(3.14)), "3.14");
    }

    #[test]
    fn value_to_literal_bool() {
        assert_eq!(lit(&json!(true)), "true");
        assert_eq!(lit(&json!(false)), "false");
    }

    #[test]
    fn value_to_literal_null() {
        assert_eq!(lit(&Value::Null), "null");
    }

    #[test]
    fn value_to_literal_array() {
        assert_eq!(lit(&json!([1, "two", true])), "[1, \"two\", true]");
    }

    #[test]
    fn value_to_literal_object() {
        let val = json!({"name": "Alice", "age": 30});
        let literal = lit(&val);
        // Object key order may vary, check both possibilities
        assert!(
            literal == "{age: 30, name: \"Alice\"}" || literal == "{name: \"Alice\", age: 30}",
            "Unexpected literal: {}",
            literal
        );
    }

    #[test]
    fn value_to_literal_enum_like_strings_are_quoted() {
        // Audit M7: user strings equal to enum names used to be emitted bare.
        for s in ["AscNullsLast", "NULL", "NOT_NULL", "TRUE", "FALSE"] {
            assert_eq!(lit(&json!(s)), format!("\"{s}\""));
        }
    }

    #[test]
    fn value_to_literal_rejects_invalid_keys() {
        assert!(value_to_graphql_literal(&json!({"a b": 1})).is_err());
        assert!(value_to_graphql_literal(&json!([{"ok": {"x}": 1}}])).is_err());
        assert!(value_to_graphql_literal(&json!({"": 1})).is_err());
        assert!(value_to_graphql_literal(&json!({"1a": 1})).is_err());
    }

    #[test]
    fn graphql_name_validation() {
        for ok in ["a", "_", "blogCollection", "_x9", "A_b_C"] {
            assert!(is_graphql_name(ok), "{ok}");
        }
        for bad in ["", "9a", "a-b", "a b", "é", "a{", "a:b"] {
            assert!(!is_graphql_name(bad), "{bad}");
        }
    }

    #[test]
    fn render_simple_query() {
        let (query, vars) = render_collection_query(
            "blogCollection",
            &["id".into(), "title".into()],
            None,
            &[],
            Some(10),
            None,
            None,
            None,
            None,
            false,
        )
        .unwrap();

        assert!(query.contains("query($first: Int)"));
        assert!(query.contains("blogCollection(first: $first)"));
        assert!(query.contains("node { id title }"));
        assert!(query.contains("pageInfo"));
        assert!(!query.contains("totalCount"));
        assert_eq!(vars["first"], 10);
    }

    #[test]
    fn render_query_with_filter_and_order() {
        let filter = GqlFilter::eq("status", json!("published"));
        let order = vec![OrderByEntry {
            column: "createdAt".into(),
            direction: OrderByDirection::DescNullsLast,
        }];

        let (query, _) = render_collection_query(
            "blogCollection",
            &["id".into(), "title".into()],
            Some(&filter),
            &order,
            Some(5),
            None,
            None,
            None,
            None,
            true,
        )
        .unwrap();

        assert!(query.contains("filter: {status: {eq: \"published\"}}"));
        assert!(query.contains("orderBy: [{createdAt: DescNullsLast}]"));
        assert!(query.contains("totalCount"));
    }

    #[test]
    fn render_is_filter_uses_enum() {
        let filter = GqlFilter::and(vec![
            GqlFilter::is_null("deletedAt"),
            GqlFilter::not(GqlFilter::is_not_null("x")),
        ]);
        assert_eq!(
            filter_to_graphql_literal(&filter).unwrap(),
            "{and: [{deletedAt: {is: NULL}}, {not: {x: {is: NOT_NULL}}}]}"
        );
    }

    #[test]
    fn render_rejects_invalid_names() {
        let bad_filter = GqlFilter::eq("id: {eq: 1}}) { x } evil: q(a", json!(1));
        assert!(render_collection_query(
            "c",
            &[],
            Some(&bad_filter),
            &[],
            None,
            None,
            None,
            None,
            None,
            false
        )
        .is_err());
        let bad_order = vec![OrderByEntry {
            column: "a}]".into(),
            direction: OrderByDirection::AscNullsFirst,
        }];
        assert!(render_collection_query(
            "c",
            &[],
            None,
            &bad_order,
            None,
            None,
            None,
            None,
            None,
            false
        )
        .is_err());
        assert!(render_collection_query(
            "c",
            &["id } evil { x".into()],
            None,
            &[],
            None,
            None,
            None,
            None,
            None,
            false
        )
        .is_err());
        assert!(render_collection_query(
            "c(x)",
            &[],
            None,
            &[],
            None,
            None,
            None,
            None,
            None,
            false
        )
        .is_err());
        assert!(render_mutation(
            "c",
            MutationKind::Delete,
            &["id } x".into()],
            None,
            None,
            None,
            None
        )
        .is_err());
    }

    #[test]
    fn mutation_field_name_handles_bad_collection_without_panicking() {
        // Audit G3: collection[..1] panicked on "" and non-ASCII first chars.
        for name in ["", "éventCollection"] {
            assert!(mutation_field_name(name, MutationKind::Insert).is_err());
        }
        assert_eq!(
            mutation_field_name("blogCollection", MutationKind::Update).unwrap(),
            "updateBlogCollection"
        );
        assert_eq!(
            mutation_field_name("_x", MutationKind::Delete).unwrap(),
            "deleteFrom_x"
        );
    }

    #[test]
    fn render_query_with_cursor() {
        let (query, vars) = render_collection_query(
            "blogCollection",
            &["id".into()],
            None,
            &[],
            Some(10),
            None,
            Some("cursor123"),
            None,
            None,
            false,
        )
        .unwrap();

        assert!(query.contains("$after: Cursor"));
        assert!(query.contains("after: $after"));
        assert_eq!(vars["after"], "cursor123");
    }

    #[test]
    fn render_insert_mutation() {
        let objects = json!([{"title": "New Post", "body": "Content"}]);
        let (query, _) = render_mutation(
            "blogCollection",
            MutationKind::Insert,
            &["id".into(), "title".into()],
            None,
            None,
            Some(&objects),
            None,
        )
        .unwrap();

        assert!(query.contains("mutation { insertIntoBlogCollection"));
        assert!(query.contains("objects: ["));
        assert!(query.contains("affectedCount records { id title }"));
    }

    #[test]
    fn render_update_mutation() {
        let set = json!({"title": "Updated"});
        let filter = GqlFilter::eq("id", json!(1));

        let (query, _) = render_mutation(
            "blogCollection",
            MutationKind::Update,
            &["id".into(), "title".into()],
            Some(&filter),
            Some(&set),
            None,
            Some(1),
        )
        .unwrap();

        assert!(query.contains("mutation { updateBlogCollection"));
        assert!(query.contains("set: {title: \"Updated\"}"));
        assert!(query.contains("filter: {id: {eq: 1}}"));
        assert!(query.contains("atMost: 1"));
    }

    #[test]
    fn render_delete_mutation() {
        let filter = GqlFilter::eq("id", json!(1));

        let (query, _) = render_mutation(
            "blogCollection",
            MutationKind::Delete,
            &["id".into()],
            Some(&filter),
            None,
            None,
            Some(1),
        )
        .unwrap();

        assert!(query.contains("mutation { deleteFromBlogCollection"));
        assert!(query.contains("filter: {id: {eq: 1}}"));
        assert!(query.contains("atMost: 1"));
        assert!(query.contains("records { id }"));
    }

    #[test]
    fn render_query_no_fields_uses_typename() {
        let (query, _) = render_collection_query(
            "testCollection",
            &[],
            None,
            &[],
            None,
            None,
            None,
            None,
            None,
            false,
        )
        .unwrap();

        assert!(query.contains("node { __typename }"));
    }
}
