//! Internal module for rendering GraphQL query strings from builder state.
//!
//! Converts `serde_json::Value` trees into GraphQL literal syntax and
//! assembles complete query/mutation documents.

use serde_json::Value;
use std::fmt::Write;

use crate::order::OrderByEntry;

/// Set of GraphQL enum literal strings that should be rendered unquoted.
const GRAPHQL_ENUM_LITERALS: &[&str] = &[
    // OrderByDirection
    "AscNullsFirst",
    "AscNullsLast",
    "DescNullsFirst",
    "DescNullsLast",
    // FilterIs
    "NULL",
    "NOT_NULL",
    "TRUE",
    "FALSE",
];

/// Convert a `serde_json::Value` into a GraphQL literal string.
///
/// - Strings that match known enum literals are rendered unquoted.
/// - Other strings are rendered with double quotes and escaping.
/// - Numbers, booleans, null are rendered as-is.
/// - Arrays become `[elem1, elem2, ...]`.
/// - Objects become `{key1: value1, key2: value2}`.
pub(crate) fn value_to_graphql_literal(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => {
            if GRAPHQL_ENUM_LITERALS.contains(&s.as_str()) {
                s.clone()
            } else {
                format!("\"{}\"", escape_graphql_string(s))
            }
        }
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(value_to_graphql_literal).collect();
            format!("[{}]", items.join(", "))
        }
        Value::Object(map) => {
            let fields: Vec<String> = map
                .iter()
                .map(|(k, v)| format!("{}: {}", k, value_to_graphql_literal(v)))
                .collect();
            format!("{{{}}}", fields.join(", "))
        }
    }
}

/// Escape special characters in a GraphQL string value.
fn escape_graphql_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
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
pub(crate) fn render_collection_query(
    collection: &str,
    select_fields: &[String],
    filter: Option<&Value>,
    order_by: &[OrderByEntry],
    first: Option<i64>,
    last: Option<i64>,
    after: Option<&str>,
    before: Option<&str>,
    offset: Option<i64>,
    include_total_count: bool,
) -> (String, Value) {
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

    if let Some(filter_val) = filter {
        args.push(format!("filter: {}", value_to_graphql_literal(filter_val)));
    }

    if !order_by.is_empty() {
        let entries: Vec<String> = order_by
            .iter()
            .map(|e| value_to_graphql_literal(&e.to_value()))
            .collect();
        args.push(format!("orderBy: [{}]", entries.join(", ")));
    }

    // Build query string
    if var_defs.is_empty() {
        write!(query, "query").unwrap();
    } else {
        write!(query, "query({})", var_defs.join(", ")).unwrap();
    }

    write!(query, " {{ {}", collection).unwrap();

    if !args.is_empty() {
        write!(query, "({})", args.join(", ")).unwrap();
    }

    // Selection set
    let node_fields = if select_fields.is_empty() {
        "__typename".to_string()
    } else {
        select_fields.join(" ")
    };

    write!(
        query,
        " {{ edges {{ cursor node {{ {} }} }} pageInfo {{ hasNextPage hasPreviousPage startCursor endCursor }}",
        node_fields
    )
    .unwrap();

    if include_total_count {
        write!(query, " totalCount").unwrap();
    }

    write!(query, " }} }}").unwrap();

    (query, Value::Object(variables))
}

/// The kind of mutation to render.
#[derive(Debug, Clone, Copy)]
pub(crate) enum MutationKind {
    Insert,
    Update,
    Delete,
}

/// Render a mutation query.
///
/// The collection name should match the pg_graphql convention (e.g., `blogCollection`).
/// The mutation field name is derived as:
/// - insert: `insertIntoBlogCollection`
/// - update: `updateBlogCollection`
/// - delete: `deleteFromBlogCollection`
pub(crate) fn render_mutation(
    collection: &str,
    kind: MutationKind,
    returning_fields: &[String],
    filter: Option<&Value>,
    set: Option<&Value>,
    objects: Option<&Value>,
    at_most: Option<i64>,
) -> (String, Value) {
    let mut query = String::with_capacity(256);
    let variables = serde_json::Map::new();

    // Derive the mutation field name from the collection
    // e.g., blogCollection -> insertIntoBlogCollection / updateBlogCollection / deleteFromBlogCollection
    let mutation_field = match kind {
        MutationKind::Insert => format!(
            "insertInto{}{}",
            collection[..1].to_uppercase(),
            &collection[1..]
        ),
        MutationKind::Update => format!(
            "update{}{}",
            collection[..1].to_uppercase(),
            &collection[1..]
        ),
        MutationKind::Delete => format!(
            "deleteFrom{}{}",
            collection[..1].to_uppercase(),
            &collection[1..]
        ),
    };

    // Build argument list
    let mut args = Vec::new();

    match kind {
        MutationKind::Insert => {
            if let Some(objs) = objects {
                args.push(format!("objects: {}", value_to_graphql_literal(objs)));
            }
        }
        MutationKind::Update => {
            if let Some(set_val) = set {
                args.push(format!("set: {}", value_to_graphql_literal(set_val)));
            }
            if let Some(filter_val) = filter {
                args.push(format!(
                    "filter: {}",
                    value_to_graphql_literal(filter_val)
                ));
            }
            if let Some(n) = at_most {
                args.push(format!("atMost: {}", n));
            }
        }
        MutationKind::Delete => {
            if let Some(filter_val) = filter {
                args.push(format!(
                    "filter: {}",
                    value_to_graphql_literal(filter_val)
                ));
            }
            if let Some(n) = at_most {
                args.push(format!("atMost: {}", n));
            }
        }
    }

    write!(query, "mutation {{ {}", mutation_field).unwrap();

    if !args.is_empty() {
        write!(query, "({})", args.join(", ")).unwrap();
    }

    // Selection set for mutations: affectedCount + records
    let record_fields = if returning_fields.is_empty() {
        "__typename".to_string()
    } else {
        returning_fields.join(" ")
    };

    write!(
        query,
        " {{ affectedCount records {{ {} }} }} }}",
        record_fields
    )
    .unwrap();

    (query, Value::Object(variables))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::GqlFilter;
    use crate::order::OrderByDirection;
    use serde_json::json;

    #[test]
    fn value_to_literal_string() {
        assert_eq!(
            value_to_graphql_literal(&json!("hello")),
            "\"hello\""
        );
    }

    #[test]
    fn value_to_literal_string_escaped() {
        assert_eq!(
            value_to_graphql_literal(&json!("say \"hi\"")),
            "\"say \\\"hi\\\"\""
        );
    }

    #[test]
    fn value_to_literal_number() {
        assert_eq!(value_to_graphql_literal(&json!(42)), "42");
        assert_eq!(value_to_graphql_literal(&json!(3.14)), "3.14");
    }

    #[test]
    fn value_to_literal_bool() {
        assert_eq!(value_to_graphql_literal(&json!(true)), "true");
        assert_eq!(value_to_graphql_literal(&json!(false)), "false");
    }

    #[test]
    fn value_to_literal_null() {
        assert_eq!(value_to_graphql_literal(&Value::Null), "null");
    }

    #[test]
    fn value_to_literal_array() {
        assert_eq!(
            value_to_graphql_literal(&json!([1, "two", true])),
            "[1, \"two\", true]"
        );
    }

    #[test]
    fn value_to_literal_object() {
        let val = json!({"name": "Alice", "age": 30});
        let literal = value_to_graphql_literal(&val);
        // Object key order may vary, check both possibilities
        assert!(
            literal == "{age: 30, name: \"Alice\"}" || literal == "{name: \"Alice\", age: 30}",
            "Unexpected literal: {}",
            literal
        );
    }

    #[test]
    fn value_to_literal_enum() {
        assert_eq!(
            value_to_graphql_literal(&json!("AscNullsLast")),
            "AscNullsLast"
        );
        assert_eq!(value_to_graphql_literal(&json!("NULL")), "NULL");
        assert_eq!(value_to_graphql_literal(&json!("NOT_NULL")), "NOT_NULL");
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
        );

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
            Some(&filter.to_value()),
            &order,
            Some(5),
            None,
            None,
            None,
            None,
            true,
        );

        assert!(query.contains("filter: {status: {eq: \"published\"}}"));
        assert!(query.contains("orderBy: [{createdAt: DescNullsLast}]"));
        assert!(query.contains("totalCount"));
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
        );

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
        );

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
            Some(&filter.to_value()),
            Some(&set),
            None,
            Some(1),
        );

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
            Some(&filter.to_value()),
            None,
            None,
            Some(1),
        );

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
        );

        assert!(query.contains("node { __typename }"));
    }
}
