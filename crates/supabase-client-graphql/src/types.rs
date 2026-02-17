use serde::{Deserialize, Serialize};

use crate::error::GraphqlApiError;

/// Raw GraphQL response envelope.
///
/// Every response from the `/graphql/v1` endpoint has this shape.
#[derive(Debug, Clone, Deserialize)]
pub struct GraphqlResponse<T> {
    pub data: Option<T>,
    #[serde(default)]
    pub errors: Vec<GraphqlApiError>,
}

/// Relay-style connection returned by pg_graphql collection queries.
///
/// `T` is the row type (e.g., `BlogRow`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Connection<T> {
    pub edges: Vec<Edge<T>>,
    pub page_info: PageInfo,
    #[serde(default)]
    pub total_count: Option<i64>,
}

/// A single edge in a Relay connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge<T> {
    pub cursor: String,
    pub node: T,
}

/// Pagination metadata for a Relay connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PageInfo {
    pub has_next_page: bool,
    pub has_previous_page: bool,
    #[serde(default)]
    pub start_cursor: Option<String>,
    #[serde(default)]
    pub end_cursor: Option<String>,
}

/// Result of a mutation (insert, update, delete).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MutationResult<T> {
    pub affected_count: i64,
    pub records: Vec<T>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn deserialize_connection() {
        let json = json!({
            "edges": [
                {
                    "cursor": "abc123",
                    "node": { "id": 1, "title": "Hello" }
                }
            ],
            "pageInfo": {
                "hasNextPage": true,
                "hasPreviousPage": false,
                "startCursor": "abc123",
                "endCursor": "abc123"
            },
            "totalCount": 42
        });

        let conn: Connection<serde_json::Value> = serde_json::from_value(json).unwrap();
        assert_eq!(conn.edges.len(), 1);
        assert_eq!(conn.edges[0].cursor, "abc123");
        assert!(conn.page_info.has_next_page);
        assert!(!conn.page_info.has_previous_page);
        assert_eq!(conn.total_count, Some(42));
    }

    #[test]
    fn deserialize_connection_no_total_count() {
        let json = json!({
            "edges": [],
            "pageInfo": {
                "hasNextPage": false,
                "hasPreviousPage": false
            }
        });

        let conn: Connection<serde_json::Value> = serde_json::from_value(json).unwrap();
        assert!(conn.edges.is_empty());
        assert_eq!(conn.total_count, None);
    }

    #[test]
    fn deserialize_mutation_result() {
        let json = json!({
            "affectedCount": 2,
            "records": [
                { "id": 1, "title": "A" },
                { "id": 2, "title": "B" }
            ]
        });

        let result: MutationResult<serde_json::Value> = serde_json::from_value(json).unwrap();
        assert_eq!(result.affected_count, 2);
        assert_eq!(result.records.len(), 2);
    }

    #[test]
    fn deserialize_graphql_response_with_data() {
        let json = json!({
            "data": { "blogCollection": { "edges": [] } }
        });

        let resp: GraphqlResponse<serde_json::Value> = serde_json::from_value(json).unwrap();
        assert!(resp.data.is_some());
        assert!(resp.errors.is_empty());
    }

    #[test]
    fn deserialize_graphql_response_with_errors() {
        let json = json!({
            "data": null,
            "errors": [
                { "message": "Column not found" }
            ]
        });

        let resp: GraphqlResponse<serde_json::Value> = serde_json::from_value(json).unwrap();
        assert!(resp.data.is_none());
        assert_eq!(resp.errors.len(), 1);
        assert_eq!(resp.errors[0].message, "Column not found");
    }
}
