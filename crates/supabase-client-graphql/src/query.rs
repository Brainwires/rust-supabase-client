use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::client::GraphqlClient;
use crate::error::GraphqlError;
use crate::filter::GqlFilter;
use crate::order::{OrderByDirection, OrderByEntry};
use crate::render;
use crate::types::Connection;

/// Builder for GraphQL collection queries.
///
/// Produces Relay-style connection queries against pg_graphql.
///
/// # Example
/// ```ignore
/// let connection = client.collection("blogCollection")
///     .select(&["id", "title", "createdAt"])
///     .filter(GqlFilter::eq("status", "published"))
///     .order_by("createdAt", OrderByDirection::DescNullsLast)
///     .first(10)
///     .total_count()
///     .execute::<BlogRow>().await?;
/// ```
#[derive(Debug)]
pub struct QueryBuilder {
    client: GraphqlClient,
    collection: String,
    select_fields: Vec<String>,
    filter: Option<GqlFilter>,
    order_by: Vec<OrderByEntry>,
    first: Option<i64>,
    last: Option<i64>,
    after: Option<String>,
    before: Option<String>,
    offset: Option<i64>,
    include_total_count: bool,
}

impl QueryBuilder {
    pub(crate) fn new(client: GraphqlClient, collection: String) -> Self {
        Self {
            client,
            collection,
            select_fields: Vec::new(),
            filter: None,
            order_by: Vec::new(),
            first: None,
            last: None,
            after: None,
            before: None,
            offset: None,
            include_total_count: false,
        }
    }

    /// Set the fields to select in each node.
    pub fn select(mut self, fields: &[&str]) -> Self {
        self.select_fields = fields.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Set a filter condition.
    pub fn filter(mut self, filter: GqlFilter) -> Self {
        self.filter = Some(filter);
        self
    }

    /// Add an order-by clause.
    pub fn order_by(mut self, column: &str, direction: OrderByDirection) -> Self {
        self.order_by.push(OrderByEntry {
            column: column.to_string(),
            direction,
        });
        self
    }

    /// Limit results to the first N items (forward pagination).
    pub fn first(mut self, n: i64) -> Self {
        self.first = Some(n);
        self
    }

    /// Limit results to the last N items (backward pagination).
    pub fn last(mut self, n: i64) -> Self {
        self.last = Some(n);
        self
    }

    /// Set the cursor for forward pagination.
    pub fn after(mut self, cursor: &str) -> Self {
        self.after = Some(cursor.to_string());
        self
    }

    /// Set the cursor for backward pagination.
    pub fn before(mut self, cursor: &str) -> Self {
        self.before = Some(cursor.to_string());
        self
    }

    /// Set the offset for pagination.
    pub fn offset(mut self, n: i64) -> Self {
        self.offset = Some(n);
        self
    }

    /// Include the `totalCount` field in the response.
    pub fn total_count(mut self) -> Self {
        self.include_total_count = true;
        self
    }

    /// Build the query string and variables without executing.
    ///
    /// Returns `(query_string, variables)` for inspection or debugging.
    pub fn build(&self) -> (String, Value) {
        let filter_value = self.filter.as_ref().map(|f| f.to_value());
        render::render_collection_query(
            &self.collection,
            &self.select_fields,
            filter_value.as_ref(),
            &self.order_by,
            self.first,
            self.last,
            self.after.as_deref(),
            self.before.as_deref(),
            self.offset,
            self.include_total_count,
        )
    }

    /// Execute the query and return a typed `Connection<T>`.
    ///
    /// The response `data` field is expected to have the shape:
    /// `{ "collectionName": { "edges": [...], "pageInfo": {...}, "totalCount": ... } }`
    pub async fn execute<T: DeserializeOwned>(self) -> Result<Connection<T>, GraphqlError> {
        let (query, variables) = self.build();
        let collection_name = self.collection.clone();

        let response = self
            .client
            .execute::<Value>(&query, Some(variables), None)
            .await?;

        let data = response.data.ok_or_else(|| {
            GraphqlError::InvalidConfig("No data in GraphQL response".to_string())
        })?;

        let collection_data = data.get(&collection_name).ok_or_else(|| {
            GraphqlError::InvalidConfig(format!(
                "Collection '{}' not found in response data",
                collection_name
            ))
        })?;

        let connection: Connection<T> = serde_json::from_value(collection_data.clone())?;
        Ok(connection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_client() -> GraphqlClient {
        GraphqlClient::new("https://example.supabase.co", "test-key").unwrap()
    }

    #[test]
    fn build_simple_query() {
        let builder = QueryBuilder::new(test_client(), "blogCollection".into())
            .select(&["id", "title"])
            .first(10);

        let (query, vars) = builder.build();
        assert!(query.contains("blogCollection"));
        assert!(query.contains("node { id title }"));
        assert!(query.contains("$first: Int"));
        assert_eq!(vars["first"], 10);
    }

    #[test]
    fn build_query_with_filter() {
        let builder = QueryBuilder::new(test_client(), "blogCollection".into())
            .select(&["id"])
            .filter(GqlFilter::eq("status", json!("published")));

        let (query, _) = builder.build();
        assert!(query.contains("filter: {status: {eq: \"published\"}}"));
    }

    #[test]
    fn build_query_with_order() {
        let builder = QueryBuilder::new(test_client(), "blogCollection".into())
            .select(&["id"])
            .order_by("createdAt", OrderByDirection::DescNullsLast);

        let (query, _) = builder.build();
        assert!(query.contains("orderBy: [{createdAt: DescNullsLast}]"));
    }

    #[test]
    fn build_query_with_total_count() {
        let builder = QueryBuilder::new(test_client(), "blogCollection".into())
            .select(&["id"])
            .total_count();

        let (query, _) = builder.build();
        assert!(query.contains("totalCount"));
    }

    #[test]
    fn build_query_with_cursors() {
        let builder = QueryBuilder::new(test_client(), "blogCollection".into())
            .select(&["id"])
            .first(5)
            .after("abc123");

        let (query, vars) = builder.build();
        assert!(query.contains("$after: Cursor"));
        assert!(query.contains("after: $after"));
        assert_eq!(vars["after"], "abc123");
    }

    #[test]
    fn build_query_backward_pagination() {
        let builder = QueryBuilder::new(test_client(), "blogCollection".into())
            .select(&["id"])
            .last(5)
            .before("xyz789");

        let (query, vars) = builder.build();
        assert!(query.contains("$last: Int"));
        assert!(query.contains("$before: Cursor"));
        assert_eq!(vars["last"], 5);
        assert_eq!(vars["before"], "xyz789");
    }

    #[test]
    fn build_full_query() {
        let builder = QueryBuilder::new(test_client(), "blogCollection".into())
            .select(&["id", "title", "createdAt"])
            .filter(GqlFilter::and(vec![
                GqlFilter::eq("status", json!("published")),
                GqlFilter::gte("views", json!(100)),
            ]))
            .order_by("createdAt", OrderByDirection::DescNullsLast)
            .first(10)
            .after("cursor123")
            .total_count();

        let (query, vars) = builder.build();
        assert!(query.contains("blogCollection"));
        assert!(query.contains("node { id title createdAt }"));
        assert!(query.contains("filter:"));
        assert!(query.contains("orderBy:"));
        assert!(query.contains("totalCount"));
        assert_eq!(vars["first"], 10);
        assert_eq!(vars["after"], "cursor123");
    }
}
