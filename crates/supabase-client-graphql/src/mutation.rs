use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::client::GraphqlClient;
use crate::error::GraphqlError;
use crate::filter::GqlFilter;
use crate::render;
use crate::types::MutationResult;

/// The kind of mutation operation.
#[derive(Debug, Clone, Copy)]
pub enum MutationKind {
    Insert,
    Update,
    Delete,
}

impl From<MutationKind> for render::MutationKind {
    fn from(kind: MutationKind) -> Self {
        match kind {
            MutationKind::Insert => render::MutationKind::Insert,
            MutationKind::Update => render::MutationKind::Update,
            MutationKind::Delete => render::MutationKind::Delete,
        }
    }
}

/// Builder for GraphQL mutations (insert, update, delete).
///
/// # Examples
///
/// ```ignore
/// // Insert
/// let result = client.insert_into("blogCollection")
///     .objects(vec![json!({"title": "New", "body": "Content"})])
///     .returning(&["id", "title"])
///     .execute::<BlogRow>().await?;
///
/// // Update
/// let result = client.update("blogCollection")
///     .set(json!({"title": "Updated"}))
///     .filter(GqlFilter::eq("id", 1))
///     .at_most(1)
///     .returning(&["id", "title"])
///     .execute::<BlogRow>().await?;
///
/// // Delete
/// let result = client.delete_from("blogCollection")
///     .filter(GqlFilter::eq("id", 1))
///     .at_most(1)
///     .returning(&["id"])
///     .execute::<BlogRow>().await?;
/// ```
#[derive(Debug)]
pub struct MutationBuilder {
    client: GraphqlClient,
    collection: String,
    kind: MutationKind,
    returning_fields: Vec<String>,
    filter: Option<GqlFilter>,
    set: Option<Value>,
    objects: Option<Value>,
    at_most: Option<i64>,
}

impl MutationBuilder {
    pub(crate) fn new(client: GraphqlClient, collection: String, kind: MutationKind) -> Self {
        Self {
            client,
            collection,
            kind,
            returning_fields: Vec::new(),
            filter: None,
            set: None,
            objects: None,
            at_most: None,
        }
    }

    /// Set the fields to return in the mutation result.
    pub fn returning(mut self, fields: &[&str]) -> Self {
        self.returning_fields = fields.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Set a filter condition (for update/delete).
    pub fn filter(mut self, filter: GqlFilter) -> Self {
        self.filter = Some(filter);
        self
    }

    /// Set the values to update (for update mutations).
    ///
    /// The value should be a JSON object with field names and new values.
    pub fn set(mut self, values: Value) -> Self {
        self.set = Some(values);
        self
    }

    /// Set the objects to insert (for insert mutations).
    ///
    /// The value should be a JSON array of objects.
    pub fn objects(mut self, objects: Vec<Value>) -> Self {
        self.objects = Some(Value::Array(objects));
        self
    }

    /// Limit the number of affected rows (for update/delete).
    pub fn at_most(mut self, n: i64) -> Self {
        self.at_most = Some(n);
        self
    }

    /// Build the mutation string and variables without executing.
    ///
    /// Returns `(query_string, variables)` for inspection or debugging.
    pub fn build(&self) -> (String, Value) {
        let filter_value = self.filter.as_ref().map(|f| f.to_value());
        render::render_mutation(
            &self.collection,
            self.kind.into(),
            &self.returning_fields,
            filter_value.as_ref(),
            self.set.as_ref(),
            self.objects.as_ref(),
            self.at_most,
        )
    }

    /// Execute the mutation and return a typed `MutationResult<T>`.
    ///
    /// The response is expected to have the shape:
    /// `{ "mutationField": { "affectedCount": N, "records": [...] } }`
    pub async fn execute<T: DeserializeOwned>(self) -> Result<MutationResult<T>, GraphqlError> {
        let (query, variables) = self.build();

        // Derive the expected mutation field name to extract from response
        let mutation_field = match self.kind {
            MutationKind::Insert => format!(
                "insertInto{}{}",
                self.collection[..1].to_uppercase(),
                &self.collection[1..]
            ),
            MutationKind::Update => format!(
                "update{}{}",
                self.collection[..1].to_uppercase(),
                &self.collection[1..]
            ),
            MutationKind::Delete => format!(
                "deleteFrom{}{}",
                self.collection[..1].to_uppercase(),
                &self.collection[1..]
            ),
        };

        let response = self
            .client
            .execute::<Value>(&query, Some(variables), None)
            .await?;

        let data = response.data.ok_or_else(|| {
            GraphqlError::InvalidConfig("No data in GraphQL response".to_string())
        })?;

        let mutation_data = data.get(&mutation_field).ok_or_else(|| {
            GraphqlError::InvalidConfig(format!(
                "Mutation field '{}' not found in response data",
                mutation_field
            ))
        })?;

        let result: MutationResult<T> = serde_json::from_value(mutation_data.clone())?;
        Ok(result)
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
    fn build_insert_mutation() {
        let builder = MutationBuilder::new(
            test_client(),
            "blogCollection".into(),
            MutationKind::Insert,
        )
        .objects(vec![json!({"title": "New", "body": "Content"})])
        .returning(&["id", "title"]);

        let (query, _) = builder.build();
        assert!(query.contains("insertIntoBlogCollection"));
        assert!(query.contains("objects:"));
        assert!(query.contains("records { id title }"));
        assert!(query.contains("affectedCount"));
    }

    #[test]
    fn build_update_mutation() {
        let builder = MutationBuilder::new(
            test_client(),
            "blogCollection".into(),
            MutationKind::Update,
        )
        .set(json!({"title": "Updated"}))
        .filter(GqlFilter::eq("id", json!(1)))
        .at_most(1)
        .returning(&["id", "title"]);

        let (query, _) = builder.build();
        assert!(query.contains("updateBlogCollection"));
        assert!(query.contains("set: {title: \"Updated\"}"));
        assert!(query.contains("filter: {id: {eq: 1}}"));
        assert!(query.contains("atMost: 1"));
    }

    #[test]
    fn build_delete_mutation() {
        let builder = MutationBuilder::new(
            test_client(),
            "blogCollection".into(),
            MutationKind::Delete,
        )
        .filter(GqlFilter::eq("id", json!(1)))
        .at_most(1)
        .returning(&["id"]);

        let (query, _) = builder.build();
        assert!(query.contains("deleteFromBlogCollection"));
        assert!(query.contains("filter: {id: {eq: 1}}"));
        assert!(query.contains("atMost: 1"));
        assert!(query.contains("records { id }"));
    }

    #[test]
    fn build_mutation_no_returning_uses_typename() {
        let builder = MutationBuilder::new(
            test_client(),
            "blogCollection".into(),
            MutationKind::Delete,
        )
        .filter(GqlFilter::eq("id", json!(1)));

        let (query, _) = builder.build();
        assert!(query.contains("records { __typename }"));
    }

    #[test]
    fn build_insert_multiple_objects() {
        let builder = MutationBuilder::new(
            test_client(),
            "blogCollection".into(),
            MutationKind::Insert,
        )
        .objects(vec![
            json!({"title": "Post 1"}),
            json!({"title": "Post 2"}),
        ])
        .returning(&["id"]);

        let (query, _) = builder.build();
        assert!(query.contains("insertIntoBlogCollection"));
        assert!(query.contains("objects: ["));
    }
}
