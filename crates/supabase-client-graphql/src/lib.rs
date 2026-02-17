//! Supabase GraphQL client for `pg_graphql`.
//!
//! This crate provides a GraphQL client for querying Supabase's auto-generated
//! GraphQL API powered by the `pg_graphql` PostgreSQL extension. The endpoint
//! is at `POST /graphql/v1`.
//!
//! # Usage
//!
//! ```ignore
//! use supabase_client_sdk::prelude::*;
//! use serde_json::json;
//!
//! let client = SupabaseClient::new(config)?;
//! let graphql = client.graphql()?;
//!
//! // Collection query with builder
//! let connection = graphql.collection("blogCollection")
//!     .select(&["id", "title", "createdAt"])
//!     .filter(GqlFilter::eq("status", json!("published")))
//!     .order_by("createdAt", OrderByDirection::DescNullsLast)
//!     .first(10)
//!     .execute::<BlogRow>().await?;
//!
//! // Insert mutation
//! let result = graphql.insert_into("blogCollection")
//!     .objects(vec![json!({"title": "New Post"})])
//!     .returning(&["id", "title"])
//!     .execute::<BlogRow>().await?;
//! ```

pub mod client;
pub mod error;
pub mod filter;
pub mod mutation;
pub mod order;
pub mod query;
pub(crate) mod render;
pub mod types;

// Re-exports for convenient access
pub use client::GraphqlClient;
pub use error::{GraphqlApiError, GraphqlError};
pub use filter::{FilterOp, GqlFilter, IsValue};
pub use mutation::{MutationBuilder, MutationKind};
pub use order::OrderByDirection;
pub use query::QueryBuilder;
pub use types::*;

use supabase_client_core::SupabaseClient;

/// Extension trait to create a [`GraphqlClient`] from a [`SupabaseClient`].
///
/// # Example
/// ```ignore
/// use supabase_client_sdk::prelude::*;
/// use supabase_client_graphql::SupabaseClientGraphqlExt;
///
/// let client = SupabaseClient::new(config)?;
/// let graphql = client.graphql()?;
/// let response = graphql.collection("blogCollection")
///     .select(&["id", "title"])
///     .first(10)
///     .execute::<BlogRow>().await?;
/// ```
pub trait SupabaseClientGraphqlExt {
    /// Create a [`GraphqlClient`] from the client's configuration.
    ///
    /// Requires `supabase_url` and `supabase_key` to be set in the config.
    fn graphql(&self) -> Result<GraphqlClient, GraphqlError>;
}

impl SupabaseClientGraphqlExt for SupabaseClient {
    fn graphql(&self) -> Result<GraphqlClient, GraphqlError> {
        GraphqlClient::new(self.supabase_url(), self.api_key())
    }
}
