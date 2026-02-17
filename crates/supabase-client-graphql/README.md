# supabase-client-graphql

GraphQL client for supabase-client, powered by the `pg_graphql` PostgreSQL extension.

> **Note:** This crate is part of the [`supabase-client-sdk`](https://crates.io/crates/supabase-client-sdk) workspace. Most users should depend on `supabase-client-sdk` with the `graphql` feature rather than using this crate directly.

## Key Features

- **`SupabaseClientGraphqlExt`** extension trait — adds `.graphql()` to `SupabaseClient`
- **`GraphqlClient`** — HTTP client for the `/graphql/v1` endpoint
- Raw query execution with variables and operation names
- Fluent **`QueryBuilder`** for Relay-style collection queries with filtering, ordering, pagination, and total count
- Fluent **`MutationBuilder`** for insert, update, and delete mutations
- Rich filter support: `eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `in`, `is`, `like`, `ilike`, `startsWith`, and composable `and`/`or`/`not`
- Cursor-based (`first`/`after`, `last`/`before`) and offset pagination
- `set_auth()` to override the default token for subsequent requests

## Usage

### Raw Query

```rust
use supabase_client_graphql::SupabaseClientGraphqlExt;

let graphql = client.graphql()?;

let response = graphql.execute_raw(
    "query { blogCollection { edges { node { id title } } } }",
    None,
    None,
).await?;
```

### Collection Query (Builder)

```rust
use supabase_client_graphql::{SupabaseClientGraphqlExt, GqlFilter, OrderByDirection};
use serde_json::json;

let graphql = client.graphql()?;

let connection = graphql.collection("blogCollection")
    .select(&["id", "title", "createdAt"])
    .filter(GqlFilter::eq("status", json!("published")))
    .order_by("createdAt", OrderByDirection::DescNullsLast)
    .first(10)
    .total_count()
    .execute::<BlogRow>().await?;

for edge in &connection.edges {
    println!("{}: {}", edge.node.id, edge.node.title);
}
```

### Insert Mutation

```rust
use supabase_client_graphql::SupabaseClientGraphqlExt;
use serde_json::json;

let graphql = client.graphql()?;

let result = graphql.insert_into("blogCollection")
    .objects(vec![json!({"title": "New Post", "body": "Content"})])
    .returning(&["id", "title"])
    .execute::<BlogRow>().await?;
```

### Update Mutation

```rust
use supabase_client_graphql::{SupabaseClientGraphqlExt, GqlFilter};

let graphql = client.graphql()?;

let result = graphql.update("blogCollection")
    .set(json!({"title": "Updated Title"}))
    .filter(GqlFilter::eq("id", 1))
    .at_most(1)
    .returning(&["id", "title"])
    .execute::<BlogRow>().await?;
```

### Delete Mutation

```rust
use supabase_client_graphql::{SupabaseClientGraphqlExt, GqlFilter};

let graphql = client.graphql()?;

let result = graphql.delete_from("blogCollection")
    .filter(GqlFilter::eq("id", 1))
    .at_most(1)
    .returning(&["id"])
    .execute::<BlogRow>().await?;
```

## License

Licensed under either of [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0) or [MIT license](http://opensource.org/licenses/MIT) at your option.
