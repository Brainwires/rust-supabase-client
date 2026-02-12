# supabase-client-query

Query builder, filters, modifiers, and SQL/PostgREST execution for supabase-client.

> **Note:** This crate is part of the [`supabase-client-sdk`](https://crates.io/crates/supabase-client-sdk) workspace. Most users should depend on `supabase-client-sdk` with the `query` feature (enabled by default) rather than using this crate directly.

## Key Features

- **`SupabaseClientQueryExt`** extension trait — adds `.from()`, `.from_typed()`, `.rpc()`, `.rpc_typed()` to `SupabaseClient`
- Fluent builders: `SelectBuilder`, `InsertBuilder`, `UpdateBuilder`, `DeleteBuilder`, `UpsertBuilder`, `RpcBuilder`
- 20+ filter methods: `eq`, `neq`, `gt`, `lt`, `gte`, `lte`, `like`, `ilike`, `in_`, `is`, `contains`, `overlaps`, `text_search`, `or_`, `not_`, and more
- Modifiers: `order`, `limit`, `range`, `single`, `count`, `head`, `explain`
- Response format overrides: `.csv()` and `.geojson()`
- Count options: `exact`, `planned`, `estimated` via `count_option()`
- RPC dry-run with `.rollback()`
- Optional `direct-sql` feature for direct PostgreSQL execution via sqlx

## Usage

```rust
use supabase_client_query::SupabaseClientQueryExt;

let response = client.from("cities")
    .select("id, name, country_id")
    .eq("country_id", 1)
    .order("name", OrderDirection::Ascending)
    .limit(10)
    .execute()
    .await;

let rows = response.into_result()?;
```

## License

Licensed under either of [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0) or [MIT license](http://opensource.org/licenses/MIT) at your option.
