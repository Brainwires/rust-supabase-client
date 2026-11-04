# supabase-client-sdk

Rust client for Supabase with fluent API — REST by default, direct SQL opt-in.

## Installation

```toml
[dependencies]
supabase-client-sdk = "0.3"
# Or with specific features:
supabase-client-sdk = { version = "0.3", features = ["auth", "realtime"] }
# Without rustls/aws-lc-rs, using the platform TLS library:
# supabase-client-sdk = { version = "0.3", default-features = false, features = ["query", "derive", "native-tls"] }
```

Requires Rust 1.89+. The default `rustls` backend compiles AWS-LC, which needs
a C compiler (and CMake on some targets).

### Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `query` | Yes | Query builder (select, insert, update, delete, upsert, rpc) |
| `derive` | Yes | `#[derive(Table)]` proc macro |
| `auth` | No | GoTrue authentication client |
| `realtime` | No | WebSocket realtime subscriptions |
| `storage` | No | Object storage client |
| `functions` | No | Edge Functions client |
| `graphql` | No | GraphQL client (pg_graphql) |
| `direct-sql` | No | Direct PostgreSQL via sqlx (bypasses PostgREST; not on wasm32) |
| `full` | No | `query`, `derive`, `auth`, `realtime`, `storage`, `functions`, `graphql` |
| `rustls` | Yes | TLS via rustls + aws-lc-rs with the OS trust store |
| `native-tls` | No | TLS via OpenSSL / SChannel / Secure Transport |

After `client.auth()?.sign_in_*()`, the query, storage, functions, GraphQL and
realtime clients created from the same `SupabaseClient` send the signed-in
user's JWT, so row-level security applies to that user.

## Quick Start

```rust
use supabase_client_sdk::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SupabaseConfig::new(
        "https://your-project.supabase.co",
        "your-anon-key",
    );

    let client = SupabaseClient::new(config)?;

    let response = client.from("cities")
        .select("*")
        .execute()
        .await;

    for row in response.into_result()? {
        println!("{}", row.get_as::<String>("name").unwrap());
    }

    Ok(())
}
```

## Architecture

This is the facade crate that re-exports all sub-crates behind feature flags:

| Crate | Description |
|-------|-------------|
| [`supabase-client-core`](https://crates.io/crates/supabase-client-core) | `SupabaseClient`, config, errors, response types |
| [`supabase-client-query`](https://crates.io/crates/supabase-client-query) | Query builder, filters, modifiers, RPC |
| [`supabase-client-derive`](https://crates.io/crates/supabase-client-derive) | `#[derive(Table)]` proc macro |
| [`supabase-client-auth`](https://crates.io/crates/supabase-client-auth) | GoTrue authentication client |
| [`supabase-client-realtime`](https://crates.io/crates/supabase-client-realtime) | WebSocket realtime client |
| [`supabase-client-storage`](https://crates.io/crates/supabase-client-storage) | Object storage client |
| [`supabase-client-functions`](https://crates.io/crates/supabase-client-functions) | Edge Functions client |
| [`supabase-client-graphql`](https://crates.io/crates/supabase-client-graphql) | GraphQL (pg_graphql) client |
| [`supabase-client-wasm`](https://crates.io/crates/supabase-client-wasm) | WASM/TypeScript bindings |

Each sub-crate provides an extension trait on `SupabaseClient`:
- `SupabaseClientQueryExt` — `.from()`, `.from_typed()`, `.rpc()`
- `SupabaseClientAuthExt` — `.auth()`
- `SupabaseClientRealtimeExt` — `.realtime()`
- `SupabaseClientStorageExt` — `.storage()`
- `SupabaseClientFunctionsExt` — `.functions()`
- `SupabaseClientGraphqlExt` — `.graphql()`

See the [repository README](https://github.com/Brainwires/rust-supabase-client) for full documentation, examples, and usage guides.

## License

Licensed under either of [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0) or [MIT license](http://opensource.org/licenses/MIT) at your option.
