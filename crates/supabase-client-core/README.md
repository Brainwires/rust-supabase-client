# supabase-client-core

Core types for supabase-client: connection, config, errors, response.

> **Note:** This crate is part of the [`supabase-client-sdk`](https://crates.io/crates/supabase-client-sdk) workspace. Most users should depend on `supabase-client-sdk` with the appropriate feature flag rather than using this crate directly.

## Key Features

- **`SupabaseClient`** — main client struct holding HTTP client and configuration
- **`SupabaseConfig`** — connection URL, API key, schema, and optional database pool settings
- **`SupabaseError`** — unified error type across all sub-crates
- **`SupabaseResponse`** — response wrapper with rows, count, and status
- **`Row`** — dynamic row type backed by `serde_json::Value`
- **`row!` macro** — convenient row construction: `row![("name", "Tokyo")]`
- Optional `direct-sql` feature for `PoolConfig` and direct PostgreSQL access via sqlx
- Platform abstraction layer for native and WASM targets

## Usage

```rust
use supabase_client_core::{SupabaseClient, SupabaseConfig};

let config = SupabaseConfig::new(
    "https://your-project.supabase.co",
    "your-anon-key",
);
let client = SupabaseClient::new(config)?;
```

## License

Licensed under either of [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0) or [MIT license](http://opensource.org/licenses/MIT) at your option.
