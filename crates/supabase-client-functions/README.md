# supabase-client-functions

Edge Functions client for supabase-client.

> **Note:** This crate is part of the [`supabase-client-sdk`](https://crates.io/crates/supabase-client-sdk) workspace. Most users should depend on `supabase-client-sdk` with the `functions` feature rather than using this crate directly.

## Key Features

- **`SupabaseClientFunctionsExt`** extension trait — adds `.functions()` to `SupabaseClient`
- **`FunctionsClient`** — HTTP client for invoking Supabase Edge Functions (Deno/TypeScript)
- JSON, binary, and text request/response bodies
- Custom headers, authorization override, and region routing
- `set_auth()` to update default token for subsequent invocations
- Full HTTP method support (GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD)

## Usage

```rust
use supabase_client_functions::SupabaseClientFunctionsExt;
use supabase_client_functions::InvokeOptions;
use serde_json::json;

let functions = client.functions()?;

let response = functions.invoke("hello", InvokeOptions::new()
    .body(json!({"name": "World"}))
).await?;
let data: serde_json::Value = response.json()?;
```

## License

Licensed under either of [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0) or [MIT license](http://opensource.org/licenses/MIT) at your option.
