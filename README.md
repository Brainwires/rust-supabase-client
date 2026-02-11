# supabase-client

A Rust crate wrapping [sqlx](https://github.com/launchbadge/sqlx) with a Supabase-like fluent API for PostgreSQL.

> **This is NOT a REST API wrapper.** It generates SQL directly via sqlx, giving you compile-time safety, connection pooling, and the full power of Postgres while using a familiar Supabase-style builder API.

## Features

**Query Builder** - Fluent API for SELECT, INSERT, UPDATE, DELETE, and UPSERT
- 20+ filter methods (`eq`, `neq`, `gt`, `lt`, `like`, `ilike`, `in_`, `is`, `contains`, `overlaps`, `text_search`, `or_`, `not_`, ...)
- Modifiers: `order`, `limit`, `range`, `single`, `count`
- RPC/stored procedure calls with `rpc()` / `rpc_typed()`

**Derive Macros** - `#[derive(Table)]` for type-safe queries
- Automatic table/column name mapping
- `#[primary_key]`, `#[column(name = "...")]`, `#[column(skip)]` attributes
- Auto-generate support for serial/identity columns

**Auth (GoTrue)** - HTTP client for Supabase authentication
- Email/password sign-up and sign-in
- Phone, OAuth, magic link, OTP, anonymous auth
- Token refresh, password recovery, user management
- Admin API (list/create/update/delete users)

**Realtime (WebSocket)** - Phoenix Channels v1.0.0 protocol
- Postgres Changes: listen for INSERT, UPDATE, DELETE events with filters
- Broadcast: send/receive ephemeral messages between clients
- Presence: track and sync online user state
- Automatic heartbeat and reconnection with exponential backoff

**Storage** - HTTP client for Supabase Object Storage
- Bucket management: create, list, get, update, empty, delete
- File operations: upload, download, update, list, move, copy, remove
- Signed URLs for time-limited access and delegated uploads
- Public URL construction for public buckets

**Edge Functions** - HTTP client for Supabase Edge Functions
- Invoke deployed Deno/TypeScript functions
- JSON, binary, and text request/response bodies
- Custom headers, authorization override, and region routing
- Full HTTP method support (GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD)

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
supabase-client = { path = "crates/supabase-client" }
# Or with specific features:
supabase-client = { path = "crates/supabase-client", features = ["auth", "realtime"] }
```

### Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `query` | Yes | Query builder (select, insert, update, delete, upsert, rpc) |
| `derive` | Yes | `#[derive(Table)]` proc macro |
| `auth` | No | GoTrue authentication client |
| `realtime` | No | WebSocket realtime subscriptions |
| `storage` | No | Object storage client |
| `functions` | No | Edge Functions client |
| `full` | No | All features enabled |

## Quick Start

```rust
use supabase_client::prelude::*;

#[tokio::main]
async fn main() -> Result<(), SupabaseError> {
    let config = SupabaseConfig::new("postgres://user:pass@localhost/mydb")
        .supabase_url("http://localhost:54321")
        .supabase_key("your-anon-key");

    let client = SupabaseClient::new(config).await?;

    // Select all rows from a table
    let response = client.from("cities")
        .select("*")
        .execute()
        .await?;

    println!("Cities: {:?}", response.data);
    Ok(())
}
```

## Usage

### Query Builder

```rust
use supabase_client::prelude::*;

// SELECT with filters and modifiers
let response = client.from("cities")
    .select("id, name, country_id")
    .eq("country_id", 1)
    .order("name", OrderDirection::Asc)
    .limit(10)
    .execute()
    .await?;

// INSERT
let response = client.from("cities")
    .insert(vec![
        row! { "name" => "Tokyo", "country_id" => 1 },
        row! { "name" => "Osaka", "country_id" => 1 },
    ])
    .execute()
    .await?;

// UPDATE
let response = client.from("cities")
    .update(row! { "name" => "New Tokyo" })
    .eq("id", 1)
    .execute()
    .await?;

// DELETE
let response = client.from("cities")
    .delete()
    .eq("id", 1)
    .execute()
    .await?;

// UPSERT (insert or update on conflict)
let response = client.from("cities")
    .upsert(vec![
        row! { "id" => 1, "name" => "Updated City", "country_id" => 1 },
    ])
    .execute()
    .await?;

// RPC (stored procedures)
let response = client.rpc("get_cities_by_country", serde_json::json!({"cid": 1}))?
    .execute()
    .await?;
```

### Derive Macros

```rust
use supabase_client::prelude::*;

#[derive(Table, sqlx::FromRow, Debug)]
#[table(name = "cities")]
struct City {
    #[primary_key(auto_generate)]
    pub id: i32,
    pub name: String,
    pub country_id: i32,
}

// Typed SELECT
let response = client.from_typed::<City>()
    .select()
    .eq("name", "Tokyo")
    .execute()
    .await?;

let cities: Vec<City> = response.data;

// Typed INSERT
let city = City { id: 0, name: "Berlin".into(), country_id: 2 };
let response = client.from_typed::<City>()
    .insert(vec![city])
    .execute()
    .await?;
```

### Auth (GoTrue)

Requires the `auth` feature.

```rust
use supabase_client::prelude::*;

let auth = client.auth()?;

// Sign up
let response = auth.sign_up_with_email("user@example.com", "password123").await?;

// Sign in
let session = auth.sign_in_with_password_email("user@example.com", "password123").await?;
println!("Access token: {}", session.access_token);

// Get current user
let user = auth.get_user(&session.access_token).await?;

// Admin operations (requires service_role key)
let admin = auth.admin();
let users = admin.list_users(None, None).await?;
```

### Realtime (WebSocket)

Requires the `realtime` feature.

```rust
use supabase_client::prelude::*;
use serde_json::json;

let realtime = client.realtime()?;
realtime.connect().await?;

// Listen for database changes
let channel = realtime.channel("db-changes")
    .on_postgres_changes(
        PostgresChangesEvent::Insert,
        PostgresChangesFilter::new("public", "messages"),
        |payload| println!("New row: {:?}", payload.record),
    )
    .subscribe(|status, _err| {
        println!("Status: {status}");
    })
    .await?;

// Broadcast messages between clients
let chat = realtime.channel("chat-room")
    .on_broadcast("new-message", |payload| {
        println!("Message: {payload}");
    })
    .broadcast_self(true)
    .subscribe(|_, _| {})
    .await?;

chat.send_broadcast("new-message", json!({"text": "hello"})).await?;

// Presence tracking
let room = realtime.channel("room-1")
    .on_presence_sync(|state| println!("State: {state:?}"))
    .on_presence_join(|key, metas| println!("{key} joined: {metas:?}"))
    .on_presence_leave(|key, metas| println!("{key} left: {metas:?}"))
    .subscribe(|_, _| {})
    .await?;

room.track(json!({"user": "alice", "online_at": "2024-01-01"})).await?;

// Cleanup
realtime.remove_all_channels().await?;
realtime.disconnect().await?;
```

### Storage

Requires the `storage` feature.

```rust
use supabase_client::prelude::*;

let storage = client.storage()?;

// Bucket management
storage.create_bucket("photos", BucketOptions::new().public(true)).await?;
let buckets = storage.list_buckets().await?;

// File operations via .from("bucket")
let file_api = storage.from("photos");

// Upload
let data = std::fs::read("photo.png")?;
file_api.upload("folder/photo.png", data, FileOptions::new()
    .content_type("image/png")
    .upsert(true)
).await?;

// Download
let bytes = file_api.download("folder/photo.png").await?;

// List files
let files = file_api.list(Some("folder"), Some(SearchOptions::new()
    .limit(100)
    .sort_by("name", SortOrder::Asc)
)).await?;

// Move, copy, remove
file_api.move_file("old.png", "new.png").await?;
file_api.copy("original.png", "backup.png").await?;
file_api.remove(vec!["old.png"]).await?;

// Signed URLs (time-limited access)
let signed = file_api.create_signed_url("photo.png", 3600).await?;
println!("Signed URL: {}", signed.signed_url);

// Public URL (no HTTP call)
let public_url = file_api.get_public_url("photo.png");

// Cleanup
storage.empty_bucket("photos").await?;
storage.delete_bucket("photos").await?;
```

### Edge Functions

Requires the `functions` feature.

```rust
use supabase_client::prelude::*;
use serde_json::json;

let functions = client.functions()?;

// Basic JSON invocation (default: POST)
let response = functions.invoke("hello", InvokeOptions::new()
    .body(json!({"name": "World"}))
).await?;
let data: serde_json::Value = response.json()?;

// GET request
let response = functions.invoke("get-data", InvokeOptions::new()
    .method(HttpMethod::Get)
).await?;

// Custom headers + region
let response = functions.invoke("hello", InvokeOptions::new()
    .body(json!({"name": "World"}))
    .header("x-custom", "value")
    .region(FunctionRegion::UsEast1)
).await?;

// Binary body/response
let response = functions.invoke("process", InvokeOptions::new()
    .body_bytes(raw_bytes)
).await?;
let output = response.bytes();

// Override authorization (e.g., user JWT)
let response = functions.invoke("protected", InvokeOptions::new()
    .authorization(format!("Bearer {}", user_jwt))
).await?;

// Response accessors
response.status();           // u16
response.json::<T>()?;       // deserialize JSON
response.text()?;            // UTF-8 string
response.bytes();            // &[u8]
response.content_type();     // Option<&str>
response.header("x-foo");   // case-insensitive lookup
```

## Architecture

This project is a Cargo workspace with the following crates:

| Crate | Description |
|-------|-------------|
| `supabase-client` | Facade crate with feature-gated re-exports and prelude |
| `supabase-client-core` | `SupabaseClient`, `SupabaseConfig`, connection pool, error types |
| `supabase-client-query` | Query builder, filters, modifiers, RPC |
| `supabase-client-derive` | `#[derive(Table)]` proc macro |
| `supabase-client-auth` | GoTrue auth HTTP client via reqwest |
| `supabase-client-realtime` | WebSocket realtime client via tokio-tungstenite |
| `supabase-client-storage` | Object storage HTTP client via reqwest |
| `supabase-client-functions` | Edge Functions HTTP client via reqwest |

Each sub-crate provides an extension trait on `SupabaseClient`:
- `SupabaseClientQueryExt` - `.from()`, `.from_typed()`, `.rpc()`
- `SupabaseClientAuthExt` - `.auth()`
- `SupabaseClientRealtimeExt` - `.realtime()`
- `SupabaseClientStorageExt` - `.storage()`
- `SupabaseClientFunctionsExt` - `.functions()`

## Configuration

```rust
let config = SupabaseConfig::new("postgres://user:pass@host/db")
    .supabase_url("https://your-project.supabase.co")  // Required for auth/realtime/storage
    .supabase_key("your-anon-key")                      // Required for auth/realtime/storage
    .schema("public")                                    // Default schema
    .max_connections(10)                                 // Connection pool max
    .min_connections(1);                                 // Connection pool min
```

- `database_url` - PostgreSQL connection string (required for queries)
- `supabase_url` - Supabase project URL (required for auth, realtime, storage, functions)
- `supabase_key` - Supabase anon or service_role key (required for auth, realtime, storage, functions)

## Testing

Tests require a local Supabase instance:

```bash
# Start local Supabase (from project root)
supabase start

# Run all tests (use --test-threads=1 to avoid race conditions)
cargo test --workspace -- --test-threads=1

# Run tests for a specific crate
cargo test -p supabase-client-query
cargo test -p supabase-client-auth
cargo test -p supabase-client-realtime
cargo test -p supabase-client-storage --test integration -- --test-threads=1
cargo test -p supabase-client-functions --test integration -- --test-threads=1
```

The local Supabase instance runs on custom ports (API: 64321, DB: 64322). Integration tests default to these ports and use hardcoded local development keys.

Set `SKIP_REALTIME_TESTS=1` to skip realtime integration tests if the local instance isn't running.

## Requirements

- Rust 1.75+
- PostgreSQL (via sqlx 0.8)
- Local Supabase CLI (for integration tests)

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
