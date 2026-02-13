# supabase-client-sdk (Rust)

[![Tests](https://img.shields.io/badge/tests-390%2B%20passing-brightgreen)](#testing)
[![Rust](https://img.shields.io/badge/rust-2021%20edition-orange)](https://www.rust-lang.org/)

A Rust client for [Supabase](https://supabase.com/) with a fluent, Supabase JS-like API. Uses the **PostgREST REST API by default** — no database connection needed. Opt into direct PostgreSQL access via [sqlx](https://github.com/launchbadge/sqlx) with the `direct-sql` feature flag.

## Features

**Query Builder** - Fluent API for SELECT, INSERT, UPDATE, DELETE, and UPSERT
- 20+ filter methods (`eq`, `neq`, `gt`, `lt`, `like`, `ilike`, `in_`, `is`, `contains`, `overlaps`, `text_search`, `or_`, `not_`, ...)
- Modifiers: `order`, `limit`, `range`, `single`, `count`, `head`, `explain`
- Count options: `exact`, `planned`, `estimated` via `count_option()`
- Response format overrides: `.csv()` (returns `String`) and `.geojson()` (returns `Value`)
- Per-query `.schema()` override for multi-schema databases
- Upsert with `ignore_duplicates()` for `ON CONFLICT DO NOTHING`
- RPC/stored procedure calls with `rpc()` / `rpc_typed()`, `.rollback()` for dry-run

**Derive Macros** - `#[derive(Table)]` for type-safe queries
- Automatic table/column name mapping
- `#[primary_key]`, `#[column(name = "...")]`, `#[column(skip)]` attributes
- Auto-generate support for serial/identity columns

**Auth (GoTrue)** - HTTP client for Supabase authentication
- Email/password sign-up and sign-in (with optional captcha token)
- Phone, OAuth, magic link, OTP, anonymous auth
- Web3 wallet auth (Ethereum/Solana) via `sign_in_with_web3()`
- SSO (SAML), ID token (external OIDC), identity linking/unlinking
- Token refresh, password recovery, user management, `get_user_identities()`
- JWT claims extraction via `get_claims()` (no network call)
- Session state management: `get_session()`, `set_session()`, `on_auth_state_change()`
- Auto-refresh with configurable intervals via `start_auto_refresh()`
- Admin API (list/create/update/delete users, MFA factor management)
- MFA: TOTP enroll/challenge/verify, phone factors, AAL detection
- OAuth Server: consent management, grant listing/revocation, admin client CRUD
- OAuth Client-Side Flow: PKCE, token exchange/refresh/revoke, OIDC discovery, JWKS

**Realtime (WebSocket)** - Phoenix Channels v1.0.0 protocol
- Postgres Changes: listen for INSERT, UPDATE, DELETE events with filters
- Broadcast: send/receive ephemeral messages between clients
- Presence: track and sync online user state
- `set_auth()` to update token on existing connections
- Custom headers for WebSocket handshake via `RealtimeConfig`
- Automatic heartbeat and auto-reconnect with configurable backoff

**Storage** - HTTP client for Supabase Object Storage
- Bucket management: create, list, get, update, empty, delete
- File operations: upload, download, update, list, move, copy, remove (including cross-bucket)
- File metadata (`info`) and existence checking (`exists`)
- Signed URLs for time-limited access and delegated uploads
- Public URL construction for public buckets (with optional download disposition)
- Image transform options (resize, quality, format) on download, public URL, and signed URLs

**Edge Functions** - HTTP client for Supabase Edge Functions
- Invoke deployed Deno/TypeScript functions
- JSON, binary, and text request/response bodies
- Custom headers, authorization override, and region routing
- `set_auth()` to update default token for subsequent invocations
- Full HTTP method support (GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD)

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
supabase-client-sdk = "0.2.1"
# Or with specific features:
supabase-client-sdk = { version = "0.2.1", features = ["auth", "realtime"] }
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
| `direct-sql` | No | Direct PostgreSQL via sqlx (bypasses PostgREST) |
| `full` | No | All features enabled |

## Quick Start

```rust
use supabase_client_sdk::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SupabaseConfig::new(
        "https://your-project.supabase.co",  // or "http://localhost:64321" for local
        "your-anon-key",
    );

    let client = SupabaseClient::new(config)?; // sync — no database connection needed

    // Select all rows from a table (via PostgREST)
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

## Usage

### Query Builder

```rust
use supabase_client_sdk::prelude::*;
use serde_json::json;

// SELECT with filters and modifiers
let response = client.from("cities")
    .select("id, name, country_id")
    .eq("country_id", 1)
    .order("name", OrderDirection::Ascending)
    .limit(10)
    .execute()
    .await;
let rows = response.into_result()?;

// INSERT a single row
let response = client.from("cities")
    .insert(row![("name", "Tokyo"), ("country_id", 1)])
    .select()
    .execute()
    .await;

// INSERT multiple rows
let response = client.from("cities")
    .insert_many(vec![
        row![("name", "Tokyo"), ("country_id", 1)],
        row![("name", "Osaka"), ("country_id", 1)],
    ])
    .select()
    .execute()
    .await;

// UPDATE
let response = client.from("cities")
    .update(row![("name", "New Tokyo")])
    .eq("id", 1)
    .select()
    .execute()
    .await;

// DELETE
let response = client.from("cities")
    .delete()
    .eq("id", 1)
    .select()
    .execute()
    .await;

// UPSERT (insert or update on conflict)
let response = client.from("cities")
    .upsert(row![("id", 1), ("name", "Updated City"), ("country_id", 1)])
    .select()
    .execute()
    .await;

// UPSERT with ignore_duplicates (ON CONFLICT DO NOTHING)
let response = client.from("cities")
    .upsert(row![("name", "Existing City"), ("country_id", 1)])
    .ignore_duplicates()
    .select()
    .execute()
    .await;

// SELECT with count
let response = client.from("cities")
    .select("*")
    .count()
    .execute()
    .await;
println!("Count: {:?}", response.count);

// SELECT single row
let response = client.from("cities")
    .select("*")
    .eq("name", "Tokyo")
    .single()
    .execute()
    .await;
let city = response.into_single()?;

// RPC (stored procedures)
let response = client.rpc("get_cities_by_country", json!({"cid": 1}))?
    .execute()
    .await;

// RPC dry-run (rollback after execution)
let response = client.rpc("mutating_function", json!({"arg": 1}))?
    .rollback()
    .execute()
    .await;

// CSV response format
let csv_string: String = client.from("cities")
    .select("id, name")
    .csv()
    .execute()
    .await?;

// GeoJSON response format
let geojson: serde_json::Value = client.from("locations")
    .select("id, name, geom")
    .geojson()
    .execute()
    .await?;

// Count options (exact, planned, estimated)
let response = client.from("cities")
    .select("*")
    .count_option(CountOption::Estimated)
    .execute()
    .await;

// HEAD mode (count only, no row data)
let response = client.from("cities")
    .select("*")
    .count()
    .head()
    .execute()
    .await;
println!("Count: {:?}", response.count);

// EXPLAIN query plan
let response = client.from("cities")
    .select("*")
    .explain()
    .execute()
    .await;
```

### Derive Macros

```rust
use supabase_client_sdk::prelude::*;
use serde::Deserialize;

#[derive(Table, Deserialize, Debug)]
#[table(name = "cities")]
struct City {
    #[primary_key(auto_generate)]
    pub id: i32,
    pub name: String,
    pub country_id: i32,
}
// Note: also derive `sqlx::FromRow` when using the `direct-sql` feature

// Typed SELECT
let response = client.from_typed::<City>()
    .select()
    .eq("name", "Tokyo")
    .execute()
    .await;
let cities: Vec<City> = response.into_result()?;

// Typed RPC
let response = client.rpc_typed::<City>("get_cities_by_country", json!({"cid": 1}))?
    .execute()
    .await;
let cities: Vec<City> = response.into_result()?;
```

### Auth (GoTrue)

Requires the `auth` feature.

```rust
use supabase_client_sdk::prelude::*;

let auth = client.auth()?;

// Sign up
let response = auth.sign_up_with_email("user@example.com", "password123").await?;

// Sign in
let session = auth.sign_in_with_password_email("user@example.com", "password123").await?;
println!("Access token: {}", session.access_token);

// Get current user
let user = auth.get_user(&session.access_token).await?;

// Session state management
auth.set_session(session.clone()).await;
let current = auth.get_session().await; // Option<Session>

// Listen for auth state changes
let mut subscription = auth.on_auth_state_change();
tokio::spawn(async move {
    while let Some(change) = subscription.next().await {
        println!("Auth event: {}", change.event);
    }
});

// Auto-refresh tokens in the background
auth.start_auto_refresh();

// Extract JWT claims without a network call
let claims = AuthClient::get_claims(&session.access_token)?;
println!("User ID: {}", claims["sub"]);

// Admin operations (requires service_role key)
let admin = auth.admin();
let users = admin.list_users(None, None).await?;
```

### OAuth Server (Auth Provider)

When Supabase acts as an OAuth 2.1 identity provider, third-party apps can register as OAuth clients and users can consent/revoke access.

```rust
use supabase_client_sdk::prelude::*;

let auth = client.auth()?;

// ── Admin: OAuth Client Management (requires service_role key) ──

let admin = auth.admin();

// Create an OAuth client
let params = CreateOAuthClientParams::new("My App", vec!["https://myapp.com/callback".into()])
    .client_uri("https://myapp.com")
    .scope("openid profile");
let new_client = admin.oauth_create_client(params).await?;
println!("Client ID: {}", new_client.client_id);
println!("Secret: {:?}", new_client.client_secret);

// List, get, update, regenerate secret, delete
let clients = admin.oauth_list_clients(None, None).await?;
let fetched = admin.oauth_get_client(&new_client.client_id).await?;
let updated = admin.oauth_update_client(
    &new_client.client_id,
    UpdateOAuthClientParams::new().client_name("Updated App"),
).await?;
let refreshed = admin.oauth_regenerate_client_secret(&new_client.client_id).await?;
admin.oauth_delete_client(&new_client.client_id).await?;

// ── User: OAuth Consent & Grants (requires user JWT) ────────

let session = auth.sign_in_with_password_email("user@example.com", "pass").await?;
let token = &session.access_token;

// Get authorization details (when redirected from OAuth client)
let details = auth.oauth_get_authorization_details(token, "auth-id-123").await?;

// Approve or deny
let redirect = auth.oauth_approve_authorization(token, "auth-id-123").await?;
let redirect = auth.oauth_deny_authorization(token, "auth-id-123").await?;

// List and revoke granted permissions
let grants = auth.oauth_list_grants(token).await?;
auth.oauth_revoke_grant(token, "client-id-456").await?;
```

### OAuth Client-Side Flow (PKCE)

When using Supabase as an OAuth 2.1 identity provider, clients can use the authorization code flow with PKCE. Includes OIDC discovery and JWKS for token verification.

```rust
use supabase_client_sdk::prelude::*;

let auth = client.auth()?;

// ── PKCE Authorization Code Flow ─────────────────────────

// 1. Generate a PKCE pair (verifier + challenge)
let pkce = AuthClient::generate_pkce_pair();

// 2. Build the authorization URL
let url_params = OAuthAuthorizeUrlParams::new("client-id", "https://myapp.com/callback")
    .scope("openid profile")
    .state("random-csrf-token")
    .pkce(&pkce.challenge);
let authorize_url = auth.build_oauth_authorize_url(&url_params);
// → Redirect the user to authorize_url

// 3. After the user approves, exchange the code for tokens
let exchange_params = OAuthTokenExchangeParams::new(
    "auth-code-from-callback",
    "https://myapp.com/callback",
    "client-id",
)
.client_secret("client-secret")
.pkce_verifier(&pkce.verifier);
let tokens = auth.oauth_token_exchange(exchange_params).await?;
println!("Access token: {}", tokens.access_token);

// 4. Refresh tokens
let new_tokens = auth.oauth_token_refresh(
    "client-id",
    tokens.refresh_token.as_deref().unwrap(),
    Some("client-secret"),
).await?;

// 5. Revoke a token
auth.oauth_revoke_token(&tokens.access_token, Some("access_token")).await?;

// ── Discovery & Verification ─────────────────────────────

// Fetch OIDC configuration
let config = auth.oauth_get_openid_configuration().await?;
println!("Issuer: {}", config.issuer);
println!("Token endpoint: {}", config.token_endpoint);

// Fetch JWKS for token signature verification
let jwks = auth.oauth_get_jwks().await?;
for key in &jwks.keys {
    println!("Key: {} ({})", key.kid.as_deref().unwrap_or("?"), key.kty);
}

// Fetch user info with an access token
let userinfo = auth.oauth_get_userinfo(&tokens.access_token).await?;
println!("Subject: {}", userinfo["sub"]);
```

### Realtime (WebSocket)

Requires the `realtime` feature.

```rust
use supabase_client_sdk::prelude::*;
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
use supabase_client_sdk::prelude::*;

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

// File metadata
let info = file_api.info("photo.png").await?;
println!("Size: {:?} bytes, Type: {:?}", info.size, info.content_type);

// Check if file exists
let exists = file_api.exists("photo.png").await?;

// Image transforms (resize, quality, format)
let transform = TransformOptions::new()
    .width(200)
    .height(200)
    .resize(ResizeMode::Cover)
    .quality(80);

// Download with transform
let thumb = file_api.download_with_transform("photo.png", &transform).await?;

// Public URL with transform
let url = file_api.get_public_url_with_transform("photo.png", &transform);

// Signed URL with transform
let signed = file_api.create_signed_url_with_transform("photo.png", 3600, &transform).await?;

// Cleanup
storage.empty_bucket("photos").await?;
storage.delete_bucket("photos").await?;
```

### Edge Functions

Requires the `functions` feature.

```rust
use supabase_client_sdk::prelude::*;
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

## Examples

Runnable examples are provided in `crates/supabase-client-sdk/examples/`. Each example works against a local Supabase instance (`supabase start`).

```bash
# Query basics: SELECT, INSERT, UPDATE, DELETE, UPSERT with filters
cargo run --example query_basics -p supabase-client-sdk

# Typed queries with #[derive(Table)]
cargo run --example typed_queries -p supabase-client-sdk

# Advanced: CSV output, count options, RPC rollback, EXPLAIN, HEAD
cargo run --example advanced_queries -p supabase-client-sdk

# Authentication: sign-up, sign-in, sessions, JWT claims, admin ops
cargo run --example auth -p supabase-client-sdk --features auth

# Realtime: broadcast, postgres changes, presence
cargo run --example realtime -p supabase-client-sdk --features realtime

# Storage: bucket CRUD, upload/download, signed URLs, image transforms
cargo run --example storage -p supabase-client-sdk --features storage

# Edge Functions: JSON/binary invocation, custom headers
cargo run --example functions -p supabase-client-sdk --features functions

# Full SDK demo: all features in one example
cargo run --example full_client -p supabase-client-sdk --features full

# WASM usage from JavaScript (see example HTML file)
wasm-pack build crates/supabase-client-wasm --target web --out-dir ../../pkg
```

## Architecture

This project is a Cargo workspace with the following crates:

| Crate | Description |
|-------|-------------|
| `supabase-client-sdk` | Facade crate with feature-gated re-exports and prelude |
| `supabase-client-core` | `SupabaseClient`, `SupabaseConfig`, connection pool, error types |
| `supabase-client-query` | Query builder, filters, modifiers, RPC |
| `supabase-client-derive` | `#[derive(Table)]` proc macro |
| `supabase-client-auth` | GoTrue auth HTTP client via reqwest |
| `supabase-client-realtime` | WebSocket realtime client via tokio-tungstenite |
| `supabase-client-storage` | Object storage HTTP client via reqwest |
| `supabase-client-functions` | Edge Functions HTTP client via reqwest |
| `supabase-client-wasm` | WASM/JavaScript bindings via wasm-bindgen |

Each sub-crate provides an extension trait on `SupabaseClient`:
- `SupabaseClientQueryExt` - `.from()`, `.from_typed()`, `.rpc()`
- `SupabaseClientAuthExt` - `.auth()`
- `SupabaseClientRealtimeExt` - `.realtime()`
- `SupabaseClientStorageExt` - `.storage()`
- `SupabaseClientFunctionsExt` - `.functions()`

## WASM / JavaScript / TypeScript

All crates compile for `wasm32-unknown-unknown`. A dedicated `supabase-client-wasm` crate provides `#[wasm_bindgen]` bindings with auto-generated TypeScript declarations.

### Building the WASM package

```bash
# Install wasm-pack if you haven't already
cargo install wasm-pack

# Build for browser <script type="module"> usage
wasm-pack build crates/supabase-client-wasm --target web --out-dir ../../pkg

# Or build for bundlers (webpack, vite, etc.)
wasm-pack build crates/supabase-client-wasm --target bundler --out-dir ../../pkg
```

This generates:

```
pkg/
  supabase_client_wasm.js         # JS glue code
  supabase_client_wasm.d.ts       # TypeScript declarations
  supabase_client_wasm_bg.wasm    # WASM binary
  package.json                    # npm package metadata
```

### WASM API Reference

The WASM bindings expose a thin, JS-friendly wrapper around the full Rust SDK. Each class maps to a sub-client:

**`WasmSupabaseClient`** — main entry point

| Method | Description |
|--------|-------------|
| `new(url, key)` | Create a new client |
| `from_select(table, columns)` | SELECT query — returns JSON rows |
| `from_insert(table, data)` | INSERT a single row (JSON object) |
| `from_update(table, data, column, value)` | UPDATE rows matching `column = value` |
| `from_delete(table, column, value)` | DELETE rows matching `column = value` |
| `auth()` | Get a `WasmAuthClient` |
| `realtime()` | Get a `WasmRealtimeClient` |
| `storage()` | Get a `WasmStorageClient` |
| `functions()` | Get a `WasmFunctionsClient` |

**`WasmAuthClient`** — authentication

| Method | Description |
|--------|-------------|
| `sign_up(email, password)` | Email/password sign-up |
| `sign_in_with_password(email, password)` | Email/password sign-in — returns session JSON |
| `sign_in_anonymous()` | Anonymous sign-in — returns session JSON |
| `sign_in_with_otp(email)` | Send a magic link / OTP email |
| `get_session()` | Current session (JSON or `null`) |
| `refresh_session()` | Refresh the current session |
| `sign_out()` | Sign out the current user |
| `get_user(access_token)` | Fetch user for a given token |
| `reset_password_for_email(email)` | Send a password reset email |
| `get_oauth_url(provider)` | OAuth sign-in URL (`"github"`, `"google"`, etc.) |

**`WasmRealtimeClient`** — WebSocket realtime

| Method | Description |
|--------|-------------|
| `connect()` | Connect to the Realtime server |
| `disconnect()` | Disconnect from the Realtime server |
| `is_connected()` | Check connection status |

**`WasmStorageClient`** — object storage

| Method | Description |
|--------|-------------|
| `list_buckets()` | List all buckets — returns JSON array |
| `get_bucket(id)` | Get a bucket by ID — returns JSON object |

**`WasmFunctionsClient`** — edge functions

| Method | Description |
|--------|-------------|
| `invoke(function_name, body)` | Invoke a function with JSON body — returns JSON response |

### Usage from JavaScript/TypeScript

```typescript
import init, { WasmSupabaseClient } from './pkg/supabase_client_wasm.js';

await init();

const client = new WasmSupabaseClient(
  'https://your-project.supabase.co',
  'your-anon-key'
);

// ── Query (CRUD) ───────────────────────────────────────────
const rows = await client.from_select('cities', '*');
console.log('Cities:', rows);

await client.from_insert('cities', { name: 'Tokyo', country_id: 1 });
await client.from_update('cities', { name: 'New Tokyo' }, 'id', '1');
await client.from_delete('cities', 'id', '1');

// ── Auth ───────────────────────────────────────────────────
const auth = client.auth();

// Sign in (email/password or anonymous)
const session = await auth.sign_in_with_password('user@example.com', 'password');
console.log('Access token:', session.access_token);

const anonSession = await auth.sign_in_anonymous();

// Session management
const current = await auth.get_session();   // JSON or null
await auth.refresh_session();

// User info
const user = await auth.get_user(session.access_token);
console.log('User ID:', user.id);

// OAuth
const githubUrl = auth.get_oauth_url('github');
// → redirect the user to githubUrl

// Password reset & sign-out
await auth.reset_password_for_email('user@example.com');
await auth.sign_out();

// ── Realtime ───────────────────────────────────────────────
const realtime = client.realtime();
await realtime.connect();
console.log('Connected:', realtime.is_connected());
await realtime.disconnect();

// ── Storage ────────────────────────────────────────────────
const storage = client.storage();
const buckets = await storage.list_buckets();
const bucket = await storage.get_bucket('photos');

// ── Edge Functions ─────────────────────────────────────────
const functions = client.functions();
const result = await functions.invoke('hello', { name: 'World' });
console.log('Function result:', result);
```

> **Note:** The WASM bindings (`supabase-client-wasm`) are a thin JS-friendly wrapper that exposes a subset of the full Rust SDK through `wasm_bindgen`. If you're building a Rust application targeting WASM, you can use the full SDK directly (see below) and get access to all features, filters, modifiers, and typed queries — not just the simplified JS API.

### Using in Rust WASM projects

You can also use the SDK directly in Rust code compiled to WASM (without the JS bindings crate):

```toml
[dependencies]
supabase-client-sdk = { version = "0.2.1", features = ["full"] }
```

The platform abstraction layer automatically uses browser-compatible APIs (`fetch` via `reqwest`, `web_sys::WebSocket`, `gloo-timers`) when targeting `wasm32-unknown-unknown`.

## Configuration

```rust
// REST-only (default) — no database connection needed
let config = SupabaseConfig::new(
    "https://your-project.supabase.co",
    "your-anon-key",
)
.schema("public"); // optional, defaults to "public"
```

```rust
// With direct SQL (requires `direct-sql` feature)
let config = SupabaseConfig::new(
    "https://your-project.supabase.co",
    "your-anon-key",
)
.database_url("postgres://user:pass@host/db")
.max_connections(10)
.min_connections(1);

let client = SupabaseClient::with_database(config).await?;
```

- `supabase_url` - Supabase project URL (required)
- `supabase_key` - Supabase anon or service_role key (required)
- `database_url` - PostgreSQL connection string (optional, requires `direct-sql` feature)

## Testing

Tests require a local Supabase instance:

```bash
# Start local Supabase (from project root)
supabase start

# Run all tests (use --test-threads=1 to avoid race conditions)
cargo test --workspace -- --test-threads=1

# REST integration tests (PostgREST backend, default)
cargo test -p supabase-client-query --test rest_integration -- --test-threads=1

# Direct-SQL integration tests (requires direct-sql feature)
cargo test -p supabase-client-sdk --features direct-sql -- --test-threads=1

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
- Local Supabase CLI (for integration tests)
- PostgreSQL via sqlx 0.8 (only when using the `direct-sql` feature)

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
