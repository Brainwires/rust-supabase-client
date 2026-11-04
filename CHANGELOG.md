# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - Unreleased

Security and correctness release. It contains breaking changes; see
"Breaking changes" below.

<!-- Entries for the query, graphql, realtime, derive and wasm crates are
     added when that work is merged. -->

### Security

- **Storage, auth admin and functions: path traversal / query injection
  with the service-role key.** Bucket ids, object paths, user/factor/client/
  identity/authorization ids and function names were spliced into URLs, and
  `..` segments and `?` were honoured. For example
  `admin().delete_user("../../../../rest/v1/profiles?id=not.is.null")` sent a
  mass `DELETE` to PostgREST with the service-role bearer. Every URL is now
  built one percent-encoded segment at a time; empty, `.` and `..` segments
  are rejected (`StorageError::InvalidPath`, `AuthError::InvalidInput`,
  `FunctionsError::InvalidFunctionName`), and query strings never come from
  interpolated input.
- **Secrets in `Debug` output.** `StorageClient`, `StorageBucketApi`,
  `FunctionsClient` (including the `set_auth` JWT), `InvokeOptions` and
  `AdminClient` printed the API key or tokens. They now have redacting
  `Debug` impls, and `apikey`/`Authorization` header values are marked
  sensitive.
- The `upload_to_signed_url` token is query-encoded and transport errors
  from that call no longer include the URL (and so the token).
- Error bodies are read up to 64 KiB; downloads and function responses can
  be capped (`with_max_download_size`, `with_max_response_size`) and given a
  total timeout (`with_timeout`).
- wasm32: `SupabaseClient::new` refuses a `service_role` JWT or `sb_secret_`
  key unless `SupabaseConfig::allow_privileged_key_on_wasm(true)` is set;
  sub-clients built directly log a warning.

### Fixed

- Auth sign-up returned and stored no session: GoTrue `/signup` answers with
  the session at the top level (autoconfirm) or a bare user (confirmation
  required). `AuthResponse` now deserializes both shapes.
- Auto-refresh could bring a session back after sign-out. Refreshes are
  single-flight (shared by the background task, `refresh_current_session`
  and `refresh_session` with the stored token) and the result is written
  back only if the stored refresh token is still the one used.
- The auto-refresh task outlived the client (it held a strong reference). It
  now holds a `Weak` reference and is aborted on drop; start/stop no longer
  drop the handle on lock contention. Sign-out stops the task; the next
  sign-in resumes it.
- Auto-refresh failures never wipe a newer session, and an invalid refresh
  token is not retried. Refresh errors keep GoTrue's message and
  `error_code`.
- `sign_out(SignOutScope::Others)` cleared the local session; it no longer
  does. A 401/403/404 from `/logout` now clears the local session (as
  supabase-js does) instead of leaving a stale one.
- Sessions without `expires_at` never refreshed; it is now filled from
  `expires_in`.
- `redirect_to` was ignored by `reset_password_for_email` and
  `admin().invite_user_by_email`; it is sent as a query parameter.
- Storage `x-metadata` is sent base64-encoded, as the storage server
  expects.
- Storage public/download URLs percent-encode path segments and
  form-encode the `download` filename.
- `StorageApiErrorResponse.status_code` and `GoTrueErrorResponse.code`
  accept a string or a number.
- `FunctionsClient::set_auth` no longer panics on a poisoned lock.
- `#[derive(Table)]` works when only `supabase-client-sdk` is a dependency
  (the sdk re-exports the query crate as a hidden `__query` path).

### Added

- Issue #6: the signed-in user's JWT is used everywhere. `SupabaseClient`
  owns a shared `AccessToken` slot (`set_access_token`,
  `clear_access_token`, `access_token`, `bearer_token`); `client.auth()`
  keeps it in sync with the session, and storage, functions, query,
  GraphQL and realtime clients created from the same `SupabaseClient` send
  it as `Authorization: Bearer` with the API key as `apikey`.
  `StorageClient::set_auth`/`clear_auth`, `FunctionsClient::clear_auth`,
  `AuthClient::with_token_sink`, `with_session_token` on storage/functions.
- Issue #5: `rustls` (default) and `native-tls` features on the sdk and
  every HTTP crate. `default-features = false, features = [..., "native-tls"]`
  builds without rustls; the default build needs no OpenSSL.
- `AuthClient::is_auto_refresh_running`, `GoTrueErrorResponse::code_str`,
  `StorageApiErrorResponse::status_code_str`.
- `compile_error!` for the `direct-sql` feature on wasm32.
- LICENSE-MIT and LICENSE-APACHE in every published crate; docs.rs builds
  with all features.
- CI: fmt, clippy `-D warnings` on all targets and features, unit tests and
  doctests with `--locked`, MSRV, feature matrix, wasm32, cargo-deny.

### Changed

- Dependencies (based on community PR #4 by getong): reqwest 0.12 -> 0.13
  (default features off, TLS chosen by our features), tokio-tungstenite
  0.26 -> 0.30, gloo-timers 0.3 -> 0.4, getrandom 0.3 -> 0.4, sha2 0.10 ->
  0.11, rand 0.9 -> 0.10, totp-rs (dev) 5 -> 6, serial_test (dev) 3 -> 4.
- TLS: the `rustls` backend now uses aws-lc-rs, and sqlx (with `direct-sql`)
  follows it (`tls-rustls-aws-lc-rs`), so one crypto provider is compiled in.
  Building aws-lc-sys needs a C compiler, and CMake on targets without
  pre-generated bindings and for FIPS builds; use `native-tls` to avoid it.
  Certificates are verified against the **OS trust store**
  (rustls-platform-verifier) instead of the bundled webpki roots; minimal
  containers need a CA bundle (e.g. the `ca-certificates` package).
- MSRV is now Rust 1.89 (was declared as 1.75, which the tree no longer
  built with).
- Earlier, unreleased on crates.io: `SupabaseClient::new` validates the key
  and returns errors instead of panicking (#7); PostgREST URL building,
  header handling, timeouts and `Debug` redaction hardening (#9); the
  `Table` trait no longer requires `sqlx::FromRow` (460e189).

### Breaking changes

- `Table` no longer has a `sqlx::FromRow` supertrait (460e189).
- New error variants: `StorageError::{InvalidPath, ResponseTooLarge}`,
  `FunctionsError::{InvalidFunctionName, ResponseTooLarge}`,
  `AuthError::InvalidInput`.
- `StorageApiErrorResponse.status_code` is `Option<serde_json::Value>` (was
  `Option<String>`); `GoTrueErrorResponse.code` is
  `Option<serde_json::Value>` (was `Option<i32>`).
- `AuthResponse` deserializes GoTrue's real shapes; it no longer derives
  `Deserialize` with `#[serde(default)]` fields.
- `sign_out*` return `Ok(())` on 401/403/404 and clear the local session;
  `SignOutScope::Others` keeps it.
- Storage object paths and bucket ids, auth ids and function names with
  empty, `.` or `..` segments are rejected; `/` inside an auth id is
  encoded instead of creating new path segments.
- `SupabaseConfig` has a new public field, `allow_privileged_key_on_wasm`.
- wasm32: a privileged key is refused by `SupabaseClient::new`.
- Internal crates depend on each other with `default-features = false`;
  crates that make HTTP requests gained a default `rustls` feature. If you
  depend on a sub-crate with `default-features = false`, enable `rustls`
  or `native-tls`.
- Workspace-level `reqwest` no longer enables reqwest's default features.

## [0.2.2] - 2026-02-17

### Added

- `supabase-client-graphql` crate for `pg_graphql`: query and mutation
  builders, filters, Relay-style connections, `SupabaseClientGraphqlExt`.
- Wiremock-based tests across all crates and WASM Node.js integration tests.
- Code coverage via cargo-llvm-cov (`make coverage`).

### Changed

- Integration tests run serially (`serial_test`).

## [0.2.1] - 2026-02-12

### Added

- Per-crate `README.md` files for all 9 workspace crates so each crate page on crates.io has documentation
- `readme = "README.md"` field in all crate `Cargo.toml` files

### Changed

- Renamed `crates/supabase-client/` directory to `crates/supabase-client-sdk/` to match the published crate name

## [0.2.0] - 2026-02-12

### Added

#### WASM / JavaScript Support
- Full `wasm32-unknown-unknown` compatibility across all crates
- New `supabase-client-wasm` crate with `#[wasm_bindgen]` bindings and auto-generated TypeScript declarations
- `WasmSupabaseClient` with CRUD query methods (`from_select`, `from_insert`, `from_update`, `from_delete`)
- `WasmAuthClient` with sign-up, sign-in (password, anonymous, OTP), session management, OAuth URL generation, and password reset
- `WasmRealtimeClient` with connect/disconnect/status
- `WasmStorageClient` with bucket listing and retrieval
- `WasmFunctionsClient` for edge function invocation
- Platform abstraction layer (`platform` module in core) for task spawning and sleeping across native/WASM
- Unified WebSocket transport layer for both native and WASM environments
- Conditional dependency compilation for WASM targets across all crates

#### Query Builder
- GeoJSON response format via `.geojson()` on SELECT queries (`GeoJsonSelectBuilder`)
- Schema override on DELETE, INSERT, UPDATE, and UPSERT builders
- `ExplainOptions` and `ExplainFormat` for SELECT query plan introspection
- HEAD mode (`.head()`) for count-only queries without row data
- `ignore_duplicates()` on UPSERT for `ON CONFLICT DO NOTHING` behavior
- `count_option()` with exact, planned, and estimated modes
- REST and Direct-SQL dual-backend execution (`QueryBackend`)
- `from_typed::<T>()` and `rpc_typed::<T>()` for derive-macro-based typed queries

#### Auth (GoTrue)
- Multi-Factor Authentication (MFA): TOTP enroll/challenge/verify, phone factors, AAL detection
- OAuth server support: client CRUD, consent management, grant listing/revocation
- OAuth client-side flow: PKCE pair generation, authorization code exchange, token refresh/revoke
- OIDC discovery and JWKS endpoints for token verification
- SSO (SAML) and ID token (external OIDC) sign-in
- Web3 wallet auth (Ethereum/Solana) via `sign_in_with_web3()`
- Identity linking/unlinking and `get_user_identities()`
- `get_claims()` for JWT claims extraction without a network call
- Session state management: `get_session()`, `set_session()`, `on_auth_state_change()`
- Auto-refresh with configurable intervals via `start_auto_refresh()`
- Admin API: list/create/update/delete users, MFA factor management
- Manual linking and MFA configuration support

#### Realtime (WebSocket)
- Phoenix Channels v1.0.0 protocol implementation
- Postgres Changes: listen for INSERT, UPDATE, DELETE events with filters
- Broadcast: send/receive ephemeral messages between clients
- Presence: track and sync online user state
- `set_auth()` to update token on existing connections
- Custom headers for WebSocket handshake via `RealtimeConfig`
- Automatic heartbeat and auto-reconnect with configurable backoff
- Warm-up function for Supabase Realtime WAL listener in integration tests

#### Storage
- Full bucket management: create, list, get, update, empty, delete
- File operations: upload, download, update, list, move, copy, remove
- Cross-bucket move and copy via `move_to_bucket()` and `copy_to_bucket()`
- File metadata (`info`) and existence checking (`exists`)
- Signed URLs for time-limited access and delegated uploads
- Public URL construction with optional download disposition
- Image transform options (resize, quality, format) on download, public URL, and signed URLs

#### Edge Functions
- `FunctionsClient` for invoking Supabase Edge Functions
- JSON, binary, and text request/response bodies
- Custom headers, authorization override, and region routing
- `set_auth()` to update default token for subsequent invocations
- Full HTTP method support (GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD)

#### Derive Macros
- `#[derive(Table)]` for type-safe queries
- Automatic table/column name mapping
- `#[primary_key]`, `#[column(name = "...")]`, `#[column(skip)]` attributes
- Auto-generate support for serial/identity columns

#### Examples & Documentation
- `query_basics` — SELECT, INSERT, UPDATE, DELETE, UPSERT with filters
- `typed_queries` — derive macro usage with `from_typed`
- `advanced_queries` — CSV output, count options, RPC rollback, EXPLAIN, HEAD
- `auth` — sign-up, sign-in, sessions, JWT claims, admin operations
- `realtime` — broadcast, postgres changes, presence
- `storage` — bucket CRUD, upload/download, signed URLs, image transforms
- `functions` — JSON/binary invocation, custom headers
- `full_client` — all features combined in a single example
- `wasm_usage.html` — interactive HTML/JS reference for WASM bindings
- WASM API reference tables in README
- Comprehensive README with usage examples for all features

### Changed

- **Package rename**: `supabase-client` renamed to `supabase-client-sdk` (facade crate)
- Query execution refactored to support pluggable REST and Direct-SQL backends
- PostgREST request handling refactored to compose Prefer headers for count and return options
- Realtime and Storage client initialization simplified via `SupabaseClient` extension methods
- Dependency structure refactored for WASM compatibility (conditional native/WASM deps)

## [0.1.0] - Initial Release

- Core `SupabaseClient` and `SupabaseConfig`
- Basic query builder (SELECT, INSERT, UPDATE, DELETE)
- Filter methods and modifiers
- Workspace structure with modular crates
