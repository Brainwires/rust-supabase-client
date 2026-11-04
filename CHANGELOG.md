# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-11-03

Security and correctness release. Users of 0.2.x should upgrade: see
"Security" below. It contains breaking changes; see "Breaking changes".

### Security

- **Storage, auth admin and functions: path traversal / query injection
  carrying the service-role key.** Bucket ids, object paths, user/factor/
  client/identity/authorization ids and function names were spliced into
  URLs, and `..` segments and `?` were honoured. For example
  `admin().delete_user("../../../../rest/v1/profiles?id=not.is.null")` sent a
  mass `DELETE` to PostgREST with the service-role bearer. Every URL is now
  built one percent-encoded segment at a time; empty, `.` and `..` segments
  are rejected (`StorageError::InvalidPath`, `AuthError::InvalidInput`,
  `FunctionsError::InvalidFunctionName`), and query strings never come from
  interpolated input.
- **Query: invalid filters were silently dropped, which could turn an
  update or delete into a whole-table operation.** A filter or order method
  whose column name failed validation logged a warning and returned the
  builder unchanged, so `delete().eq("id\"", 42)` sent an unfiltered
  `DELETE` (likewise `update`, and filters inside `not`/`or_filter`/
  `match_filter`). Invalid filters are now recorded and the request is
  refused with an error. A typed `update()` on a table without a primary
  key is an error instead of an `UPDATE` with no `WHERE`.
- **Direct-SQL injection.** The text-search config, `ON CONFLICT` columns
  and constraint, and select/returning lists were interpolated into SQL.
  They are now validated and quoted (text-search config as
  `'cfg'::regconfig`; columns as `*` or plain / double-quoted identifiers).
- **GraphQL injection.** Collection names, field names, object keys,
  filter and orderBy columns were spliced into the query, so a crafted key
  could add a second mutation (e.g. a `deleteFrom...`). All names must
  match `^[_A-Za-z][_0-9A-Za-z]*$` (`GraphqlError::InvalidInput`), strings
  are always quoted and escaped, and enum values come only from typed
  enums, so a value like `"NULL"` stays a string.
- **Private realtime channels joined as public.** `ChannelBuilder::private()`
  did not send `config.private = true`, so the channel joined as a public
  one and Realtime Authorization (RLS on `realtime.messages`) was not
  applied. It is now sent.
- **Secrets in `Debug` output.** `StorageClient`, `StorageBucketApi`,
  `FunctionsClient` (including the `set_auth` JWT), `InvokeOptions`,
  `AdminClient` and `GraphqlClient` printed the API key or tokens. They now
  have redacting `Debug` impls, and `apikey`/`Authorization` header values
  are marked sensitive.
- The `upload_to_signed_url` token is query-encoded and transport errors
  from that call no longer include the URL (and so the token).
- Error bodies are read up to 64 KiB; downloads and function responses can
  be capped (`with_max_download_size`, `with_max_response_size`) and given a
  total timeout (`with_timeout`).
- wasm32: `SupabaseClient::new` refuses a `service_role` JWT or `sb_secret_`
  key; `SupabaseClient::new_allowing_privileged_key` opts out (for wasm32
  builds that never run in a browser); sub-clients built directly log a
  warning.

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
- Query: text-array elements are backslash-escaped in PostgREST values;
  column names inside `or=()`/`and=()` trees are quoted; the `Range` header
  uses checked arithmetic, is omitted for `limit(0)` and rejects negative
  values; RPC `POST` sends `Content-Profile`; `rollback()` sends
  `tx=rollback,handling=strict` (direct-SQL: runs in `BEGIN ... ROLLBACK`);
  typed `upsert()` no longer sends an insertable primary key twice;
  direct-SQL `count=exact` returns the window count and strips `__count`
  from rows (plain counted selects only).
- GraphQL: an empty or non-ASCII collection name no longer panics, and
  `errors` returned next to `data` are no longer dropped.
- Realtime: rejoining after a reconnect works (every join stores the new
  `join_ref`, registers the reply and rebuilds the postgres_changes id map;
  only channels joined on an older connection are rejoined, with the latest
  access token). postgres_changes events only reach their own bindings.
- Realtime: heartbeat tasks are tied to their connection and aborted on
  reconnect; a heartbeat still unacknowledged at the next tick drops the
  connection so it reconnects. Pong, binary and raw frames no longer end
  the stream.
- Realtime: a failed join unregisters the channel; `unsubscribe` closes and
  unregisters it; channels hold a weak client reference (no `Arc` cycle);
  `connect()` while connected or reconnecting is a no-op; connects are
  bounded by `RealtimeConfig::connect_timeout` (default 10 s); the wasm
  transport closes the socket on an open error or timeout.
- Realtime no longer panics with "Could not automatically determine the
  process-level CryptoProvider" when the application links more than one
  rustls crypto backend: `wss://` uses an explicit rustls config (the
  installed process provider, else aws-lc-rs).
- wasm bindings: results arrive as plain JS objects (not `Map`s) with 64-bit
  integers as numbers; a panic hook is installed by `new
  WasmSupabaseClient()` (and exported as `init_panic_hook()`).
- `#[derive(Table)]` works when only `supabase-client-sdk` is a dependency
  (the macro finds the query crate with proc-macro-crate, falling back to
  the sdk's hidden `__query` re-export).

### Added

- Issue #6: the signed-in user's JWT is used everywhere. `SupabaseClient`
  owns a shared `AccessToken` slot (`set_access_token`,
  `clear_access_token`, `access_token`, `bearer_token`,
  `access_token_handle`); `client.auth()` keeps it in sync with the session
  (sign-in, refresh, sign-out). Query, storage, functions, GraphQL and
  realtime clients created from the same `SupabaseClient` send it as
  `Authorization: Bearer <jwt>`, with the API key still in `apikey`; after
  sign-out they fall back to the API key. Realtime channels join with it
  and a refreshed token is pushed to joined channels on the next heartbeat.
  Lower-level APIs: `.access_token(jwt)` on `QueryBuilder`,
  `TypedQueryBuilder`, `RpcBuilder` and `TypedRpcBuilder`;
  `QueryBackend::with_access_token`/`set_access_token`;
  `with_session_token` on the storage, functions, GraphQL and realtime
  clients; `StorageClient::set_auth`/`clear_auth`,
  `FunctionsClient::clear_auth`, `GraphqlClient::clear_auth`;
  `AuthClient::with_token_sink`; `RealtimeClient::set_auth` now stores the
  token (also while disconnected); wasm `WasmSupabaseClient::set_access_token`
  and `WasmRealtimeClient::set_auth`.
- Issue #5: `rustls` (default) and `native-tls` features on the sdk and
  every crate that makes HTTP or WebSocket connections.
  `default-features = false, features = [..., "native-tls"]` builds without
  rustls, ring or aws-lc; the default build needs no OpenSSL.
- `JoinConfig::private` / `ChannelBuilder::private()` for private realtime
  channels; `RealtimeConfig::connect_timeout`.
- `AuthClient::is_auto_refresh_running`, `GoTrueErrorResponse::code_str`,
  `StorageApiErrorResponse::status_code_str`.
- `compile_error!` for the `direct-sql` feature on wasm32.
- LICENSE-MIT and LICENSE-APACHE in every published crate; docs.rs builds
  with all features.
- CI: fmt, clippy `-D warnings` on all targets and features, unit, offline
  integration and doc tests with `--locked`, MSRV, feature matrix, wasm32,
  cargo-deny.

### Changed

- Dependencies, based on community PR #4 by getong (thanks!): reqwest
  0.12 -> 0.13 (default features off, TLS chosen by our features),
  tokio-tungstenite 0.26 -> 0.30, gloo-timers 0.3 -> 0.4, getrandom 0.3 ->
  0.4, sha2 0.10 -> 0.11, rand 0.9 -> 0.10, totp-rs (dev) 5 -> 6,
  serial_test (dev) 3 -> 4. New: proc-macro-crate (derive),
  console_error_panic_hook (wasm), rustls + rustls-platform-verifier
  (realtime, `rustls` feature only).
- TLS: the `rustls` backend uses aws-lc-rs everywhere: reqwest, realtime
  `wss://`, and sqlx with `direct-sql` (`tls-rustls-aws-lc-rs`), so one
  crypto provider is compiled in (no ring). Building aws-lc-sys needs a C
  compiler, and CMake on targets without pre-generated bindings and for
  FIPS builds; use `native-tls` to avoid it.
- TLS trust store: HTTP and realtime certificates are verified against the
  **OS trust store** (rustls-platform-verifier) instead of the bundled
  webpki roots; minimal containers need a CA bundle (e.g. the
  `ca-certificates` package). sqlx (`direct-sql`) keeps its own
  webpki roots.
- MSRV is now Rust 1.89 (was declared as 1.75, which the tree no longer
  built with).
- Earlier, unreleased on crates.io: `SupabaseClient::new` validates the key
  and returns errors instead of panicking (#7); PostgREST URL building,
  header handling, timeouts and `Debug` redaction hardening (#9); the
  `Table` trait no longer requires `sqlx::FromRow` (460e189).

### Breaking changes

- Invalid filter or order columns make the request fail (error response)
  instead of being skipped; `FilterCondition` has a new `Invalid` variant.
  Typed `update()` on a table without a primary key returns an error.
- `QueryBackend::Rest` has a new `access_token` field (struct literals need
  it; use `None` or `with_access_token`).
- GraphQL: `QueryBuilder::build` and `MutationBuilder::build` return
  `Result<(String, Value), GraphqlError>`; names that are not GraphQL
  identifiers are rejected with the new `GraphqlError::InvalidInput`.
- Realtime: `JoinConfig` has a new `private` field and `RealtimeConfig` a
  new `connect_timeout` field (struct literals need them); `set_auth` no
  longer errors while disconnected; `unsubscribe` removes the channel from
  the client.
- `Table` no longer has a `sqlx::FromRow` supertrait (460e189).
- New error variants: `StorageError::{InvalidPath, ResponseTooLarge}`,
  `FunctionsError::{InvalidFunctionName, ResponseTooLarge}`,
  `AuthError::InvalidInput`, `GraphqlError::InvalidInput`.
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
- Clients created from a `SupabaseClient` (query, storage, functions,
  GraphQL, realtime) send the signed-in user's JWT instead of the API key
  as the bearer once `client.auth()` has a session, so RLS policies apply
  as that user.
- wasm32: a privileged key is refused by `SupabaseClient::new`.
- wasm bindings return plain JS objects instead of `Map`s.
- Internal crates depend on each other with `default-features = false`;
  crates that make HTTP or WebSocket connections gained a default `rustls`
  feature. If you depend on a sub-crate with `default-features = false`,
  enable `rustls` or `native-tls`.
- Workspace-level `reqwest` no longer enables reqwest's default features.
- Certificates are checked against the OS trust store instead of bundled
  webpki roots (see "Changed").
- MSRV 1.89.

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
