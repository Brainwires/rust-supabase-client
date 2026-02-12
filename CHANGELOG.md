# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-02-12

### Added

- Per-crate `README.md` files for all 9 workspace crates so each crate page on crates.io has documentation
- `readme = "README.md"` field in all crate `Cargo.toml` files

### Changed

- Renamed `crates/supabase-client/` directory to `crates/supabase-client-sdk/` to match the published crate name

## [0.2.0] - 2025-02-12

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
