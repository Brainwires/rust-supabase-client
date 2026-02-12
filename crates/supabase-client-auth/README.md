# supabase-client-auth

Auth (GoTrue) client for supabase-client.

> **Note:** This crate is part of the [`supabase-client-sdk`](https://crates.io/crates/supabase-client-sdk) workspace. Most users should depend on `supabase-client-sdk` with the `auth` feature rather than using this crate directly.

## Key Features

- **`SupabaseClientAuthExt`** extension trait — adds `.auth()` to `SupabaseClient`
- **`AuthClient`** — full GoTrue HTTP client via reqwest
- Sign-in methods: email/password, phone, OAuth, magic link, OTP, anonymous, Web3 (Ethereum/Solana), SSO (SAML), ID token (external OIDC)
- Session management: `get_session()`, `set_session()`, `on_auth_state_change()`
- Auto-refresh with configurable intervals via `start_auto_refresh()`
- JWT claims extraction via `get_claims()` (no network call)
- MFA: TOTP enroll/challenge/verify, phone factors, AAL detection
- **Admin API**: list/create/update/delete users, MFA factor management
- **OAuth Server**: consent management, grant listing/revocation, client CRUD
- **OAuth Client-Side Flow**: PKCE, token exchange/refresh/revoke, OIDC discovery, JWKS

## Usage

```rust
use supabase_client_auth::SupabaseClientAuthExt;

let auth = client.auth()?;

// Sign in with email/password
let session = auth.sign_in_with_password_email("user@example.com", "password123").await?;
println!("Access token: {}", session.access_token);

// Get current user
let user = auth.get_user(&session.access_token).await?;
```

## License

Licensed under either of [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0) or [MIT license](http://opensource.org/licenses/MIT) at your option.
