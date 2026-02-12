# supabase-client-realtime

Realtime WebSocket client for supabase-client.

> **Note:** This crate is part of the [`supabase-client-sdk`](https://crates.io/crates/supabase-client-sdk) workspace. Most users should depend on `supabase-client-sdk` with the `realtime` feature rather than using this crate directly.

## Key Features

- **`SupabaseClientRealtimeExt`** extension trait — adds `.realtime()` to `SupabaseClient`
- **`RealtimeClient`** — Phoenix Channels v1.0.0 protocol over WebSocket
- **Postgres Changes**: listen for INSERT, UPDATE, DELETE events with table/column filters
- **Broadcast**: send/receive ephemeral messages between clients
- **Presence**: track and sync online user state with join/leave callbacks
- `set_auth()` to update token on existing connections
- Custom headers for WebSocket handshake via `RealtimeConfig`
- Automatic heartbeat and auto-reconnect with configurable backoff
- Works on both native (tokio-tungstenite) and WASM (web-sys WebSocket) targets

## Usage

```rust
use supabase_client_realtime::SupabaseClientRealtimeExt;
use supabase_client_realtime::{PostgresChangesEvent, PostgresChangesFilter};

let realtime = client.realtime()?;
realtime.connect().await?;

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
```

## License

Licensed under either of [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0) or [MIT license](http://opensource.org/licenses/MIT) at your option.
