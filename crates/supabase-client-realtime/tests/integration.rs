//! Integration tests for supabase-client-realtime.
//!
//! Unit tests (no server required) and integration tests (require local Supabase).
//!
//! Run with: cargo test -p supabase-client-realtime -- --test-threads=1

use std::time::Duration;

use serde_json::json;
use tokio::sync::mpsc;

use supabase_client_realtime::{
    ChannelState, PostgresChangesEvent, PostgresChangesFilter, RealtimeClient,
    RealtimeConfig, RealtimeError, SubscriptionStatus,
};
use supabase_client_realtime::types::{
    BroadcastConfig, JoinConfig, JoinPayload, PhoenixMessage, PresenceConfig,
    PresenceDiff,
};

// ── Test Configuration ────────────────────────────────────────────────────────

const SUPABASE_URL: &str = "http://127.0.0.1:64321";
const SUPABASE_ANON_KEY: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0";

fn get_url() -> String {
    std::env::var("SUPABASE_URL").unwrap_or_else(|_| SUPABASE_URL.to_string())
}

fn get_key() -> String {
    std::env::var("SUPABASE_ANON_KEY").unwrap_or_else(|_| SUPABASE_ANON_KEY.to_string())
}

// ── Unit Tests (no server) ────────────────────────────────────────────────────

mod unit {
    use super::*;

    #[test]
    fn phoenix_message_serialization_roundtrip() {
        let msg = PhoenixMessage {
            event: "phx_join".to_string(),
            topic: "realtime:test".to_string(),
            payload: json!({"key": "value"}),
            msg_ref: Some("1".to_string()),
            join_ref: Some("1".to_string()),
        };
        let json_str = serde_json::to_string(&msg).unwrap();
        let parsed: PhoenixMessage = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.event, "phx_join");
        assert_eq!(parsed.topic, "realtime:test");
        assert_eq!(parsed.msg_ref, Some("1".to_string()));
        assert_eq!(parsed.join_ref, Some("1".to_string()));
    }

    #[test]
    fn join_payload_serialization() {
        let payload = JoinPayload {
            config: JoinConfig {
                broadcast: BroadcastConfig {
                    ack: false,
                    self_send: true,
                },
                presence: PresenceConfig {
                    key: "user-1".to_string(),
                },
                postgres_changes: vec![
                    PostgresChangesFilter::new("public", "messages")
                        .event(PostgresChangesEvent::Insert),
                    PostgresChangesFilter::new("public", "users")
                        .event(PostgresChangesEvent::All)
                        .with_filter("id=eq.1"),
                ],
            },
            access_token: Some("test-token".to_string()),
        };
        let json_val = serde_json::to_value(&payload).unwrap();
        assert_eq!(json_val["config"]["broadcast"]["self"], true);
        assert_eq!(json_val["config"]["broadcast"]["ack"], false);
        assert_eq!(json_val["config"]["presence"]["key"], "user-1");
        assert_eq!(json_val["config"]["postgres_changes"].as_array().unwrap().len(), 2);
        assert_eq!(json_val["config"]["postgres_changes"][0]["event"], "INSERT");
        assert_eq!(json_val["config"]["postgres_changes"][0]["schema"], "public");
        assert_eq!(json_val["config"]["postgres_changes"][0]["table"], "messages");
        assert_eq!(json_val["config"]["postgres_changes"][1]["filter"], "id=eq.1");
        assert_eq!(json_val["access_token"], "test-token");
    }

    #[test]
    fn error_display() {
        let err = RealtimeError::InvalidConfig("test".into());
        assert_eq!(err.to_string(), "Invalid configuration: test");

        let err = RealtimeError::ChannelNotFound("my-chan".into());
        assert_eq!(err.to_string(), "Channel not found: my-chan");

        let err = RealtimeError::SubscribeTimeout(Duration::from_secs(10));
        assert_eq!(err.to_string(), "Subscribe timed out after 10s");

        let err = RealtimeError::InvalidChannelState {
            expected: ChannelState::Joined,
            actual: ChannelState::Closed,
        };
        assert!(err.to_string().contains("expected"));
    }

    #[test]
    fn error_converts_to_supabase_error() {
        use supabase_client_core::SupabaseError;
        let err = RealtimeError::ConnectionClosed;
        let se: SupabaseError = err.into();
        match se {
            SupabaseError::Realtime(msg) => assert!(msg.contains("closed")),
            _ => panic!("Expected Realtime variant"),
        }
    }

    #[test]
    fn postgres_changes_filter_builder() {
        let filter = PostgresChangesFilter::new("public", "messages")
            .event(PostgresChangesEvent::Insert)
            .with_filter("id=eq.5");
        assert_eq!(filter.schema, "public");
        assert_eq!(filter.table.as_deref(), Some("messages"));
        assert_eq!(filter.event, "INSERT");
        assert_eq!(filter.filter.as_deref(), Some("id=eq.5"));
    }

    #[test]
    fn postgres_changes_filter_schema_only() {
        let filter = PostgresChangesFilter::schema_only("public");
        assert_eq!(filter.schema, "public");
        assert!(filter.table.is_none());
        assert_eq!(filter.event, "*");
    }

    #[tokio::test]
    async fn channel_topic_format() {
        // Verify topic/name via a subscribed channel
        // The topic format should be "realtime:<name>"
        // We test this in integration::channel_names_and_topics
        // Here we just verify the client doesn't panic with a simple channel name
        let client = RealtimeClient::new("http://localhost:64321", "test-key").unwrap();
        let _builder = client.channel("my-channel");
        // Builder is opaque but if it got here without error, the format is valid
    }

    #[test]
    fn realtime_client_validation() {
        let result = RealtimeClient::new("", "key");
        assert!(result.is_err());

        let result = RealtimeClient::new("http://localhost", "");
        assert!(result.is_err());

        let result = RealtimeClient::new("http://localhost", "key");
        assert!(result.is_ok());
    }

    #[test]
    fn subscription_status_display() {
        assert_eq!(SubscriptionStatus::Subscribed.to_string(), "SUBSCRIBED");
        assert_eq!(SubscriptionStatus::TimedOut.to_string(), "TIMED_OUT");
        assert_eq!(SubscriptionStatus::Closed.to_string(), "CLOSED");
        assert_eq!(SubscriptionStatus::ChannelError.to_string(), "CHANNEL_ERROR");
    }

    #[test]
    fn channel_state_display() {
        assert_eq!(ChannelState::Closed.to_string(), "closed");
        assert_eq!(ChannelState::Joined.to_string(), "joined");
        assert_eq!(ChannelState::Joining.to_string(), "joining");
    }

    #[test]
    fn presence_diff_deserialization() {
        let json = json!({
            "joins": {
                "user1": {
                    "metas": [{"phx_ref": "r1", "status": "online"}]
                }
            },
            "leaves": {}
        });
        let diff: PresenceDiff = serde_json::from_value(json).unwrap();
        assert_eq!(diff.joins.len(), 1);
        assert!(diff.joins.contains_key("user1"));
        assert!(diff.leaves.is_empty());
    }

    #[test]
    fn postgres_changes_event_serialization() {
        assert_eq!(serde_json::to_string(&PostgresChangesEvent::All).unwrap(), "\"*\"");
        assert_eq!(serde_json::to_string(&PostgresChangesEvent::Insert).unwrap(), "\"INSERT\"");
        assert_eq!(serde_json::to_string(&PostgresChangesEvent::Update).unwrap(), "\"UPDATE\"");
        assert_eq!(serde_json::to_string(&PostgresChangesEvent::Delete).unwrap(), "\"DELETE\"");
    }

    #[test]
    fn realtime_config_defaults() {
        let config = RealtimeConfig::new("http://localhost", "key");
        assert_eq!(config.heartbeat_interval, Duration::from_secs(25));
        assert_eq!(config.subscribe_timeout, Duration::from_secs(10));
        assert_eq!(config.reconnect.intervals.len(), 4);
    }
}

// ── Integration Tests (require local Supabase) ───────────────────────────────

mod integration {
    use super::*;

    fn should_run() -> bool {
        // Skip integration tests if SKIP_REALTIME_TESTS is set
        std::env::var("SKIP_REALTIME_TESTS").is_err()
    }

    #[tokio::test]
    async fn connect_and_disconnect() {
        if !should_run() { return; }

        let client = RealtimeClient::new(get_url(), get_key()).unwrap();
        assert!(!client.is_connected());

        client.connect().await.unwrap();
        assert!(client.is_connected());

        client.disconnect().await.unwrap();
        // Give background tasks time to shut down
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!client.is_connected());
    }

    #[tokio::test]
    async fn channel_subscribe_unsubscribe() {
        if !should_run() { return; }

        let client = RealtimeClient::new(get_url(), get_key()).unwrap();
        client.connect().await.unwrap();

        let (status_tx, mut status_rx) = mpsc::channel(10);
        let channel = client
            .channel("test-sub")
            .subscribe(move |status, _err| {
                let _ = status_tx.try_send(status);
            })
            .await
            .unwrap();

        // Should receive SUBSCRIBED status
        let status = tokio::time::timeout(Duration::from_secs(5), status_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status, SubscriptionStatus::Subscribed);
        assert_eq!(channel.state().await, ChannelState::Joined);

        // Unsubscribe
        channel.unsubscribe().await.unwrap();
        assert_eq!(channel.state().await, ChannelState::Leaving);

        client.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn broadcast_send_receive_self() {
        if !should_run() { return; }

        let client = RealtimeClient::new(get_url(), get_key()).unwrap();
        client.connect().await.unwrap();

        let (msg_tx, mut msg_rx) = mpsc::channel(10);

        let channel = client
            .channel("broadcast-test")
            .broadcast_self(true)
            .on_broadcast("test-event", move |payload| {
                let _ = msg_tx.try_send(payload);
            })
            .subscribe(|_, _| {})
            .await
            .unwrap();

        // Small delay to ensure subscription is fully established
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Send a broadcast
        channel
            .send_broadcast("test-event", json!({"text": "hello from self"}))
            .await
            .unwrap();

        // Should receive our own message back (broadcast_self = true)
        let received = tokio::time::timeout(Duration::from_secs(5), msg_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received["text"], "hello from self");

        client.remove_channel(&channel).await.unwrap();
        client.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn broadcast_between_two_channels() {
        if !should_run() { return; }

        let client = RealtimeClient::new(get_url(), get_key()).unwrap();
        client.connect().await.unwrap();

        let (msg_tx, mut msg_rx) = mpsc::channel(10);

        // Channel 1: receiver
        let _ch1 = client
            .channel("shared-room")
            .on_broadcast("chat", move |payload| {
                let _ = msg_tx.try_send(payload);
            })
            .subscribe(|_, _| {})
            .await
            .unwrap();

        // Need a second client for the sender on the same channel name
        let client2 = RealtimeClient::new(get_url(), get_key()).unwrap();
        client2.connect().await.unwrap();

        let ch2 = client2
            .channel("shared-room")
            .subscribe(|_, _| {})
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Send from ch2
        ch2.send_broadcast("chat", json!({"msg": "hi there"}))
            .await
            .unwrap();

        // ch1 should receive it
        let received = tokio::time::timeout(Duration::from_secs(5), msg_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received["msg"], "hi there");

        client.remove_all_channels().await.unwrap();
        client.disconnect().await.unwrap();
        client2.remove_all_channels().await.unwrap();
        client2.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn presence_track_and_sync() {
        if !should_run() { return; }

        let client = RealtimeClient::new(get_url(), get_key()).unwrap();
        client.connect().await.unwrap();

        let (sync_tx, mut sync_rx) = mpsc::channel(10);

        let channel = client
            .channel("presence-test")
            .presence_key("user-1")
            .on_presence_sync(move |state| {
                let _ = sync_tx.try_send(state.clone());
            })
            .subscribe(|_, _| {})
            .await
            .unwrap();

        // Drain initial empty presence_state
        let _ = tokio::time::timeout(Duration::from_secs(2), sync_rx.recv()).await;

        // Track presence
        channel
            .track(json!({"user": "alice", "status": "online"}))
            .await
            .unwrap();

        // Should receive a sync with our presence (from presence_diff)
        // Wait for a non-empty state
        let mut found = false;
        for _ in 0..5 {
            match tokio::time::timeout(Duration::from_secs(3), sync_rx.recv()).await {
                Ok(Some(state)) if !state.is_empty() => {
                    found = true;
                    break;
                }
                _ => continue,
            }
        }
        assert!(found, "Should receive non-empty presence state after track");

        // Check presence_state() method
        let state = channel.presence_state().await;
        assert!(!state.is_empty());

        // Untrack
        channel.untrack().await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;

        client.remove_channel(&channel).await.unwrap();
        client.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn presence_join_leave_callbacks() {
        if !should_run() { return; }

        let client = RealtimeClient::new(get_url(), get_key()).unwrap();
        client.connect().await.unwrap();

        let (join_tx, mut join_rx) = mpsc::channel(10);
        let (leave_tx, mut leave_rx) = mpsc::channel(10);

        let channel = client
            .channel("presence-jl")
            .on_presence_join(move |key, _metas| {
                let _ = join_tx.try_send(key);
            })
            .on_presence_leave(move |key, _metas| {
                let _ = leave_tx.try_send(key);
            })
            .subscribe(|_, _| {})
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(500)).await;

        // A second client joins the same channel
        let client2 = RealtimeClient::new(get_url(), get_key()).unwrap();
        client2.connect().await.unwrap();

        let ch2 = client2
            .channel("presence-jl")
            .presence_key("user-2")
            .subscribe(|_, _| {})
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(500)).await;

        ch2.track(json!({"name": "bob"})).await.unwrap();

        // Should get a join notification
        let join_key = tokio::time::timeout(Duration::from_secs(5), join_rx.recv()).await;
        assert!(join_key.is_ok(), "Should receive join callback");

        // Now disconnect client2 — should trigger leave
        client2.remove_channel(&ch2).await.unwrap();
        client2.disconnect().await.unwrap();

        let leave_key = tokio::time::timeout(Duration::from_secs(5), leave_rx.recv()).await;
        assert!(leave_key.is_ok(), "Should receive leave callback");

        client.remove_channel(&channel).await.unwrap();
        client.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn postgres_changes_insert() {
        if !should_run() { return; }

        let client = RealtimeClient::new(get_url(), get_key()).unwrap();
        client.connect().await.unwrap();

        let (change_tx, mut change_rx) = mpsc::channel(10);

        let channel = client
            .channel("pg-insert")
            .on_postgres_changes(
                PostgresChangesEvent::Insert,
                PostgresChangesFilter::new("public", "realtime_test"),
                move |payload| {
                    let _ = change_tx.try_send(payload);
                },
            )
            .subscribe(|_, _| {})
            .await
            .unwrap();

        // Allow subscription to propagate
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Insert a row via SQL
        let db_url = "postgres://postgres:postgres@127.0.0.1:64322/postgres";
        let pool = sqlx::PgPool::connect(db_url).await.unwrap();
        sqlx::query("INSERT INTO realtime_test (name, value) VALUES ('test-insert', 'hello')")
            .execute(&pool)
            .await
            .unwrap();

        // Should receive the change
        let result = tokio::time::timeout(Duration::from_secs(5), change_rx.recv()).await;
        assert!(result.is_ok(), "Should receive postgres INSERT change");
        if let Ok(Some(payload)) = result {
            assert_eq!(payload.change_type, "INSERT");
            assert_eq!(payload.table, "realtime_test");
        }

        // Cleanup
        sqlx::query("DELETE FROM realtime_test WHERE name = 'test-insert'")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;

        client.remove_channel(&channel).await.unwrap();
        client.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn postgres_changes_update() {
        if !should_run() { return; }

        let client = RealtimeClient::new(get_url(), get_key()).unwrap();
        client.connect().await.unwrap();

        let db_url = "postgres://postgres:postgres@127.0.0.1:64322/postgres";
        let pool = sqlx::PgPool::connect(db_url).await.unwrap();

        // Insert a row first
        sqlx::query("INSERT INTO realtime_test (name, value) VALUES ('test-update', 'before')")
            .execute(&pool)
            .await
            .unwrap();

        let (change_tx, mut change_rx) = mpsc::channel(10);

        let channel = client
            .channel("pg-update")
            .on_postgres_changes(
                PostgresChangesEvent::Update,
                PostgresChangesFilter::new("public", "realtime_test"),
                move |payload| {
                    let _ = change_tx.try_send(payload);
                },
            )
            .subscribe(|_, _| {})
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_secs(1)).await;

        // Update the row
        sqlx::query("UPDATE realtime_test SET value = 'after' WHERE name = 'test-update'")
            .execute(&pool)
            .await
            .unwrap();

        let result = tokio::time::timeout(Duration::from_secs(5), change_rx.recv()).await;
        assert!(result.is_ok(), "Should receive postgres UPDATE change");
        if let Ok(Some(payload)) = result {
            assert_eq!(payload.change_type, "UPDATE");
        }

        // Cleanup
        sqlx::query("DELETE FROM realtime_test WHERE name = 'test-update'")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;

        client.remove_channel(&channel).await.unwrap();
        client.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn postgres_changes_delete() {
        if !should_run() { return; }

        let client = RealtimeClient::new(get_url(), get_key()).unwrap();
        client.connect().await.unwrap();

        let db_url = "postgres://postgres:postgres@127.0.0.1:64322/postgres";
        let pool = sqlx::PgPool::connect(db_url).await.unwrap();

        // Insert a row first
        sqlx::query("INSERT INTO realtime_test (name, value) VALUES ('test-delete', 'gone')")
            .execute(&pool)
            .await
            .unwrap();

        let (change_tx, mut change_rx) = mpsc::channel(10);

        let channel = client
            .channel("pg-delete")
            .on_postgres_changes(
                PostgresChangesEvent::Delete,
                PostgresChangesFilter::new("public", "realtime_test"),
                move |payload| {
                    let _ = change_tx.try_send(payload);
                },
            )
            .subscribe(|_, _| {})
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_secs(1)).await;

        // Delete the row
        sqlx::query("DELETE FROM realtime_test WHERE name = 'test-delete'")
            .execute(&pool)
            .await
            .unwrap();

        let result = tokio::time::timeout(Duration::from_secs(5), change_rx.recv()).await;
        assert!(result.is_ok(), "Should receive postgres DELETE change");
        if let Ok(Some(payload)) = result {
            assert_eq!(payload.change_type, "DELETE");
        }

        pool.close().await;
        client.remove_channel(&channel).await.unwrap();
        client.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn postgres_changes_all_events() {
        if !should_run() { return; }

        let client = RealtimeClient::new(get_url(), get_key()).unwrap();
        client.connect().await.unwrap();

        let (change_tx, mut change_rx) = mpsc::channel(10);

        let channel = client
            .channel("pg-all")
            .on_postgres_changes(
                PostgresChangesEvent::All,
                PostgresChangesFilter::new("public", "realtime_test"),
                move |payload| {
                    let _ = change_tx.try_send(payload.change_type);
                },
            )
            .subscribe(|_, _| {})
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_secs(1)).await;

        let db_url = "postgres://postgres:postgres@127.0.0.1:64322/postgres";
        let pool = sqlx::PgPool::connect(db_url).await.unwrap();

        // INSERT
        sqlx::query("INSERT INTO realtime_test (name, value) VALUES ('test-all', 'v1')")
            .execute(&pool)
            .await
            .unwrap();

        let insert = tokio::time::timeout(Duration::from_secs(5), change_rx.recv()).await;
        assert!(insert.is_ok(), "Should receive INSERT");

        // UPDATE
        sqlx::query("UPDATE realtime_test SET value = 'v2' WHERE name = 'test-all'")
            .execute(&pool)
            .await
            .unwrap();

        let update = tokio::time::timeout(Duration::from_secs(5), change_rx.recv()).await;
        assert!(update.is_ok(), "Should receive UPDATE");

        // DELETE
        sqlx::query("DELETE FROM realtime_test WHERE name = 'test-all'")
            .execute(&pool)
            .await
            .unwrap();

        let delete = tokio::time::timeout(Duration::from_secs(5), change_rx.recv()).await;
        assert!(delete.is_ok(), "Should receive DELETE");

        pool.close().await;
        client.remove_channel(&channel).await.unwrap();
        client.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn multiple_channels() {
        if !should_run() { return; }

        let client = RealtimeClient::new(get_url(), get_key()).unwrap();
        client.connect().await.unwrap();

        let ch1 = client
            .channel("multi-1")
            .subscribe(|_, _| {})
            .await
            .unwrap();

        let ch2 = client
            .channel("multi-2")
            .subscribe(|_, _| {})
            .await
            .unwrap();

        let ch3 = client
            .channel("multi-3")
            .subscribe(|_, _| {})
            .await
            .unwrap();

        assert_eq!(ch1.state().await, ChannelState::Joined);
        assert_eq!(ch2.state().await, ChannelState::Joined);
        assert_eq!(ch3.state().await, ChannelState::Joined);

        let channels = client.channels();
        assert_eq!(channels.len(), 3);

        // Remove one
        client.remove_channel(&ch2).await.unwrap();
        let channels = client.channels();
        assert_eq!(channels.len(), 2);

        // Remove all
        client.remove_all_channels().await.unwrap();
        let channels = client.channels();
        assert_eq!(channels.len(), 0);

        client.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn channel_names_and_topics() {
        if !should_run() { return; }

        let client = RealtimeClient::new(get_url(), get_key()).unwrap();
        client.connect().await.unwrap();

        let ch = client
            .channel("my-room")
            .subscribe(|_, _| {})
            .await
            .unwrap();

        assert_eq!(ch.name(), "my-room");
        assert_eq!(ch.topic(), "realtime:my-room");

        client.remove_all_channels().await.unwrap();
        client.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn send_broadcast_after_unsubscribe_fails() {
        if !should_run() { return; }

        let client = RealtimeClient::new(get_url(), get_key()).unwrap();
        client.connect().await.unwrap();

        let channel = client
            .channel("unsub-test")
            .subscribe(|_, _| {})
            .await
            .unwrap();

        // Unsubscribe puts channel in Leaving state
        channel.unsubscribe().await.unwrap();

        let result = channel
            .send_broadcast("test", json!({"hi": true}))
            .await;
        assert!(result.is_err());

        client.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn duplicate_channel_name_errors() {
        if !should_run() { return; }

        let client = RealtimeClient::new(get_url(), get_key()).unwrap();
        client.connect().await.unwrap();

        let _ch1 = client
            .channel("dup-test")
            .subscribe(|_, _| {})
            .await
            .unwrap();

        // Subscribing to same name should fail
        let result = client
            .channel("dup-test")
            .subscribe(|_, _| {})
            .await;
        assert!(result.is_err());

        client.remove_all_channels().await.unwrap();
        client.disconnect().await.unwrap();
    }
}
