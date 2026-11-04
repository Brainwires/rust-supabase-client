//! Regression tests for the realtime protocol audit findings, run against a
//! local Phoenix-like WebSocket server (no Supabase instance needed).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

use supabase_client_realtime::types::{RealtimeConfig, ReconnectConfig};
use supabase_client_realtime::{
    ChannelState, PostgresChangesEvent, PostgresChangesFilter, RealtimeClient,
};

type Ws = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

async fn accept(l: &TcpListener) -> Ws {
    let (s, _) = l.accept().await.unwrap();
    tokio_tungstenite::accept_async(s).await.unwrap()
}

/// Read frames for `dur`; answer heartbeats when `ack_heartbeats` is set.
/// Returns (non-heartbeat messages, heartbeat count).
async fn drain(ws: &mut Ws, dur: Duration, ack_heartbeats: bool) -> (Vec<Value>, usize) {
    let end = Instant::now() + dur;
    let (mut msgs, mut hb) = (vec![], 0);
    while let Ok(Some(Ok(m))) = tokio::time::timeout_at(end.into(), ws.next()).await {
        if let Message::Text(t) = m {
            let v: Value = serde_json::from_str(&t).unwrap();
            if v["event"] == "heartbeat" {
                hb += 1;
                if ack_heartbeats {
                    reply(ws, &v, json!({})).await;
                }
            } else {
                msgs.push(v)
            }
        }
    }
    (msgs, hb)
}

/// Wait for the next message with the given event (answering heartbeats).
async fn next_event(ws: &mut Ws, event: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(Instant::now() < deadline, "timed out waiting for {event}");
        let (msgs, _) = drain(ws, Duration::from_millis(50), true).await;
        if let Some(m) = msgs.into_iter().find(|v| v["event"] == event) {
            return m;
        }
    }
}

async fn reply(ws: &mut Ws, req: &Value, response: Value) {
    let r = json!({
        "event": "phx_reply",
        "topic": req["topic"],
        "ref": req["ref"],
        "join_ref": req["join_ref"],
        "payload": {"status": "ok", "response": response},
    });
    ws.send(Message::Text(r.to_string().into())).await.unwrap();
}

async fn setup(heartbeat: Duration) -> (TcpListener, RealtimeClient) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let mut cfg = RealtimeConfig::new(format!("http://127.0.0.1:{port}"), "anon-key");
    cfg.heartbeat_interval = heartbeat;
    cfg.subscribe_timeout = Duration::from_secs(3);
    cfg.reconnect = ReconnectConfig {
        intervals: vec![Duration::from_millis(50)],
        fallback: Duration::from_millis(50),
    };
    (l, RealtimeClient::with_config(cfg).unwrap())
}

/// H4: private() must be sent in the join config.
/// H5: after a reconnect the rejoin completes (state Joined, sends work).
/// M3: heartbeats do not pile up across reconnects.
/// M4: a binary frame is not treated as end of stream.
#[tokio::test(flavor = "multi_thread")]
async fn private_flag_rejoin_heartbeats_and_binary_frames() {
    let (l, client) = setup(Duration::from_millis(400)).await;
    let (r, mut ws1) = tokio::join!(client.connect(), accept(&l));
    r.unwrap();

    let c2 = client.clone();
    let sub = tokio::spawn(async move { c2.channel("room").private().subscribe(|_, _| {}).await });
    let join = next_event(&mut ws1, "phx_join").await;
    assert_eq!(join["payload"]["config"]["private"], true, "{join}");
    reply(&mut ws1, &join, json!({})).await;
    let ch = sub.await.unwrap().unwrap();
    assert_eq!(ch.state().await, ChannelState::Joined);

    // Server drops the connection -> client reconnects and rejoins.
    drop(ws1);
    let mut ws2 = accept(&l).await;
    let rejoin = next_event(&mut ws2, "phx_join").await;
    assert_ne!(rejoin["join_ref"], join["join_ref"]);
    assert_eq!(rejoin["payload"]["config"]["private"], true);
    reply(&mut ws2, &rejoin, json!({})).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        ch.state().await,
        ChannelState::Joined,
        "rejoin never completed"
    );
    ch.send_broadcast("e", json!({})).await.unwrap();
    let b = next_event(&mut ws2, "broadcast").await;
    assert_eq!(
        b["join_ref"], rejoin["join_ref"],
        "broadcast must use the new join_ref"
    );

    // One heartbeat task only: 3-4 heartbeats in 1.5s at 400ms, not 7-8.
    let (_, hb) = drain(&mut ws2, Duration::from_millis(1500), true).await;
    assert!((2..=5).contains(&hb), "heartbeats in 1.5s: {hb}");

    // A binary frame must not drop the connection.
    ws2.send(Message::Binary(vec![1u8, 2, 3].into()))
        .await
        .unwrap();
    ws2.send(Message::Pong(vec![].into())).await.unwrap();
    // Keep acknowledging heartbeats meanwhile, or the missed-ack check
    // would (correctly) reconnect.
    let (_, reconnected) = tokio::join!(
        drain(&mut ws2, Duration::from_millis(800), true),
        tokio::time::timeout(Duration::from_millis(800), accept(&l)),
    );
    assert!(
        reconnected.is_err(),
        "client reconnected after a binary/pong frame"
    );
    assert!(client.is_connected());

    client.disconnect().await.unwrap();
}

/// M3: an un-acknowledged heartbeat makes the client reconnect.
#[tokio::test(flavor = "multi_thread")]
async fn unacked_heartbeat_triggers_reconnect() {
    let (l, client) = setup(Duration::from_millis(150)).await;
    let (r, mut ws1) = tokio::join!(client.connect(), accept(&l));
    r.unwrap();
    // Read but never answer heartbeats (keep the socket open).
    let silent = tokio::spawn(async move { while let Some(Ok(_)) = ws1.next().await {} });
    let ws2 = tokio::time::timeout(Duration::from_secs(3), accept(&l)).await;
    assert!(ws2.is_ok(), "no reconnect after missed heartbeat ack");
    client.disconnect().await.unwrap();
    silent.abort();
}

/// H5: postgres_changes callbacks after a rejoin only fire for their own
/// server-assigned subscription ids (the id map is rebuilt).
#[tokio::test(flavor = "multi_thread")]
async fn postgres_changes_routing_survives_rejoin() {
    let (l, client) = setup(Duration::from_secs(30)).await;
    let (r, mut ws1) = tokio::join!(client.connect(), accept(&l));
    r.unwrap();

    let hits_a = Arc::new(AtomicUsize::new(0));
    let hits_b = Arc::new(AtomicUsize::new(0));
    let (ha, hb) = (hits_a.clone(), hits_b.clone());
    let c2 = client.clone();
    let sub = tokio::spawn(async move {
        c2.channel("db")
            .on_postgres_changes(
                PostgresChangesEvent::All,
                PostgresChangesFilter::new("public", "a"),
                move |_| {
                    ha.fetch_add(1, Ordering::SeqCst);
                },
            )
            .on_postgres_changes(
                PostgresChangesEvent::All,
                PostgresChangesFilter::new("public", "b"),
                move |_| {
                    hb.fetch_add(1, Ordering::SeqCst);
                },
            )
            .subscribe(|_, _| {})
            .await
    });
    let join = next_event(&mut ws1, "phx_join").await;
    reply(
        &mut ws1,
        &join,
        json!({"postgres_changes": [{"id": 11}, {"id": 12}]}),
    )
    .await;
    let ch = sub.await.unwrap().unwrap();

    drop(ws1);
    let mut ws2 = accept(&l).await;
    let rejoin = next_event(&mut ws2, "phx_join").await;
    // New server ids after the rejoin.
    reply(
        &mut ws2,
        &rejoin,
        json!({"postgres_changes": [{"id": 21}, {"id": 22}]}),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(ch.state().await, ChannelState::Joined);

    let change = json!({
        "event": "postgres_changes",
        "topic": "realtime:db",
        "ref": null,
        "join_ref": rejoin["join_ref"],
        "payload": {
            "ids": [22],
            "data": {
                "schema": "public", "table": "b", "commit_timestamp": "2024-01-01T00:00:00Z",
                "type": "INSERT", "columns": [], "record": {"id": 1}, "old_record": null,
                "errors": null
            }
        }
    });
    ws2.send(Message::Text(change.to_string().into()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        hits_a.load(Ordering::SeqCst),
        0,
        "callback for table a fired"
    );
    assert_eq!(hits_b.load(Ordering::SeqCst), 1);
    client.disconnect().await.unwrap();
}

/// M5: set_auth stores the token; new channels and rejoins use it.
#[tokio::test(flavor = "multi_thread")]
async fn set_auth_token_used_for_new_channels_and_rejoins() {
    let (l, client) = setup(Duration::from_secs(30)).await;
    client.set_auth("jwt-1").await.unwrap();
    let (r, mut ws1) = tokio::join!(client.connect(), accept(&l));
    r.unwrap();

    let c2 = client.clone();
    let sub = tokio::spawn(async move { c2.channel("room").subscribe(|_, _| {}).await });
    let join = next_event(&mut ws1, "phx_join").await;
    assert_eq!(join["payload"]["access_token"], "jwt-1");
    reply(&mut ws1, &join, json!({})).await;
    let _ch = sub.await.unwrap().unwrap();

    // Token refresh while connected: pushed to the joined channel.
    client.set_auth("jwt-2").await.unwrap();
    let push = next_event(&mut ws1, "access_token").await;
    assert_eq!(push["payload"]["access_token"], "jwt-2");

    drop(ws1);
    let mut ws2 = accept(&l).await;
    let rejoin = next_event(&mut ws2, "phx_join").await;
    assert_eq!(rejoin["payload"]["access_token"], "jwt-2");
    client.disconnect().await.unwrap();
}

/// Lifecycle: unsubscribe removes the channel (topic can be reused), a
/// failed join does not leave the channel registered, and connect() twice
/// does not start a second reader/connection.
#[tokio::test(flavor = "multi_thread")]
async fn channel_lifecycle_and_double_connect() {
    let (l, client) = setup(Duration::from_secs(30)).await;
    let (r, mut ws1) = tokio::join!(client.connect(), accept(&l));
    r.unwrap();

    // Second connect is a no-op: no new connection is accepted.
    client.connect().await.unwrap();
    let second = tokio::time::timeout(Duration::from_millis(300), accept(&l))
        .await
        .is_ok();
    assert!(!second, "connect() twice opened a second connection");

    let c2 = client.clone();
    let sub = tokio::spawn(async move { c2.channel("room").subscribe(|_, _| {}).await });
    let join = next_event(&mut ws1, "phx_join").await;
    reply(&mut ws1, &join, json!({})).await;
    let ch = sub.await.unwrap().unwrap();
    assert_eq!(client.channels().len(), 1);

    ch.unsubscribe().await.unwrap();
    let leave = next_event(&mut ws1, "phx_leave").await;
    assert_eq!(leave["topic"], "realtime:room");
    assert_eq!(ch.state().await, ChannelState::Closed);
    assert!(client.channels().is_empty(), "unsubscribe left the channel");

    // Same topic again; the server rejects the join.
    let c3 = client.clone();
    let sub = tokio::spawn(async move { c3.channel("room").subscribe(|_, _| {}).await });
    let join = next_event(&mut ws1, "phx_join").await;
    let err = json!({
        "event": "phx_reply", "topic": join["topic"], "ref": join["ref"],
        "join_ref": join["join_ref"],
        "payload": {"status": "error", "response": {"reason": "unauthorized"}},
    });
    ws1.send(Message::Text(err.to_string().into()))
        .await
        .unwrap();
    assert!(sub.await.unwrap().is_err());
    assert!(client.channels().is_empty(), "failed join left the channel");

    client.disconnect().await.unwrap();
    // Subscribing while disconnected fails and does not register the channel.
    assert!(client.channel("x").subscribe(|_, _| {}).await.is_err());
    assert!(client.channels().is_empty());
}
