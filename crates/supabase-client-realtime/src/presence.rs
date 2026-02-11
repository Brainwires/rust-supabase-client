use serde_json::Value;

use crate::types::{PresenceDiff, PresenceEntry, PresenceMeta, PresenceState};

/// Apply a full presence_state message from the server.
/// Returns the new complete state.
pub(crate) fn apply_state(raw: Value) -> PresenceState {
    // The server sends presence_state as: { "key": { "metas": [...] }, ... }
    let mut state = PresenceState::new();
    if let Value::Object(map) = raw {
        for (key, entry_val) in map {
            if let Ok(entry) = serde_json::from_value::<PresenceEntry>(entry_val) {
                state.insert(key, entry.metas);
            }
        }
    }
    state
}

/// Apply a presence_diff to the current state.
/// Returns (joins, leaves) as vectors of (key, metas) for callback dispatch.
pub(crate) fn apply_diff(
    current: &mut PresenceState,
    diff: PresenceDiff,
) -> (
    Vec<(String, Vec<PresenceMeta>)>,
    Vec<(String, Vec<PresenceMeta>)>,
) {
    let mut joins = Vec::new();
    let mut leaves = Vec::new();

    // Process joins: add new metas to state
    for (key, entry) in diff.joins {
        joins.push((key.clone(), entry.metas.clone()));
        let metas = current.entry(key).or_default();
        metas.extend(entry.metas);
    }

    // Process leaves: remove metas from state
    for (key, entry) in diff.leaves {
        leaves.push((key.clone(), entry.metas.clone()));
        if let Some(metas) = current.get_mut(&key) {
            // Remove metas that match by phx_ref
            let leave_refs: Vec<_> = entry
                .metas
                .iter()
                .filter_map(|m| m.phx_ref.as_ref())
                .collect();
            metas.retain(|m| {
                m.phx_ref
                    .as_ref()
                    .map_or(true, |r| !leave_refs.contains(&r))
            });
            if metas.is_empty() {
                current.remove(&key);
            }
        }
    }

    (joins, leaves)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use serde_json::json;

    #[test]
    fn test_apply_state_from_raw() {
        let raw = json!({
            "user1": {
                "metas": [
                    {"phx_ref": "ref1", "online_at": "2024-01-01"}
                ]
            },
            "user2": {
                "metas": [
                    {"phx_ref": "ref2", "status": "away"}
                ]
            }
        });

        let state = apply_state(raw);
        assert_eq!(state.len(), 2);
        assert!(state.contains_key("user1"));
        assert!(state.contains_key("user2"));
        assert_eq!(state["user1"].len(), 1);
        assert_eq!(state["user1"][0].phx_ref.as_deref(), Some("ref1"));
    }

    #[test]
    fn test_apply_state_empty() {
        let state = apply_state(json!({}));
        assert!(state.is_empty());
    }

    #[test]
    fn test_apply_diff_joins() {
        let mut state = PresenceState::new();
        let diff = PresenceDiff {
            joins: {
                let mut m = HashMap::new();
                m.insert(
                    "user1".to_string(),
                    PresenceEntry {
                        metas: vec![PresenceMeta {
                            phx_ref: Some("ref1".to_string()),
                            phx_ref_prev: None,
                            data: json!({"online": true}),
                        }],
                    },
                );
                m
            },
            leaves: HashMap::new(),
        };

        let (joins, leaves) = apply_diff(&mut state, diff);
        assert_eq!(joins.len(), 1);
        assert_eq!(joins[0].0, "user1");
        assert!(leaves.is_empty());
        assert_eq!(state.len(), 1);
        assert_eq!(state["user1"].len(), 1);
    }

    #[test]
    fn test_apply_diff_leaves() {
        let mut state = PresenceState::new();
        state.insert(
            "user1".to_string(),
            vec![PresenceMeta {
                phx_ref: Some("ref1".to_string()),
                phx_ref_prev: None,
                data: json!({"online": true}),
            }],
        );

        let diff = PresenceDiff {
            joins: HashMap::new(),
            leaves: {
                let mut m = HashMap::new();
                m.insert(
                    "user1".to_string(),
                    PresenceEntry {
                        metas: vec![PresenceMeta {
                            phx_ref: Some("ref1".to_string()),
                            phx_ref_prev: None,
                            data: json!({}),
                        }],
                    },
                );
                m
            },
        };

        let (joins, leaves) = apply_diff(&mut state, diff);
        assert!(joins.is_empty());
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0].0, "user1");
        // user1 should be removed since all metas were removed
        assert!(state.is_empty());
    }

    #[test]
    fn test_apply_diff_partial_leave() {
        let mut state = PresenceState::new();
        state.insert(
            "user1".to_string(),
            vec![
                PresenceMeta {
                    phx_ref: Some("ref1".to_string()),
                    phx_ref_prev: None,
                    data: json!({"device": "phone"}),
                },
                PresenceMeta {
                    phx_ref: Some("ref2".to_string()),
                    phx_ref_prev: None,
                    data: json!({"device": "laptop"}),
                },
            ],
        );

        let diff = PresenceDiff {
            joins: HashMap::new(),
            leaves: {
                let mut m = HashMap::new();
                m.insert(
                    "user1".to_string(),
                    PresenceEntry {
                        metas: vec![PresenceMeta {
                            phx_ref: Some("ref1".to_string()),
                            phx_ref_prev: None,
                            data: json!({}),
                        }],
                    },
                );
                m
            },
        };

        let (_, _) = apply_diff(&mut state, diff);
        // user1 should still exist with one meta
        assert_eq!(state.len(), 1);
        assert_eq!(state["user1"].len(), 1);
        assert_eq!(state["user1"][0].phx_ref.as_deref(), Some("ref2"));
    }
}
