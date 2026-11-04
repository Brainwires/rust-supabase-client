//! Shared, mutable access-token slot.
//!
//! A [`SupabaseClient`](crate::SupabaseClient) owns one [`AccessToken`]. The
//! auth client writes the signed-in user's JWT into it, and the query,
//! storage, functions, GraphQL and realtime clients built from the same
//! `SupabaseClient` read it when they build a request, so requests run with
//! the user's row-level-security context instead of the project API key.

use std::fmt;
use std::sync::{Arc, RwLock};

/// A cheaply clonable handle to a shared access token.
///
/// Clones share the same slot: setting the token through one clone is visible
/// through all of them. `Debug` never prints the token.
#[derive(Clone, Default)]
pub struct AccessToken {
    inner: Arc<RwLock<Option<String>>>,
}

impl AccessToken {
    /// Create an empty slot.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the current token, if one is set.
    pub fn get(&self) -> Option<String> {
        match self.inner.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Replace the token.
    pub fn set(&self, token: impl Into<String>) {
        self.replace(Some(token.into()));
    }

    /// Remove the token.
    pub fn clear(&self) {
        self.replace(None);
    }

    /// Replace the token with `token` (or clear it with `None`).
    pub fn replace(&self, token: Option<String>) {
        match self.inner.write() {
            Ok(mut guard) => *guard = token,
            Err(poisoned) => *poisoned.into_inner() = token,
        }
    }

    /// Whether a token is set.
    pub fn is_set(&self) -> bool {
        match self.inner.read() {
            Ok(guard) => guard.is_some(),
            Err(poisoned) => poisoned.into_inner().is_some(),
        }
    }

    /// Whether two handles share the same slot.
    pub fn ptr_eq(&self, other: &AccessToken) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AccessToken")
            .field(&if self.is_set() { "[redacted]" } else { "None" })
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_the_slot() {
        let a = AccessToken::new();
        let b = a.clone();
        assert!(a.get().is_none());
        b.set("jwt");
        assert_eq!(a.get().as_deref(), Some("jwt"));
        assert!(a.ptr_eq(&b));
        a.clear();
        assert!(!b.is_set());
    }

    #[test]
    fn debug_redacts_token() {
        let a = AccessToken::new();
        a.set("super-secret-jwt");
        let dbg = format!("{:?}", a);
        assert!(!dbg.contains("super-secret-jwt"), "{}", dbg);
        assert!(dbg.contains("redacted"), "{}", dbg);
    }

    #[test]
    fn survives_poisoned_lock() {
        let a = AccessToken::new();
        let b = a.clone();
        let _ = std::thread::spawn(move || {
            let _guard = b.inner.write().unwrap();
            panic!("poison the lock");
        })
        .join();
        a.set("after-poison");
        assert_eq!(a.get().as_deref(), Some("after-poison"));
    }
}
