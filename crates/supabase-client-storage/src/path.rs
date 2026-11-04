//! Validation of bucket ids and object paths that end up in request URLs.
//!
//! Each piece is pushed as its own URL path segment (so `?`, `#`, `%` and
//! spaces are percent-encoded), and `.`/`..`/empty segments are rejected so a
//! caller-supplied name can never move the request to another endpoint.

use crate::error::StorageError;

/// Validate a bucket id: one non-empty segment that is not `.` or `..`.
pub(crate) fn bucket_segment(id: &str) -> Result<&str, StorageError> {
    if id.is_empty() || id == "." || id == ".." || id.contains('/') {
        return Err(StorageError::InvalidPath(format!(
            "invalid bucket id {:?}: must be a single non-empty path segment other than \".\" or \"..\"",
            id
        )));
    }
    Ok(id)
}

/// Split an object path on `/`, rejecting empty, `.` and `..` segments.
pub(crate) fn object_segments(path: &str) -> Result<Vec<&str>, StorageError> {
    if path.is_empty() {
        return Err(StorageError::InvalidPath("object path is empty".into()));
    }
    let segments: Vec<&str> = path.split('/').collect();
    for seg in &segments {
        if seg.is_empty() || *seg == "." || *seg == ".." {
            return Err(StorageError::InvalidPath(format!(
                "invalid object path {:?}: segments must be non-empty and not \".\" or \"..\"",
                path
            )));
        }
    }
    Ok(segments)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_rejects_traversal() {
        for bad in ["", ".", "..", "a/b", "../../rest/v1/x"] {
            assert!(bucket_segment(bad).is_err(), "{:?}", bad);
        }
        assert_eq!(bucket_segment("avatars").unwrap(), "avatars");
        assert_eq!(bucket_segment("a b?c#d").unwrap(), "a b?c#d");
    }

    #[test]
    fn object_rejects_traversal() {
        for bad in ["", "/a", "a/", "a//b", "../x", "a/../b", "a/./b", "."] {
            assert!(object_segments(bad).is_err(), "{:?}", bad);
        }
        assert_eq!(
            object_segments("dir/a b#c.png").unwrap(),
            vec!["dir", "a b#c.png"]
        );
        assert_eq!(object_segments("...").unwrap(), vec!["..."]);
    }
}
