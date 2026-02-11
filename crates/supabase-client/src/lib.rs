// Re-export core (always available)
pub use supabase_client_core::*;

// Re-export query builder (feature-gated)
#[cfg(feature = "query")]
pub use supabase_client_query::*;

// Re-export derive macros (feature-gated)
#[cfg(feature = "derive")]
pub use supabase_client_derive::*;

// Re-export future phase crates
#[cfg(feature = "auth")]
pub use supabase_client_auth;

#[cfg(feature = "realtime")]
pub use supabase_client_realtime;

#[cfg(feature = "storage")]
pub use supabase_client_storage;

/// Prelude module for convenient imports.
///
/// ```ignore
/// use supabase_client::prelude::*;
/// ```
pub mod prelude {
    pub use supabase_client_core::{
        Row, SupabaseClient, SupabaseConfig, SupabaseError, SupabaseResponse, SupabaseResult,
    };
    pub use supabase_client_core::row;

    #[cfg(feature = "query")]
    pub use supabase_client_query::{
        Filterable, Modifiable, OrderDirection, IsValue, TextSearchType,
        SupabaseClientQueryExt, Table,
    };

    #[cfg(feature = "derive")]
    pub use supabase_client_derive::Table;
}
