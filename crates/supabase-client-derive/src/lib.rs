extern crate proc_macro;

mod parse;
mod table_impl;

use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

/// Derive the `Table` trait for a struct.
///
/// # Attributes
///
/// ## Struct-level: `#[table(...)]`
/// - `name = "table_name"` - Database table name (defaults to snake_case of struct name)
/// - `schema = "schema_name"` - Database schema (defaults to "public")
///
/// ## Field-level: `#[primary_key]` / `#[primary_key(auto_generate)]`
/// - Marks a field as part of the primary key
/// - `auto_generate` excludes it from inserts (e.g., serial/identity columns)
///
/// ## Field-level: `#[column(...)]`
/// - `name = "col_name"` - Database column name (defaults to field name)
/// - `skip` - Skip this field entirely
/// - `auto_generate` - Exclude from inserts (e.g., auto-populated columns)
///
/// # Example
///
/// ```ignore
/// #[derive(Table, sqlx::FromRow)]
/// #[table(name = "cities")]
/// struct City {
///     #[primary_key(auto_generate)]
///     pub id: i32,
///     #[column(name = "name")]
///     pub name: String,
///     pub country_id: i32,
/// }
/// ```
#[proc_macro_derive(Table, attributes(table, primary_key, column))]
pub fn derive_table(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match table_impl::expand_table_derive(&input) {
        Ok(tokens) => tokens.into(),
        Err(e) => e.to_compile_error().into(),
    }
}
