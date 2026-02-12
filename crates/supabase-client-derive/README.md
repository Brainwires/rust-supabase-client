# supabase-client-derive

Derive macros for supabase-client (`#[derive(Table)]`).

> **Note:** This crate is part of the [`supabase-client-sdk`](https://crates.io/crates/supabase-client-sdk) workspace. Most users should depend on `supabase-client-sdk` with the `derive` feature (enabled by default) rather than using this crate directly.

## Key Features

- **`#[derive(Table)]`** proc macro — implements the `Table` trait for type-safe queries
- Struct-level attributes:
  - `#[table(name = "table_name")]` — custom table name (defaults to struct name in snake_case)
  - `#[table(schema = "schema_name")]` — custom schema
- Field-level attributes:
  - `#[primary_key]` — mark the primary key column
  - `#[primary_key(auto_generate)]` — exclude from inserts (serial/identity)
  - `#[column(name = "col_name")]` — custom column name
  - `#[column(skip)]` — exclude from table mapping
  - `#[column(auto_generate)]` — exclude from inserts

## Usage

```rust
use supabase_client_derive::Table;
use serde::Deserialize;

#[derive(Table, Deserialize, Debug)]
#[table(name = "cities")]
struct City {
    #[primary_key(auto_generate)]
    pub id: i32,
    pub name: String,
    pub country_id: i32,
}
```

## License

Licensed under either of [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0) or [MIT license](http://opensource.org/licenses/MIT) at your option.
