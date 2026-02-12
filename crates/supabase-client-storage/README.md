# supabase-client-storage

Storage HTTP client for supabase-client.

> **Note:** This crate is part of the [`supabase-client-sdk`](https://crates.io/crates/supabase-client-sdk) workspace. Most users should depend on `supabase-client-sdk` with the `storage` feature rather than using this crate directly.

## Key Features

- **`SupabaseClientStorageExt`** extension trait — adds `.storage()` to `SupabaseClient`
- **`StorageClient`** — Supabase Object Storage HTTP client via reqwest
- Bucket management: create, list, get, update, empty, delete
- File operations: upload, download, update, list, move, copy, remove
- File metadata (`info`) and existence checking (`exists`)
- Signed URLs for time-limited access and delegated uploads
- Public URL construction for public buckets
- Image transform options (resize, quality, format) on download, public URL, and signed URLs

## Usage

```rust
use supabase_client_storage::SupabaseClientStorageExt;
use supabase_client_storage::{BucketOptions, FileOptions};

let storage = client.storage()?;

// Upload a file
let file_api = storage.from("photos");
let data = std::fs::read("photo.png")?;
file_api.upload("folder/photo.png", data, FileOptions::new()
    .content_type("image/png")
    .upsert(true)
).await?;

// Download
let bytes = file_api.download("folder/photo.png").await?;
```

## License

Licensed under either of [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0) or [MIT license](http://opensource.org/licenses/MIT) at your option.
