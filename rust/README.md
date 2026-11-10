# DN42 IPDB for Rust

Local IP and ASN lookup for the [BIRDCC DN42 IPDB releases](https://github.com/bird-chinese-community/DN42-IPDB-Releases).

```toml
[dependencies]
dn42-ipdb = "0.1"
```

```rust,no_run
use dn42_ipdb::{Bundle, Cache};

fn main() -> dn42_ipdb::Result<()> {
    let cache = Cache::new(".cache/dn42-ipdb")?;
    let update = cache.refresh()?;
    let database: Bundle = update.bundle;
    let ip = database.lookup_ip("172.20.0.53".parse().unwrap())?;
    println!("{ip:?}");
    if let Some(asn) = database.lookup_asn(4242420001) {
        println!("{:?}", asn.as_name);
    }
    Ok(())
}
```

`Bundle::open(directory)` reads Country, City, ASN and Connection-Type MMDBs,
`asn-index.json`, and `metadata.json` into memory and requires the associated
`LICENSE-Unicode.txt` notice. Lookups perform no network
requests. `lookup_ip` returns an IP address and a map of database matches,
each with its prefix length and decoded GeoIP2/DN42 data. `lookup_asn` returns
observations for member prefixes. Those observations do not classify an entire
autonomous system.

`Cache::new` uses the public release URL. `Cache::with_url` selects another
HTTPS base URL or an IP-literal loopback HTTP server. `refresh` downloads and
checks the seven files explicitly. `open_cached` checks and opens the existing
bundle. The cache uses `cache_root/rust/v2`, an OS file lock for reads and updates,
a staged bundle, an atomic pointer, and current/previous version retention.
Failed downloads preserve the active pointer and already loaded readers.

The update deadline defaults to 30 seconds. `with_timeout` selects a shorter
deadline. `refresh_with_cancel` accepts a cloneable `Cancellation` flag. It is
checked between blocking requests and body reads. An in-progress blocking read
can last until its remaining deadline. The manifest limit is 64 KiB and each
artifact limit is 32 MiB. MMDB types, sidecar schemas and SHA-256 hashes are
checked before activation. HTTPS redirects can include signed download URLs.

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo package --locked
```

SDK code is copyright 2026 BIRD Chinese Community and licensed under MIT.
Database attribution is retained in the release metadata. The bundled small
test databases use synthetic records and include the Unicode CLDR license.
