# DN42 IPDB for Rust

Local IP and ASN lookup for the [BIRDCC DN42 IPDB releases](https://github.com/bird-chinese-community/DN42-IPDB-Releases).

```toml
[dependencies]
dn42-ipdb = "0.3"
```

```rust,no_run
use dn42_ipdb::{Bundle, Cache};

fn main() -> dn42_ipdb::Result<()> {
    let cache = Cache::new(".cache/dn42-ipdb")?;
    let update = cache.refresh()?;
    let database: Bundle = update.bundle;
    let found = database.lookup_ip("172.20.0.53".parse().unwrap())?;
    for (key, record) in &found.records {
        println!("{key}: {}", record.network);
    }
    if let Some(asn) = database.lookup_asn(4242420001) {
        println!("{:?}", asn.as_name);
    }
    Ok(())
}
```

## Bundle

`Bundle::open(directory)` reads the seven release files once: the Country, City, ASN and
Connection-Type MMDBs, `asn-index.json`, `metadata.json` and `LICENSE-Unicode.txt`.
`dn42_ipdb::FILES` lists them. Each read checks that the path is a regular file and
enforces its size limit: 32 MiB for MMDBs and `asn-index.json`, 1 MiB for
`metadata.json` and the license, 64 KiB for `checksums.json` and `current.json`.
Validation failures are `Error::InvalidBundle { file, reason, source }`: schema version 2 in
the metadata and the ASN index, non-empty `release_repository` and `copyright`, every
ASN index key equal to the decimal `asn` of its record, each MMDB `database_type`
equal to the expected one and to the `database_types` entry in the metadata when
present. Optional fields (`release_tag`, `release_url`, `built_at`, `registry_commit`,
`registry_committed_at`, `route_observed_at`, `database_types`, `as_name` and an
observation's `asn` and `value`) may be absent but not `null`. A missing release file
is an `InvalidBundle` naming that file, with the not-found `io::Error` as `source`. A bundle keeps all data in memory and lookups perform no I/O.

- `lookup_ip(ip)` takes a `std::net::IpAddr`, converts IPv4-mapped IPv6 addresses to
  IPv4 and returns `IpLookup { ip, records }`. `records` maps the database key
  (`country`, `city`, `asn`, `connection_type`) to a `Match { network, prefix_length, data }`
  for each database with a non-empty record. `network` is the masked network of the
  match as a canonical CIDR string in the address family of `ip`; `data` is the decoded
  GeoIP2 and DN42 record.
- `lookup_asn(asn)` returns `Option<&AsnInfo>`; `asns()` iterates all records in
  ascending ASN order. The observations describe member prefixes and do not
  classify an entire autonomous system.
- `release_metadata()` returns a typed `ReleaseMetadata`: `schema_version`,
  `release_repository`, `copyright`, the optional `release_tag`, `release_url`,
  `built_at`, `registry_commit`, `registry_committed_at`, `route_observed_at` and
  `database_types`; other keys are kept in `extra`.
- `database_metadata()` returns the MaxMind metadata of each database.

## Cache

`Cache::new` uses the public release URL. `Cache::with_url` takes another base URL: HTTPS
for any host, or HTTP for a loopback IP literal (127.0.0.0/8 or ::1; IPv4-mapped IPv6
addresses do not count). Credentials, queries and fragments are rejected with
`Error::InvalidUrl`, judged on the raw text, so `https://@example.com/`,
`https://example.com/?` and `https://example.com/#` are rejected too. A missing trailing
slash is added. Redirects are followed up to 10 times; every `Location` must parse, be
HTTPS, or HTTP to the same loopback host and port as the base URL, and carry no
credentials (including an empty `@` user info) and no fragment. A redirect target may
have a query.

The cache lives in `<cache_root>/rust/v2`:

- `current.json` holds the active version and the seven checksums.
- `<version>/` holds the seven files. The version is the SHA-256 of the compact
  JSON object of the required checksums sorted by file name. Files are written with
  mode 0600 and directories with mode 0700 on Unix.
- `.update.lock` is the writer lock.

`open_cached` takes no lock. It reads `current.json`, reads the seven files of that
version once, compares their SHA-256 values with the pointer and builds the bundle
from those bytes. When a file is missing or differs because the pointer moved, it
reads `current.json` again and retries with the new version, up to three attempts.
A missing pointer is `Error::CacheMissing`; a missing file of the version is
`Error::InvalidBundle` naming it, with the not-found error as `source`; a changed file is
`Error::ChecksumMismatch`.

`refresh` and `refresh_with_cancel` take the exclusive lock on `.update.lock` and poll
until it is free, the deadline passes (`Error::LockTimeout`) or the `Cancellation`
is set. They then:

1. Download `checksums.json` and require a 64-digit digest for each of the seven files.
2. Return the current version with `changed: false` when the previous pointer has the
   same checksums and its files verify.
3. Otherwise download the files into a `.stage-*` directory, verify each SHA-256,
   build the bundle from the downloaded bytes, move the stage to its version
   directory, remove leftover `.stage-*` and `.current-*` entries and unreferenced
   bundle directories (the current and previous versions stay), and switch
   `current.json` with an atomic rename.

`Update` contains `directory`, `changed`, `recovered_cache` and the `bundle`.
`recovered_cache` is true when the previous pointer was unreadable or its version
directory was damaged and the cache was rebuilt. A failure before the rename leaves
the active pointer unchanged and removes a version directory created by that run.

The deadline defaults to 30 seconds. `with_timeout` accepts any positive duration the
platform clock can add to the current time and returns `Error::InvalidArgument` for
zero or larger values such as `Duration::MAX`; it covers the lock wait and all requests. `Cancellation` is a cloneable flag checked
between blocking requests and body reads, so a read in progress can last until the
remaining deadline. `Error::Timeout` reports an expired deadline and `Error::Cancelled` a
cancelled run.

## Errors

`Error` variants: `InvalidUrl`, `InvalidBundle { file, reason, source }`, `ChecksumMismatch { file }`,
`SizeLimit`, `HttpStatus { url, status }`, `LockTimeout`, `CacheMissing`, `Cancelled`,
`Timeout`, `InvalidArgument`, and `Io`, `Http` and `Maxmind` with the path, URL or file they
refer to and the underlying error as source.

## Checks

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo package --locked
```

SDK code is copyright 2026 BIRD Chinese Community and licensed under MIT.
Database attribution is retained in the release metadata. The bundled small
test databases use synthetic records and include the Unicode CLDR license.
