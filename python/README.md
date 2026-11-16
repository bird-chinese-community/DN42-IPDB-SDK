# dn42-ipdb

```sh
pip install dn42-ipdb
```

```python
import asyncio
from dn42_ipdb import asns, download_release, lookup, lookup_asn, open_cached_bundle


async def main():
    update = await download_release(".cache/dn42")
    print(update["changed"], update["directory"])
    bundle = open_cached_bundle(".cache/dn42")
    print(lookup(bundle, "172.23.33.0"))
    print(lookup_asn(bundle, 4242420803))
    print(len(asns(bundle)))


asyncio.run(main())
```

## Bundle

`open_bundle(directory)` and `open_cached_bundle(cache_dir)` return a `Bundle`
named tuple (`readers`, `asns`, `release`). Both are plain functions: each of the
seven release files is read once and kept in memory, so lookups perform no
I/O and there is nothing to close.

- `lookup(bundle, ip)` returns `{"ip", "records"}`. `ip` is canonical
  (dotted quad, or lowercase compressed IPv6). IPv4-mapped IPv6 addresses
  are converted to IPv4. Zone identifiers are rejected. `records` maps the
  database key (`country`, `city`, `asn`, `connection_type`) to
  `{"network", "prefix_length", "data"}` for each database with a record.
  `network` is the matched CIDR in the address family of `ip`.
- `lookup_asn(bundle, asn)` returns the `AsnInfo` record or `None`. `asn` must be
  an integer in 0..4294967295 (not a `bool`).
- `asns(bundle)` returns every `AsnInfo` ordered by ASN.
- `metadata(bundle)` returns the MMDB metadata of each database;
  `release_metadata(bundle)` returns the typed release metadata. Unknown keys
  are kept in the dictionary.

`Observation`, `RegisteredCountry`, `AsnInfo`, `Match`, `LookupResult`,
`ReleaseMetadata`, `DatabaseMetadata` and `DownloadResult` are `TypedDict` types.

A bundle directory is valid when all seven files exist, `metadata.json` and
`asn-index.json` use schema version `"2"`, every ASN record matches its key,
and each MMDB has the required `database_type` (also the one listed in
`metadata.json`, if any). Optional fields may be absent but not `null`. A
missing file raises `InvalidBundleError` naming the file, with
`FileNotFoundError` as its cause, in `open_bundle` and `open_cached_bundle`.

## Download

`download_release(cache_dir, *, base_url=DEFAULT_RELEASE_URL, timeout=30)`
returns `{"directory", "changed", "recovered_cache", "bundle"}`. `bundle` is built
from the verified bytes; `changed` is `False` when the cached bundle already
matches `checksums.json`. `recovered_cache` is `True` when an unreadable
`current.json` or a damaged cached bundle was replaced.

- The cache lives in `cache_dir/python/v2`. `current.json` names the active
  bundle directory, which is the SHA-256 of the sorted file checksums. The
  current and previous bundle are kept; other complete bundle directories,
  `.stage-*` and `.current-*` entries are removed. Files are written with mode
  0600 and directories with 0700.
- `.update.lock` serializes writers. A writer waits for it until the
  `timeout` expires and then raises `LockTimeoutError`. Readers take no
  lock. If the pointer moves while a reader works, it re-reads the pointer
  and retries up to three attempts.
- `base_url` must use HTTPS, or HTTP to an IPv4 `127.0.0.0/8` literal or
  `[::1]`, with no `@` in the authority and no `?` or `#`. A missing trailing `/`
  is added. At most 10 redirects are followed, each to HTTPS or to the same
  loopback HTTP origin. A redirect target may carry a query but no fragment and
  no `@` in the authority; an unparsable `Location` and a redirect response
  without `Location` raise `InvalidUrlError`.
- `timeout` is a number of seconds greater than 0 and at most 2147483 seconds;
  other values raise `ValueError`. It covers the lock
  wait and all requests. Cancelling the task or reaching the timeout stops the
  download before the pointer is switched. Once `current.json` is replaced, the
  call returns its result.
- On Windows the writer retries the pointer rename and the removal of old
  version directories every 50 ms while a reader has the files open, until the
  download is cancelled or times out.
- Requests use `urllib` and honor the proxy environment variables. Each
  database and `asn-index.json` is limited to 32 MiB, `metadata.json` and
  `LICENSE-Unicode.txt` to 1 MiB, `checksums.json` and `current.json` to 64 KiB.

## Errors

All SDK errors derive from `Dn42IpdbError`.

| Error                   | Also derives from    | Raised for                                   |
| ----------------------- | -------------------- | -------------------------------------------- |
| `InvalidAddressError`   | `ValueError`         | malformed IP, zone identifier                |
| `InvalidAsnError`       | `ValueError`         | ASN not an integer in range                  |
| `InvalidUrlError`       | `ValueError`         | base URL or redirect not allowed             |
| `InvalidBundleError`    | `ValueError`         | invalid or missing file (`.file`, `.reason`) |
| `ChecksumMismatchError` | `InvalidBundleError` | digest differs (`.file`)                     |
| `SizeLimitError`        | `ValueError`         | file or response over its limit              |
| `HttpStatusError`       |                      | status other than 200 (`.url`, `.status`)    |
| `LockTimeoutError`      | `TimeoutError`       | writer lock not acquired in time             |
| `CacheMissingError`     | `FileNotFoundError`  | no `current.json`                            |

## GeoIP2 readers

The bundle files also work with the official `geoip2` typed reader. Use its
memory mode on Windows with `maxminddb` 3.2.0:

```python
from geoip2.database import Reader
from maxminddb import MODE_MEMORY

with Reader("DN42-IPDB-ASN.mmdb", mode=MODE_MEMORY) as database:
    print(database.asn("172.23.33.0").autonomous_system_number)
```

The 3.2.0 Windows C extension can decode DN42's unsigned ASN values as
negative numbers. The [upstream correction](https://github.com/maxmind/MaxMind-DB-Reader-python/commit/51791b8b5d970f92dc7c5fa645bde2c7bd15475d)
is on its development branch. SDK CI validates all four official GeoIP2 typed
methods in memory mode on every platform, and its default mode on Linux and
macOS.

Copyright 2026 BIRD Chinese Community. MIT license.
