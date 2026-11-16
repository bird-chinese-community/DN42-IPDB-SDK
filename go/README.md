# DN42 IPDB Go SDK

```sh
go get github.com/bird-chinese-community/DN42-IPDB-SDK/go
```

```go
update, err := ipdb.Download(ctx, ipdb.DownloadOptions{CacheDir: ".cache/dn42"})
if err != nil { return err }
database := update.Database // the caller closes it
defer database.Close()
result, err := database.Lookup("172.23.33.0")
if err != nil { return err }
fmt.Println(result.Records["asn"].Network, result.Records["asn"].Data)
info, found := database.LookupASN(4242420803)
fmt.Println(info.ASN, found)
```

Import the package as `ipdb` from
`github.com/bird-chinese-community/DN42-IPDB-SDK/go`. Go 1.26 or newer is required.

## Opening a bundle

- `Open(directory)` reads the seven files of a release directory once and validates them.
- `OpenCached(cacheDir)` opens the current cached bundle without networking and
  without the writer lock. It compares each file with the SHA-256 digests in
  `current.json` and retries up to three times in total when `current.json`
  moves to another version during the read.

The seven files are `DN42-IPDB-Country.mmdb`, `DN42-IPDB-City.mmdb`,
`DN42-IPDB-ASN.mmdb`, `DN42-IPDB-Connection-Type.mmdb`, `asn-index.json`,
`metadata.json` and `LICENSE-Unicode.txt`. Each database must carry its
required `database_type`. `metadata.json` and `asn-index.json` need
`schema_version` `"2"`; every ASN key equals the decimal `asn` of its record, and
`database_types` in the metadata, when present, must match the databases.
Required fields of the metadata, of every ASN record, observation and registered
country must be present. `asn-index.json` may not contain a JSON `null` anywhere,
and neither may the known fields of `metadata.json` (`route_observed_at` needs
string `first` and `last`; the values of `database_types` are strings). A
`null` makes the bundle invalid. A missing release
file is an `ErrInvalidBundle` error naming the file, with `os.ErrNotExist` in
the chain; only a missing `current.json` is `ErrCacheMissing`.
Each `.mmdb` file and `asn-index.json` is limited to 32 MiB, `metadata.json` and
`LICENSE-Unicode.txt` to 1 MiB, `current.json` and `checksums.json` to 64 KiB.

## Lookups

- `Lookup(ip string) (Result, error)` accepts IPv4 and IPv6 text. Zone identifiers
  and invalid input return `ErrInvalidAddress`. IPv4-mapped IPv6 addresses are
  converted to IPv4. `Result.IP` is canonical: dotted quad for IPv4, lowercase
  compressed form for IPv6.
- `Result.Records` maps `country`, `city`, `asn` and `connection_type` to a `Match`
  for each database that has a record. A `Match` has `Network` (the matched CIDR in
  the family of the address), `PrefixLength` and `Data` (the decoded record).
- `LookupASN(asn uint32) (AsnInfo, bool)` and `ASNs() []AsnInfo` (ascending by
  ASN) return observations for member prefixes. Network types describe those
  prefixes, not the whole AS.
- `ReleaseMetadata()` returns `ReleaseMetadata` with the typed fields
  `SchemaVersion`, `ReleaseRepository`, `Copyright`, `ReleaseTag`, `ReleaseURL`,
  `BuiltAt`, `RegistryCommit`, `RegistryCommittedAt`, `RouteObservedAt` and
  `DatabaseTypes`. `Raw` holds the whole document; numbers are `json.Number`.
- `Metadata()` returns the MMDB metadata of each database key.

## Downloading

`Download(ctx, DownloadOptions{CacheDir, BaseURL, Timeout})` refreshes the cache
under `CacheDir/go/v2` and returns `DownloadResult`:

- `Directory`: the version directory.
- `Changed`: false when the cached version already matches the release.
- `RecoveredCache`: true when an unreadable `current.json` or missing or damaged
  cached files were replaced.
- `Database`: the bundle built from the verified bytes. The caller closes it.

`BaseURL` defaults to the latest release of DN42-IPDB-Releases and may omit the
trailing slash. It must not contain credentials (including empty user info such as
`https://@host/`), a query or a fragment (including an empty `?` or `#`). HTTPS
is accepted for any host; HTTP only for an IPv4 `127.0.0.0/8` literal or `[::1]`
(IPv4-mapped IPv6 addresses are rejected).
Redirects are limited to ten hops. Each hop has no credentials and no fragment and
uses HTTPS, or HTTP to the same host and port as a loopback HTTP base URL; a hop
may carry a query. An unparsable `Location` and a redirect response without
`Location` return `ErrInvalidURL`.

`Timeout` defaults to 30 seconds and covers the writer-lock wait and all requests;
the caller's context cancels the same work. Writers hold an exclusive lock on
`.update.lock` and wait for it, so concurrent downloads run one after another. A
lock wait that reaches the deadline returns `ErrLockTimeout`.

A download fetches `checksums.json`, downloads the seven files into a `.stage-*`
directory, verifies their SHA-256 digests and validates the bundle. The version
directory is named by the SHA-256 of the compact checksum JSON (keys sorted).
Before the pointer switches, the cache removes leftover `.stage-*` and
`.current-*` entries and version directories other than the new and the
previous one that hold exactly the seven bundle files. The pointer
`current.json` is replaced atomically. Files are created with mode 0600 and
directories with mode 0700.

Readers take no lock. On Windows, Go opens files without delete sharing, so a
reader can block the writer's rename of `current.json` and removal of old version
directories; the writer then retries those operations every 50 ms until the
download deadline or cancellation.

## Errors

Errors wrap one of these sentinels, matched with `errors.Is`: `ErrInvalidAddress`,
`ErrInvalidURL`, `ErrInvalidBundle`, `ErrChecksumMismatch`, `ErrSizeLimit`,
`ErrHTTPStatus`, `ErrLockTimeout` and `ErrCacheMissing`. The underlying error
(for example `os.ErrNotExist` or `context.DeadlineExceeded`) stays in the chain.

Copyright 2026 BIRD Chinese Community. MIT license.
