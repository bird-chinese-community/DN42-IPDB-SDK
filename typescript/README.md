# @birdcc/dn42-ipdb

Requires Node.js 20.18.3 or newer. Development checks use Node.js 24; the
compiled contract tests also run on the minimum supported runtime.

```sh
npm install @birdcc/dn42-ipdb
```

```typescript
import { downloadRelease, isDn42IpdbError, openCachedBundle } from "@birdcc/dn42-ipdb";

const update = await downloadRelease({ cacheDir: ".cache/dn42" });
const database = update.bundle;
console.log(database.lookup("172.23.33.0"));
console.log(database.lookupAsn(4242420803));
console.log(database.releaseMetadata().release_tag);
database.close();

try {
  (await openCachedBundle(".cache/dn42")).close();
} catch (error) {
  if (isDn42IpdbError(error, "DN42_CACHE_MISSING"))
    console.log("no release cached yet");
  else throw error;
}
```

## Reading

`openBundle(directory)` reads a release directory. `openCachedBundle(cacheDir)`
reads the current cached release without network access or locks; it compares
every file with the checksums in the cache pointer and retries when an update
switches the pointer during the read. Each file is read once.

Lookups are synchronous. `lookup(ip)` returns the canonical address
(IPv4-mapped IPv6 input becomes IPv4, IPv6 is printed in RFC 5952 form) and one
record per database that matches. Each record has `network` (the matched CIDR),
`prefix_length` and `data`. Databases without a record are absent.

| Method              | Returns                                                        |
| ------------------- | -------------------------------------------------------------- |
| `lookup(ip)`        | `{ ip, records: { country?, city?, asn?, connection_type? } }` |
| `lookupAsn(asn)`    | the `asn-index.json` entry, or `undefined`                     |
| `asns()`            | every ASN entry, ordered by number                             |
| `releaseMetadata()` | `metadata.json`, with typed release fields                     |
| `metadata()`        | MMDB metadata of the four databases                            |
| `close()`           | marks the bundle closed; later calls throw `DN42_CLOSED`       |

The optional `data.dn42.ptr_hints` property is typed as `PtrHints` and
preserves candidate cities, matching methods and DNS/catalog provenance.

Opening checks the database type of each MMDB, the `schema_version` of both
JSON sidecars, the `database_types` declared in `metadata.json`, and that each
`asn-index.json` key matches its ASN.

## Updating

`downloadRelease({ cacheDir, baseURL?, timeoutMs?, signal? })` fetches
`checksums.json`, downloads the seven release files, verifies them and switches
the cache pointer atomically. It returns `{ directory, changed, recoveredCache,
bundle }`; `bundle` is the verified release, so callers do not reopen it.
When the release is unchanged, no database file is downloaded.
`recoveredCache` is true when the previous pointer or cached files were
unreadable and have been replaced.

The cache lives under `cacheDir/typescript/v2`. Release directories are named
by the SHA-256 of their checksums, and the cache keeps the current and previous
release. Concurrent updates wait for each other through `.update.lock`; the
timeout (30 seconds by default, an integer number of milliseconds up to
2147483647) covers that wait and all requests.

HTTPS mirrors are accepted. HTTP is accepted only for loopback IP addresses
(`127.0.0.0/8` and `::1`), for tests. Base URLs cannot contain user info, a
query or a fragment. Up to 10 redirects are followed; each target must use
HTTPS, or HTTP to the host and port of a loopback base URL, and cannot contain
user info or a fragment. Databases and `asn-index.json` are limited to 32 MiB,
`metadata.json` and the Unicode notice to 1 MiB, and the checksum manifest to
64 KiB.

Consumers that require an HTTP proxy can configure their fetch dispatcher
with a compatible Undici `ProxyAgent` before calling `downloadRelease`.

## Errors

SDK errors are `Error` objects with a `code`: `DN42_INVALID_ADDRESS`,
`DN42_INVALID_ASN`, `DN42_INVALID_URL`, `DN42_INVALID_BUNDLE`,
`DN42_CHECKSUM_MISMATCH`, `DN42_SIZE_LIMIT`, `DN42_HTTP_STATUS`,
`DN42_LOCK_TIMEOUT`, `DN42_CACHE_MISSING` or `DN42_CLOSED`.
`isDn42IpdbError(error, code?)` checks them. Cancellation and timeouts reject
with the signal's reason.

Copyright 2026 BIRD Chinese Community. MIT license.
