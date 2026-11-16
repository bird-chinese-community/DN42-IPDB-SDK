# DN42 IPDB SDK

Go, TypeScript, Python and Rust SDKs for the [BIRDCC DN42 IPDB releases](https://github.com/bird-chinese-community/DN42-IPDB-Releases).

- [Go](go/README.md): `github.com/bird-chinese-community/DN42-IPDB-SDK/go`
- [TypeScript](typescript/README.md): `@birdcc/dn42-ipdb`
- [Python](python/README.md): `dn42-ipdb`
- [Rust](rust/README.md): `dn42-ipdb`

Each SDK reads Country, City, ASN and Connection-Type MMDBs with a maintained
MaxMind DB library. IP lookup returns the canonical address (IPv4-mapped IPv6
becomes IPv4) and, per database, the matched network, its prefix length, the
standard GeoIP2 fields and the `dn42` extension, including network types, PTR
names, ROA/IRR status and observations. ASN lookup and the ordered ASN list
read the release's `asn-index.json`. ASN network types describe observed
member prefixes; they do not classify an entire autonomous system.

The four database files are `DN42-IPDB-Country.mmdb`, `DN42-IPDB-City.mmdb`,
`DN42-IPDB-ASN.mmdb` and `DN42-IPDB-Connection-Type.mmdb`. A bundle opens
only when each database has its required type, both JSON sidecars use schema
version 2, `metadata.json` agrees with the database types it declares, and
every `asn-index.json` key matches its ASN. Each file is read once.

Optional `dn42.ptr_hints` records naming candidates separately from GeoFeed
location fields. Each hint retains its DNS observation time, catalog source
and matching method. PTR naming evidence does not independently confirm a
host's location.

Downloads are explicit. They fetch the checksum manifest, verify all four
MMDBs, both JSON sidecars and the Unicode attribution notice, and activate the
bundle through an atomic cache pointer. A download returns the verified bundle
it activated. Failed or cancelled downloads leave the previous pointer in
place, and a damaged pointer or cached release is replaced by the next
download. A cache retains the current and previous bundle, each in a directory
named by the SHA-256 of its checksums. SDKs use separate `<language>/v2`
subdirectories under the caller's cache directory.

Opening the cache takes no lock: readers verify every file against the pointer
and follow the pointer again when an update replaces the release during the
read. Updates take the cache's writer lock and wait for it until their timeout
(30 seconds by default, covering the wait and all requests). Each SDK reports
failures as categories: invalid address, ASN, URL or bundle, checksum
mismatch, size limit, HTTP status, lock timeout and missing cache.

Country and subdivision names come from ISO data. GeoFeed location claims and
network observations retain their sources and timestamps. Missing evidence
stays unknown. Public resolver observations describe the measured target and
query; they do not establish unrestricted recursive access.

SDK code is copyright 2026 BIRD Chinese Community and licensed under MIT.
Database attribution and source terms are recorded in each release's metadata.

GitHub Actions checks the SDKs on Linux, macOS and Windows. `tools/check.sh`
runs the same checks in a remote checkout. Contract fixtures contain synthetic
IPv4 and IPv6 networks and are shared across the four language packages.

After the first `v0.1.0` release, pushes to `main` prepare a shared version
with Knope, check the generated manifests and dispatch `release.yml` on its
version tag. The version workflow also accepts an explicit semantic version.
Release assets include the npm tarball, Python wheel and source archive, and
Rust crate; Go uses the matching `go/v*` module tag.

Registry publishing uses GitHub OIDC. Each registry's trusted publisher must
bind this repository, `release.yml`, and its GitHub environment: `npm`, `pypi`
or `crates`. Create the initial package where the registry requires it before
enabling its trusted publisher.
