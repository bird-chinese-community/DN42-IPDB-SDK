# DN42 IPDB SDK

Go, TypeScript, Python and Rust SDKs for the [BIRDCC DN42 IPDB releases](https://github.com/bird-chinese-community/DN42-IPDB-Releases).

- [Go](go/README.md): `github.com/bird-chinese-community/DN42-IPDB-SDK/go`
- [TypeScript](typescript/README.md): `@birdcc/dn42-ipdb`
- [Python](python/README.md): `dn42-ipdb`
- [Rust](rust/README.md): `dn42-ipdb`

Each SDK reads Country, City, ASN and Connection-Type MMDBs with a maintained
MaxMind DB library. IP lookup returns standard GeoIP2 fields and the `dn42`
extension, including network types, PTR names, ROA/IRR status and observations.
ASN lookup reads the release's `asn-index.json`. ASN network types describe
observed member prefixes; they do not classify an entire autonomous system.

Downloads are explicit. They fetch the checksum manifest, verify all four
MMDBs, both JSON sidecars and the Unicode attribution notice, and activate the
bundle through an atomic cache pointer. Failed or cancelled downloads leave the previous
pointer in place. A cache retains the current and previous bundle. SDKs use
separate language subdirectories under the caller's cache directory.

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
