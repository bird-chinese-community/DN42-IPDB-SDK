# Contract fixtures

These synthetic MMDBs and JSON sidecars describe only `172.20.0.0/24` and
`fd42:1234::/48`. They contain ASN 4242420001, `TestNetwork`, a claimed US/CA
location, a DE registration country, and explicit observation examples.
They exercise GeoIP2 country, city, ASN and connection-type reader APIs and
the DN42 schema version 2 extension. They contain no measured host evidence.

The generator's standard exporter produced the fixtures on 2026-11-10.
The six data files are copied into the Go, Python and Rust package tests so
their source archives can run independently. The CI contract check compares
these copies with this directory by SHA-256.

ISO name data is covered by [the Unicode license](LICENSE-Unicode.txt).
