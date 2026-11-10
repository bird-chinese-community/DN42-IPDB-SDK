# DN42 IPDB Go SDK

```sh
go get github.com/bird-chinese-community/DN42-IPDB-SDK/go
```

```go
_, err := ipdb.Download(ctx, ipdb.DownloadOptions{CacheDir: ".cache/dn42"})
if err != nil { return err }
database, err := ipdb.OpenCached(".cache/dn42")
if err != nil { return err }
defer database.Close()
result, err := database.Lookup("172.23.33.0")
if err != nil { return err }
fmt.Println(result)
asn, found := database.LookupASN(4242420803)
fmt.Println(asn, found)
```

Import the package as `ipdb` from
`github.com/bird-chinese-community/DN42-IPDB-SDK/go`. Go 1.26 or newer is required.
`OpenCached(cacheDir)` verifies and reads the current cache without networking.
`Metadata()` returns per-database MMDB metadata; `ReleaseMetadata()` returns
the release JSON metadata. Each IP match contains `prefix_length` and `data`.

`Download` accepts a caller context, HTTPS `BaseURL`, and `Timeout` (default
30 seconds). Loopback HTTP is accepted for tests. Each database or JSON
sidecar is limited to 32 MiB and the checksum manifest to 64 KiB. The Go cache
lives under `CacheDir/go` and retains the current and previous bundle.

Copyright 2026 BIRD Chinese Community. MIT license.
