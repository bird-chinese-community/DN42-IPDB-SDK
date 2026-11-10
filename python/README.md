# dn42-ipdb

```sh
pip install dn42-ipdb
```

```python
import asyncio
from dn42_ipdb import download_release, lookup, lookup_asn, open_cached_bundle


async def main():
    await download_release(".cache/dn42")
    with open_cached_bundle(".cache/dn42") as database:
        print(lookup(database, "172.23.33.0"))
        print(lookup_asn(database, 4242420803))


asyncio.run(main())
```

`open_cached_bundle(cache_dir)` opens the verified current bundle without
network activity. `metadata(bundle)` returns MMDB metadata and
`release_metadata(bundle)` returns the release JSON metadata. A match contains
`prefix_length` and `data`. Unknown IP networks are absent from `records`;
unknown ASNs return `None`.

`download_release` accepts a `base_url` HTTPS mirror and a `timeout` in seconds.
Loopback HTTP is accepted for tests. The default timeout is 30 seconds and
task cancellation stops pending downloads. Each database or JSON sidecar is
limited to 32 MiB; the checksum manifest to 64 KiB. The Python cache lives
under `cache_dir/python/v2`.

The SDK reads verified bytes with MaxMind's pure Python `MODE_FD` reader.
The official `geoip2` typed reader also supports the bundle. Use its memory
mode on Windows with `maxminddb` 3.2.0:

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
