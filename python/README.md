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
under `cache_dir/python`.

Copyright 2026 BIRD Chinese Community. MIT license.
