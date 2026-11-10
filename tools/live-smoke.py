import asyncio
import json
import os
import sys

from dn42_ipdb import (
    DEFAULT_RELEASE_URL,
    download_release,
    lookup,
    lookup_asn,
    open_cached_bundle,
    release_metadata,
)


async def main() -> None:
    cache_dir = sys.argv[1]
    update = await download_release(
        cache_dir,
        base_url=os.environ.get("DN42_IPDB_RELEASE_URL", DEFAULT_RELEASE_URL),
    )
    with open_cached_bundle(cache_dir) as bundle:
        ip = lookup(bundle, "172.23.33.0")
        assert ip["records"]["asn"]["data"]["autonomous_system_number"] == 4242420803
        asn = lookup_asn(bundle, 4242420803)
        assert asn is not None and asn["asn"] == 4242420803
        assert release_metadata(bundle)["schema_version"] == "2"
        print(json.dumps({"update": update, "ip": ip, "asn": asn}))


if __name__ == "__main__":
    asyncio.run(main())
