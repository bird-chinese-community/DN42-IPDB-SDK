# @birdcc/dn42-ipdb

```sh
npm install @birdcc/dn42-ipdb
```

```typescript
import { downloadRelease, openCachedBundle } from "@birdcc/dn42-ipdb";

await downloadRelease({ cacheDir: ".cache/dn42" });
const database = await openCachedBundle(".cache/dn42");
console.log(database.lookup("172.23.33.0"));
console.log(database.lookupAsn(4242420803));
console.log(database.releaseMetadata());
database.close();
```

`openCachedBundle(cacheDir)` loads the verified current bundle without a network
request. `openBundle(directory)` reads an existing release. Lookups are
synchronous and local after opening. Each matched record includes
`prefix_length` and `data`. `metadata()` returns the MMDB metadata by database.

`downloadRelease` accepts `baseURL`, `timeoutMs` and `signal`. It permits HTTPS
mirrors and loopback HTTP for tests. The default update timeout is 30 seconds.
Each database or JSON sidecar is limited to 32 MiB, and the checksum manifest
to 64 KiB. The TypeScript cache lives under `cacheDir/typescript`.

Copyright 2026 BIRD Chinese Community. MIT license.
