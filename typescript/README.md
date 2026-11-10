# @birdcc/dn42-ipdb

Requires Node.js 20.18.3 or newer. Development checks use Node.js 24; the
compiled contract tests also run on the minimum supported runtime.

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
The optional `data.dn42.ptr_hints` property is typed as `PtrHints` and preserves
candidate cities, matching methods and DNS/catalog provenance.

`downloadRelease` accepts `baseURL`, `timeoutMs` and `signal`. It permits HTTPS
mirrors and loopback HTTP for tests. The default update timeout is 30 seconds.
Each database or JSON sidecar is limited to 32 MiB, and the checksum manifest
to 64 KiB. The TypeScript cache lives under `cacheDir/typescript/v2`.

Consumers that require an HTTP proxy can configure their fetch dispatcher
with a compatible Undici `ProxyAgent` before calling `downloadRelease`.

Copyright 2026 BIRD Chinese Community. MIT license.
