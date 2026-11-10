import assert from "node:assert/strict";
import { downloadRelease, openCachedBundle } from "@birdcc/dn42-ipdb";

const cacheDir = process.argv[2];
assert(cacheDir, "Pass an isolated cache directory");
const update = await downloadRelease({
  cacheDir,
  baseURL: process.env.DN42_IPDB_RELEASE_URL,
});
const bundle = await openCachedBundle(cacheDir);
try {
  const ip = bundle.lookup("172.23.33.0");
  assert.equal(ip.records.asn?.data.autonomous_system_number, 4242420803);
  assert.equal(bundle.lookupAsn(4242420803)?.asn, 4242420803);
  assert.equal(bundle.releaseMetadata().schema_version, "2");
  console.log(JSON.stringify({ update, ip, asn: bundle.lookupAsn(4242420803) }));
} finally {
  bundle.close();
}
