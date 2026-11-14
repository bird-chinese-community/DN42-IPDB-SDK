import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { fork } from "node:child_process";
import { once } from "node:events";
import { readFile, readdir, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { downloadRelease, openBundle, openCachedBundle } from "../src/index.ts";

const fixtures = fileURLToPath(new URL("../../testdata/", import.meta.url));
const files = [
  "DN42-IPDB-Country.mmdb",
  "DN42-IPDB-City.mmdb",
  "DN42-IPDB-ASN.mmdb",
  "DN42-IPDB-Connection-Type.mmdb",
  "asn-index.json",
  "metadata.json",
  "LICENSE-Unicode.txt",
];
const scratch = fileURLToPath(
  new URL("../../.cache/typescript-tests/", import.meta.url),
);
await mkdir(scratch, { recursive: true });

async function fixtureServer() {
  const bytes = new Map(
    await Promise.all(
      files.map(async (file) => [file, await readFile(join(fixtures, file))] as const),
    ),
  );
  const requests: string[] = [];
  let failedFile: string | undefined;
  let stalled = false;
  let invalidManifest = false;
  let invalidChecksum = false;
  let redirect: string | undefined;
  const server = createServer((request, response) => {
    const file = new URL(request.url ?? "/", "http://localhost").pathname.slice(1);
    requests.push(file);
    if (redirect) {
      response.writeHead(302, { location: redirect }).end();
      return;
    }
    if (file === failedFile) {
      response.writeHead(503).end();
      return;
    }
    if (stalled && file === "DN42-IPDB-City.mmdb") {
      response.writeHead(200);
      response.flushHeaders();
      return;
    }
    if (file === "checksums.json") {
      const manifest: Record<string, string> = invalidManifest
        ? {}
        : Object.fromEntries(
            [...bytes].map(([name, data]) => [
              name,
              createHash("sha256").update(data).digest("hex"),
            ]),
          );
      if (invalidChecksum) manifest["DN42-IPDB-City.mmdb"] = "0".repeat(64);
      response.end(JSON.stringify(manifest));
      return;
    }
    const data = bytes.get(file);
    if (data) response.end(data);
    else response.writeHead(404).end();
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert(address && typeof address !== "string");
  return {
    bytes,
    requests,
    baseURL: `http://127.0.0.1:${address.port}/`,
    fail(file?: string) {
      failedFile = file;
    },
    stall() {
      stalled = true;
    },
    badManifest() {
      invalidManifest = true;
    },
    badChecksum() {
      invalidChecksum = true;
    },
    redirect(location: string) {
      redirect = location;
    },
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    },
  };
}

await test("reads IPv4, IPv6, ASN index, GeoIP2 names and DN42 evidence locally", async () => {
  const database = await openBundle(fixtures);
  try {
    for (const ip of ["172.20.0.1", "fd42:1234::1"]) {
      const result = database.lookup(ip);
      assert.equal(result.records.asn?.data.autonomous_system_number, 4242420001);
      assert.equal(result.records.city?.data.dn42?.schema_version, "2");
      assert.deepEqual(result.records.city?.data.dn42?.origins, [
        { asn: 4242420001, as_name: "TestNetwork" },
      ]);
      assert.equal(result.records.city?.data.country?.names?.en, "United States");
    }
    assert.equal(database.lookupAsn(4242420001)?.asn, 4242420001);
    assert.equal(database.lookupAsn(4242420999), undefined);
    assert.deepEqual(database.lookup("203.0.113.1").records, {});
    assert.throws(() => database.lookup("not-an-ip"), /Invalid IP/);
    assert.throws(() => database.lookupAsn(-1), /Invalid ASN/);
    assert.match(database.releaseMetadata().release_repository, /DN42-IPDB-Releases/);
    assert.equal(Object.keys(database.metadata()).length, 4);
  } finally {
    database.close();
  }
  assert.throws(() => database.lookup("172.20.0.1"), /closed/);
});

await test("rejects a redirect before requesting an insecure target", async () => {
  const source = await fixtureServer();
  const target = await fixtureServer();
  const cacheDir = await mkdtemp(join(scratch, "redirect-"));
  source.redirect(`${target.baseURL}checksums.json`);
  try {
    await assert.rejects(
      downloadRelease({ cacheDir, baseURL: source.baseURL }),
      /Insecure release redirect/,
    );
    assert.equal(source.requests.length, 1);
    assert.equal(target.requests.length, 0);
  } finally {
    await source.close();
    await target.close();
    await rm(cacheDir, { recursive: true });
  }
});

await test("initializes v2 beside an existing language cache", async () => {
  const server = await fixtureServer();
  const cacheDir = await mkdtemp(join(scratch, "layout-"));
  const existing = join(cacheDir, "typescript", "current.json");
  await mkdir(join(cacheDir, "typescript"));
  await writeFile(existing, "existing cache layout");
  try {
    const result = await downloadRelease({ cacheDir, baseURL: server.baseURL });
    assert.equal(result.changed, true);
    assert.equal(join(result.directory, ".."), join(cacheDir, "typescript", "v2"));
    assert.equal(await readFile(existing, "utf8"), "existing cache layout");
    const database = await openCachedBundle(cacheDir);
    assert.equal(database.lookupAsn(4242420001)?.asn, 4242420001);
    database.close();
  } finally {
    await server.close();
    await rm(cacheDir, { recursive: true });
  }
});

await test("downloads a complete verified bundle and reuses it without database requests", async () => {
  const server = await fixtureServer();
  const cacheDir = await mkdtemp(join(scratch, "cache-"));
  try {
    const first = await downloadRelease({ cacheDir, baseURL: server.baseURL });
    assert.equal(first.changed, true);
    assert.equal(server.requests.length, 8);
    const second = await downloadRelease({ cacheDir, baseURL: server.baseURL });
    assert.deepEqual(second, { directory: first.directory, changed: false });
    assert.equal(server.requests.length, 9);
    const cached = await openCachedBundle(cacheDir);
    assert.equal(cached.lookupAsn(4242420001)?.asn, 4242420001);
    cached.lookup("172.20.0.1");
    cached.close();
    assert.equal(server.requests.length, 9);
  } finally {
    await server.close();
    await rm(cacheDir, { recursive: true });
  }
});

await test("preserves the active bundle after partial downloads, wrong types and bad manifests", async () => {
  const server = await fixtureServer();
  const cacheDir = await mkdtemp(join(scratch, "failure-"));
  try {
    await downloadRelease({ cacheDir, baseURL: server.baseURL });
    const pointer = join(cacheDir, "typescript/v2/current.json");
    const original = await readFile(pointer, "utf8");
    server.bytes.set(
      "metadata.json",
      Buffer.from(
        JSON.stringify({
          schema_version: "2",
          release_repository: "test",
          copyright: "BIRDCC",
          revision: 1,
        }),
      ),
    );
    server.fail("DN42-IPDB-ASN.mmdb");
    await assert.rejects(downloadRelease({ cacheDir, baseURL: server.baseURL }), /503/);
    assert.equal(await readFile(pointer, "utf8"), original);
    server.fail();
    server.bytes.set(
      "DN42-IPDB-City.mmdb",
      await readFile(join(fixtures, "DN42-IPDB-ASN.mmdb")),
    );
    await assert.rejects(
      downloadRelease({ cacheDir, baseURL: server.baseURL }),
      /expected.*City/,
    );
    assert.equal(await readFile(pointer, "utf8"), original);
    server.badChecksum();
    await assert.rejects(
      downloadRelease({ cacheDir, baseURL: server.baseURL }),
      /Checksum mismatch/,
    );
    assert.equal(await readFile(pointer, "utf8"), original);
    server.badManifest();
    await assert.rejects(downloadRelease({ cacheDir, baseURL: server.baseURL }));
    assert.equal(await readFile(pointer, "utf8"), original);
    const cached = await openCachedBundle(cacheDir);
    assert.equal(cached.lookupAsn(4242420001)?.asn, 4242420001);
    cached.close();
  } finally {
    await server.close();
    await rm(cacheDir, { recursive: true });
  }
});

await test("cancels a streamed download before publishing the cache pointer", async () => {
  const server = await fixtureServer();
  const cacheDir = await mkdtemp(join(scratch, "abort-"));
  server.stall();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 80);
  try {
    await assert.rejects(
      downloadRelease({ cacheDir, baseURL: server.baseURL, signal: controller.signal }),
    );
    assert.equal(
      (await readdir(join(cacheDir, "typescript", "v2"))).includes("current.json"),
      false,
    );
  } finally {
    clearTimeout(timer);
    await server.close();
    await rm(cacheDir, { recursive: true });
  }
});

await test("retains two owned versions and preserves custom cache content", async () => {
  const server = await fixtureServer();
  const cacheDir = await mkdtemp(join(scratch, "retention-"));
  try {
    const first = await downloadRelease({ cacheDir, baseURL: server.baseURL });
    const reader = await openCachedBundle(cacheDir);
    const custom = join(cacheDir, "typescript", "v2", "f".repeat(64));
    await mkdir(custom);
    await writeFile(join(custom, "user-data.txt"), "keep");
    for (const revision of [1, 2, 3]) {
      server.bytes.set(
        "metadata.json",
        Buffer.from(
          JSON.stringify({
            schema_version: "2",
            release_repository: "test",
            copyright: "BIRDCC",
            revision,
          }),
        ),
      );
      await downloadRelease({ cacheDir, baseURL: server.baseURL });
    }
    const entries = await readdir(join(cacheDir, "typescript", "v2"));
    assert.equal(entries.filter((entry) => /^[0-9a-f]{64}$/.test(entry)).length, 3);
    assert.equal(await readFile(join(custom, "user-data.txt"), "utf8"), "keep");
    await assert.rejects(readFile(join(first.directory, "DN42-IPDB-City.mmdb")), {
      code: "ENOENT",
    });
    assert.equal(reader.lookupAsn(4242420001)?.asn, 4242420001);
    assert.equal(
      reader.lookup("172.20.0.1").records.city?.data.dn42?.schema_version,
      "2",
    );
    reader.close();
  } finally {
    await server.close();
    await rm(cacheDir, { recursive: true });
  }
});

await test("cached readers and updates honor the cross-process update lock", async () => {
  const server = await fixtureServer();
  const cacheDir = await mkdtemp(join(scratch, "lock-"));
  try {
    await downloadRelease({ cacheDir, baseURL: server.baseURL });
    const child = fork(fileURLToPath(new URL("./hold-lock.mjs", import.meta.url)), [
      join(cacheDir, "typescript", "v2"),
    ]);
    try {
      await once(child, "message");
      await assert.rejects(openCachedBundle(cacheDir), { code: "ELOCKED" });
      await assert.rejects(downloadRelease({ cacheDir, baseURL: server.baseURL }), {
        code: "ELOCKED",
      });
    } finally {
      child.send("release");
      await once(child, "exit");
    }
    const database = await openCachedBundle(cacheDir);
    assert.equal(database.lookupAsn(4242420001)?.asn, 4242420001);
    database.close();
  } finally {
    await server.close();
    await rm(cacheDir, { recursive: true });
  }
});

await test("recovers a malformed cache pointer after a complete verified download", async () => {
  const server = await fixtureServer();
  const cacheDir = await mkdtemp(join(scratch, "recovery-"));
  try {
    await downloadRelease({ cacheDir, baseURL: server.baseURL });
    await writeFile(join(cacheDir, "typescript/v2/current.json"), "{");
    const result = await downloadRelease({ cacheDir, baseURL: server.baseURL });
    assert.equal(result.changed, true);
    assert.equal(result.recoveredCache, true);
    const database = await openCachedBundle(cacheDir);
    assert.equal(database.lookupAsn(4242420001)?.asn, 4242420001);
    database.close();
  } finally {
    await server.close();
    await rm(cacheDir, { recursive: true });
  }
});
