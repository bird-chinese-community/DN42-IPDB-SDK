import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { fork } from "node:child_process";
import { once } from "node:events";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { createServer, type ServerResponse } from "node:http";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import {
  downloadRelease,
  isDn42IpdbError,
  openBundle,
  openCachedBundle,
  type Dn42IpdbErrorCode,
} from "../src/index.ts";

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
/** Content address of the shared fixtures, identical in every SDK language. */
const fixtureVersion =
  "ac95640bbd1d1c9d3f75239dbf7fd242b0c5f8fb5aa5332480220c904a22c157";
const scratch = fileURLToPath(
  new URL("../../.cache/typescript-tests/", import.meta.url),
);
await mkdir(scratch, { recursive: true });

const fails = (code: Dn42IpdbErrorCode) => (error: Error) =>
  isDn42IpdbError(error, code);

async function fixtureServer() {
  const bytes = new Map<string, Buffer>(
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
  const routes = new Map<string, (response: ServerResponse) => void>();
  const server = createServer((request, response) => {
    const file = new URL(request.url ?? "/", "http://localhost").pathname.slice(1);
    requests.push(file);
    const route = routes.get(file);
    if (route) {
      route(response);
      return;
    }
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
    port: address.port,
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
    route(file: string, handler: (response: ServerResponse) => void) {
      routes.set(file, handler);
    },
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    },
  };
}

async function withServer(
  name: string,
  run: (
    server: Awaited<ReturnType<typeof fixtureServer>>,
    cacheDir: string,
  ) => Promise<void>,
): Promise<void> {
  const server = await fixtureServer();
  const cacheDir = await mkdtemp(join(scratch, `${name}-`));
  try {
    await run(server, cacheDir);
  } finally {
    await server.close();
    await rm(cacheDir, { recursive: true });
  }
}

/** Copies the fixtures and rewrites one JSON sidecar. */
async function editedRelease(
  file: "metadata.json" | "asn-index.json",
  edit: (document: Record<string, unknown>) => void,
): Promise<string> {
  const directory = await mkdtemp(join(scratch, "edited-"));
  await cp(fixtures, directory, { recursive: true });
  const document: Record<string, unknown> = JSON.parse(
    await readFile(join(directory, file), "utf8"),
  );
  edit(document);
  await writeFile(join(directory, file), JSON.stringify(document));
  return directory;
}

const metadataRevision = (revision: number): Buffer =>
  Buffer.from(
    JSON.stringify({
      schema_version: "2",
      release_repository: "test",
      copyright: "BIRDCC",
      revision,
    }),
  );

const cacheEntries = async (cacheDir: string): Promise<string[]> =>
  readdir(join(cacheDir, "typescript", "v2"));

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
    assert.match(database.releaseMetadata().release_repository, /DN42-IPDB-Releases/);
    assert.deepEqual(Object.keys(database.metadata()), [
      "country",
      "city",
      "asn",
      "connection_type",
    ]);
  } finally {
    database.close();
  }
  assert.throws(() => database.lookup("172.20.0.1"), fails("DN42_CLOSED"));
  assert.throws(() => database.releaseMetadata(), fails("DN42_CLOSED"));
});

await test("normalizes addresses and reports the matched network", async () => {
  const database = await openBundle(fixtures);
  for (const input of ["172.20.0.1", "::ffff:172.20.0.1", "::FFFF:AC14:1"]) {
    const result = database.lookup(input);
    assert.equal(result.ip, "172.20.0.1");
    assert.equal(result.records.city?.network, "172.20.0.1/32");
    assert.equal(result.records.city?.prefix_length, 32);
  }
  const ipv6 = database.lookup("FD42:1234:0:0::1");
  assert.equal(ipv6.ip, "fd42:1234::1");
  assert.equal(ipv6.records.asn?.network, "fd42:1234::1/128");
  for (const input of ["not-an-ip", "fe80::1%lo0", "127.1"])
    assert.throws(() => database.lookup(input), fails("DN42_INVALID_ADDRESS"));
  for (const asn of [-1, 1.5, 4_294_967_296])
    assert.throws(() => database.lookupAsn(asn), fails("DN42_INVALID_ASN"));
  database.close();
});

await test("lists every ASN in ascending order", async () => {
  const database = await openBundle(fixtures);
  const asns = database.asns().map((info) => info.asn);
  assert.ok(asns.includes(4242420001));
  assert.deepEqual(
    asns,
    [...asns].sort((left, right) => left - right),
  );
  database.close();
});

await test("types the published release fields", async () => {
  const directory = await editedRelease("metadata.json", (document) => {
    document.release_tag = "2026-11-15.31";
    document.route_observed_at = {
      first: "2026-11-15T07:43:11Z",
      last: "2026-11-15T10:59:05Z",
    };
    document.release_url = "https://example.invalid/2026-11-15.31";
  });
  try {
    const database = await openBundle(directory);
    const release = database.releaseMetadata();
    assert.equal(release.release_tag, "2026-11-15.31");
    assert.equal(release.route_observed_at?.last, "2026-11-15T10:59:05Z");
    assert.equal(release.release_url, "https://example.invalid/2026-11-15.31");
    database.close();
  } finally {
    await rm(directory, { recursive: true });
  }
});

await test("rejects releases whose sidecars contradict the databases", async () => {
  const edits: [
    "metadata.json" | "asn-index.json",
    (document: Record<string, unknown>) => void,
  ][] = [
    ["metadata.json", (document) => (document.schema_version = "1")],
    [
      "metadata.json",
      (document) =>
        (document.database_types = { "DN42-IPDB-City.mmdb": "DN42-GeoIP2-Country" }),
    ],
    [
      "asn-index.json",
      (document) => {
        const asns = document.asns as Record<string, unknown>;
        asns["4242420002"] = asns["4242420001"];
      },
    ],
  ];
  for (const [file, edit] of edits) {
    const directory = await editedRelease(file, edit);
    try {
      await assert.rejects(openBundle(directory), fails("DN42_INVALID_BUNDLE"));
    } finally {
      await rm(directory, { recursive: true });
    }
  }
  const directory = await mkdtemp(join(scratch, "notice-"));
  try {
    await cp(fixtures, directory, { recursive: true });
    await rm(join(directory, "LICENSE-Unicode.txt"));
    await assert.rejects(openBundle(directory), fails("DN42_INVALID_BUNDLE"));
    await mkdir(join(directory, "LICENSE-Unicode.txt"));
    await assert.rejects(openBundle(directory), fails("DN42_INVALID_BUNDLE"));
  } finally {
    await rm(directory, { recursive: true });
  }
});

await test("rejects a redirect before requesting an insecure target", async () => {
  const source = await fixtureServer();
  const target = await fixtureServer();
  const cacheDir = await mkdtemp(join(scratch, "redirect-"));
  source.redirect(`${target.baseURL}checksums.json`);
  try {
    await assert.rejects(
      downloadRelease({ cacheDir, baseURL: source.baseURL }),
      fails("DN42_INVALID_URL"),
    );
    assert.equal(source.requests.length, 1);
    assert.equal(target.requests.length, 0);
  } finally {
    await source.close();
    await target.close();
    await rm(cacheDir, { recursive: true });
  }
});

await test("follows same-origin redirects and rejects unusable ones", async () => {
  await withServer("hops", async (server, cacheDir) => {
    server.route("checksums.json", (response) =>
      response.writeHead(302, { location: "/moved/checksums.json?signed=1" }).end(),
    );
    const manifest = JSON.stringify(
      Object.fromEntries(
        [...server.bytes].map(([name, data]) => [
          name,
          createHash("sha256").update(data).digest("hex"),
        ]),
      ),
    );
    server.route("moved/checksums.json", (response) => response.end(manifest));
    const result = await downloadRelease({ cacheDir, baseURL: server.baseURL });
    assert.equal(result.changed, true);
    result.bundle.close();
    for (const location of [
      "/checksums.json",
      "http://user@127.0.0.1/checksums.json",
      "//@127.0.0.1/checksums.json",
      "http://[::1",
    ]) {
      server.route("checksums.json", (response) =>
        response.writeHead(302, { location }).end(),
      );
      await assert.rejects(
        downloadRelease({ cacheDir, baseURL: server.baseURL }),
        fails("DN42_INVALID_URL"),
      );
    }
  });
});

await test("enforces the manifest size limit while downloading", async () => {
  await withServer("limits", async (server, cacheDir) => {
    const oversized = "x".repeat(64 * 1024 + 1);
    server.route("checksums.json", (response) => response.end(oversized));
    await assert.rejects(
      downloadRelease({ cacheDir, baseURL: server.baseURL }),
      fails("DN42_SIZE_LIMIT"),
    );
    server.route("checksums.json", (response) => {
      response.writeHead(200, { "transfer-encoding": "chunked" });
      response.write(oversized.slice(0, 40_000));
      response.end(oversized.slice(40_000));
    });
    await assert.rejects(
      downloadRelease({ cacheDir, baseURL: server.baseURL }),
      fails("DN42_SIZE_LIMIT"),
    );
  });
});

await test("accepts HTTPS and loopback HTTP base URLs only", async () => {
  const cacheDir = await mkdtemp(join(scratch, "url-"));
  try {
    for (const baseURL of [
      "https://user:secret@example.com/",
      "https://example.com/releases/?tag=1",
      "https://example.com/releases/#latest",
      "http://example.com/",
      "http://localhost/",
      "http://[::ffff:127.0.0.1]/",
      "https://@example.com/",
      "https:@example.com/",
      " https://@example.com/",
      String.raw`https:\\@example.com/`,
      "https://example.com/?",
      "https://example.com/#",
      "ftp://127.0.0.1/",
    ])
      await assert.rejects(
        downloadRelease({ cacheDir, baseURL }),
        fails("DN42_INVALID_URL"),
      );
    await assert.rejects(
      downloadRelease({ cacheDir, baseURL: "http://127.0.0.2:9/", timeoutMs: 2_000 }),
      (error: Error) => !isDn42IpdbError(error, "DN42_INVALID_URL"),
    );
    for (const timeoutMs of [0, 1.5, 2_147_483_648])
      await assert.rejects(downloadRelease({ cacheDir, timeoutMs }), RangeError);
  } finally {
    await rm(cacheDir, { recursive: true });
  }
});

await test("initializes v2 beside an existing language cache", async () => {
  await withServer("layout", async (server, cacheDir) => {
    const existing = join(cacheDir, "typescript", "current.json");
    await mkdir(join(cacheDir, "typescript"));
    await writeFile(existing, "existing cache layout");
    const result = await downloadRelease({ cacheDir, baseURL: server.baseURL });
    assert.equal(result.changed, true);
    assert.equal(result.directory, join(cacheDir, "typescript", "v2", fixtureVersion));
    assert.equal(await readFile(existing, "utf8"), "existing cache layout");
    assert.equal(result.bundle.lookupAsn(4242420001)?.asn, 4242420001);
    result.bundle.close();
    const database = await openCachedBundle(cacheDir);
    assert.equal(database.lookupAsn(4242420001)?.asn, 4242420001);
    database.close();
  });
});

await test("downloads a complete verified bundle and reuses it without database requests", async () => {
  await withServer("cache", async (server, cacheDir) => {
    const first = await downloadRelease({ cacheDir, baseURL: server.baseURL });
    assert.equal(first.changed, true);
    assert.equal(first.recoveredCache, false);
    assert.equal(server.requests.length, 8);
    const second = await downloadRelease({ cacheDir, baseURL: server.baseURL });
    assert.equal(second.directory, first.directory);
    assert.equal(second.changed, false);
    assert.equal(second.recoveredCache, false);
    assert.equal(second.bundle.lookup("172.20.0.1").records.asn?.prefix_length, 32);
    assert.equal(server.requests.length, 9);
    const cached = await openCachedBundle(cacheDir);
    assert.equal(cached.lookupAsn(4242420001)?.asn, 4242420001);
    cached.close();
    assert.equal(server.requests.length, 9);
  });
});

await test("opens the cache from several readers at once", async () => {
  await withServer("readers", async (server, cacheDir) => {
    await downloadRelease({ cacheDir, baseURL: server.baseURL });
    const bundles = await Promise.all(
      Array.from({ length: 4 }, () => openCachedBundle(cacheDir)),
    );
    for (const bundle of bundles) {
      assert.equal(bundle.lookupAsn(4242420001)?.asn, 4242420001);
      bundle.close();
    }
  });
});

await test("reports an empty cache", async () => {
  const cacheDir = await mkdtemp(join(scratch, "empty-"));
  try {
    await assert.rejects(openCachedBundle(cacheDir), fails("DN42_CACHE_MISSING"));
  } finally {
    await rm(cacheDir, { recursive: true });
  }
});

await test("preserves the active bundle after partial downloads, wrong types and bad manifests", async () => {
  await withServer("failure", async (server, cacheDir) => {
    await downloadRelease({ cacheDir, baseURL: server.baseURL });
    const pointer = join(cacheDir, "typescript/v2/current.json");
    const original = await readFile(pointer, "utf8");
    server.bytes.set("metadata.json", metadataRevision(1));
    server.fail("DN42-IPDB-ASN.mmdb");
    await assert.rejects(
      downloadRelease({ cacheDir, baseURL: server.baseURL }),
      fails("DN42_HTTP_STATUS"),
    );
    assert.equal(await readFile(pointer, "utf8"), original);
    server.fail();
    server.bytes.set(
      "DN42-IPDB-City.mmdb",
      await readFile(join(fixtures, "DN42-IPDB-ASN.mmdb")),
    );
    await assert.rejects(
      downloadRelease({ cacheDir, baseURL: server.baseURL }),
      fails("DN42_INVALID_BUNDLE"),
    );
    assert.equal(await readFile(pointer, "utf8"), original);
    server.badChecksum();
    await assert.rejects(
      downloadRelease({ cacheDir, baseURL: server.baseURL }),
      fails("DN42_CHECKSUM_MISMATCH"),
    );
    assert.equal(await readFile(pointer, "utf8"), original);
    server.badManifest();
    await assert.rejects(
      downloadRelease({ cacheDir, baseURL: server.baseURL }),
      fails("DN42_INVALID_BUNDLE"),
    );
    assert.equal(await readFile(pointer, "utf8"), original);
    const cached = await openCachedBundle(cacheDir);
    assert.equal(cached.lookupAsn(4242420001)?.asn, 4242420001);
    cached.close();
  });
});

await test("cancels a streamed download before publishing the cache pointer", async () => {
  await withServer("abort", async (server, cacheDir) => {
    server.stall();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 80);
    try {
      await assert.rejects(
        downloadRelease({
          cacheDir,
          baseURL: server.baseURL,
          signal: controller.signal,
        }),
      );
      assert.equal((await cacheEntries(cacheDir)).includes("current.json"), false);
    } finally {
      clearTimeout(timer);
    }
  });
});

await test("retains two owned versions and preserves custom cache content", async () => {
  await withServer("retention", async (server, cacheDir) => {
    const first = await downloadRelease({ cacheDir, baseURL: server.baseURL });
    const reader = await openCachedBundle(cacheDir);
    const custom = join(cacheDir, "typescript", "v2", "f".repeat(64));
    await mkdir(custom);
    await writeFile(join(custom, "user-data.txt"), "keep");
    for (const revision of [1, 2, 3]) {
      server.bytes.set("metadata.json", metadataRevision(revision));
      (await downloadRelease({ cacheDir, baseURL: server.baseURL })).bundle.close();
    }
    const entries = await cacheEntries(cacheDir);
    assert.equal(entries.filter((entry) => /^[0-9a-f]{64}$/.test(entry)).length, 3);
    assert.equal(await readFile(join(custom, "user-data.txt"), "utf8"), "keep");
    await assert.rejects(readFile(join(first.directory, "DN42-IPDB-City.mmdb")), {
      code: "ENOENT",
    });
    assert.equal(reader.lookupAsn(4242420001)?.asn, 4242420001);
    reader.close();
    first.bundle.close();
  });
});

await test("removes stage and pointer leftovers of interrupted updates", async () => {
  await withServer("leftovers", async (server, cacheDir) => {
    const cache = join(cacheDir, "typescript", "v2");
    await mkdir(join(cache, ".stage-interrupted"), { recursive: true });
    await writeFile(
      join(cache, ".stage-interrupted", "DN42-IPDB-City.mmdb"),
      "partial",
    );
    await writeFile(join(cache, ".current-interrupted"), "{}");
    (await downloadRelease({ cacheDir, baseURL: server.baseURL })).bundle.close();
    assert.deepEqual((await cacheEntries(cacheDir)).sort(), [
      fixtureVersion,
      "current.json",
    ]);
  });
});

await test("updates wait for the cross-process update lock while readers continue", async () => {
  await withServer("lock", async (server, cacheDir) => {
    (await downloadRelease({ cacheDir, baseURL: server.baseURL })).bundle.close();
    server.bytes.set("metadata.json", metadataRevision(1));
    const child = fork(fileURLToPath(new URL("./hold-lock.mjs", import.meta.url)), [
      join(cacheDir, "typescript", "v2"),
    ]);
    const exited = once(child, "exit");
    let released = false;
    try {
      await once(child, "message");
      const reader = await openCachedBundle(cacheDir);
      reader.close();
      await assert.rejects(
        downloadRelease({ cacheDir, baseURL: server.baseURL, timeoutMs: 150 }),
        fails("DN42_LOCK_TIMEOUT"),
      );
      const waiting = downloadRelease({ cacheDir, baseURL: server.baseURL });
      setTimeout(() => child.send("release"), 200);
      released = true;
      const result = await waiting;
      assert.equal(result.changed, true);
      assert.equal(result.bundle.releaseMetadata().revision, 1);
      result.bundle.close();
    } finally {
      if (!released) child.send("release");
      await exited;
    }
  });
});

await test("recovers a malformed cache pointer after a complete verified download", async () => {
  await withServer("recovery", async (server, cacheDir) => {
    (await downloadRelease({ cacheDir, baseURL: server.baseURL })).bundle.close();
    await writeFile(join(cacheDir, "typescript/v2/current.json"), "{");
    const result = await downloadRelease({ cacheDir, baseURL: server.baseURL });
    assert.equal(result.changed, true);
    assert.equal(result.recoveredCache, true);
    result.bundle.close();
    const database = await openCachedBundle(cacheDir);
    assert.equal(database.lookupAsn(4242420001)?.asn, 4242420001);
    database.close();
  });
});

await test("heals a cached release whose files were damaged", async () => {
  await withServer("heal", async (server, cacheDir) => {
    const first = await downloadRelease({ cacheDir, baseURL: server.baseURL });
    first.bundle.close();
    const damaged = join(first.directory, "DN42-IPDB-City.mmdb");
    await writeFile(damaged, "damaged");
    await assert.rejects(openCachedBundle(cacheDir), fails("DN42_CHECKSUM_MISMATCH"));
    const result = await downloadRelease({ cacheDir, baseURL: server.baseURL });
    assert.equal(result.changed, true);
    assert.equal(result.recoveredCache, true);
    assert.equal(result.directory, first.directory);
    result.bundle.close();
    assert.deepEqual(await readFile(damaged), server.bytes.get("DN42-IPDB-City.mmdb"));
    (await openCachedBundle(cacheDir)).close();
  });
});
