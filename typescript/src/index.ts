import { createHash, randomBytes } from "node:crypto";
import { renameSync } from "node:fs";
import { mkdir, mkdtemp, open, readdir, rm, writeFile } from "node:fs/promises";
import { isIP } from "node:net";
import { join } from "node:path";
import {
  Reader,
  type AsnResponse,
  type CityResponse,
  type CountryResponse,
  type ConnectionTypeResponse,
} from "maxmind";
import { lock } from "proper-lockfile";
import { z } from "zod";

export const defaultReleaseURL =
  "https://github.com/bird-chinese-community/DN42-IPDB-Releases/releases/latest/download/";
const maxDatabaseBytes = 32 * 1024 * 1024;
const maxManifestBytes = 64 * 1024;
const artifactTypes = {
  country: ["DN42-IPDB-Country.mmdb", "DN42-GeoIP2-Country"],
  city: ["DN42-IPDB-City.mmdb", "DN42-GeoIP2-City"],
  asn: ["DN42-IPDB-ASN.mmdb", "DN42-GeoLite2-ASN"],
  connection_type: ["DN42-IPDB-Connection-Type.mmdb", "DN42-GeoIP2-Connection-Type"],
} as const;
const artifactFiles = [
  ...Object.values(artifactTypes).map(([file]) => file),
  "asn-index.json",
  "metadata.json",
  "LICENSE-Unicode.txt",
];
type ArtifactKey = keyof typeof artifactTypes;
const digestSchema = z.string().regex(/^[0-9a-f]{64}$/);
const checksumSchema = z
  .object({
    "DN42-IPDB-Country.mmdb": digestSchema,
    "DN42-IPDB-City.mmdb": digestSchema,
    "DN42-IPDB-ASN.mmdb": digestSchema,
    "DN42-IPDB-Connection-Type.mmdb": digestSchema,
    "asn-index.json": digestSchema,
    "metadata.json": digestSchema,
    "LICENSE-Unicode.txt": digestSchema,
  })
  .catchall(z.string());
const pointerSchema = z.object({ version: digestSchema, checksums: checksumSchema });
type Checksums = z.infer<typeof checksumSchema>;

export interface Observation {
  asn?: number;
  target: string;
  kind: string;
  value?: string;
  status: string;
  method: string;
  source: string;
  authority: string;
  observed_at: string;
}
/** An AS that announces the prefix or is listed in its Registry route object. */
export interface Origin {
  asn: number;
  as_name?: string;
}
export interface Evidence {
  kind: string;
  source: string;
  observed_at: string;
  authority: string;
  confidence: string;
}
export interface PtrCandidate {
  city_id: string;
  country: string;
  city: string;
  region?: string;
  matched_token: string;
  method: string;
  rank: number;
  guarded?: boolean;
}
export interface PtrNameHint {
  hostname: string;
  normalized?: string;
  stripped_domain?: string;
  source: string;
  observed_at: string;
  observation_method: string;
  authority: string;
  status: string;
  reason?: string;
  candidates?: PtrCandidate[];
}
export interface PtrHints {
  status: string;
  reason?: string;
  algorithm: string;
  catalog: {
    version: string;
    source: string;
    license: string;
    revision: string;
    source_sha256: string;
    sha256: string;
    generated_at: string;
    valid_until: string;
  };
  names: PtrNameHint[];
}
export interface Dn42Metadata {
  /** Present when the prefix has exactly one origin. */
  asn?: number;
  as_name?: string;
  /** Every origin; releases before origins were published omit it. */
  origins?: Origin[];
  connection_type?: string;
  confidence?: string;
  schema_version: string;
  prefix: string;
  anycast: string;
  network_types: string[];
  ptr: string[];
  ptr_hints?: PtrHints;
  roa_status: string;
  irr_status: string;
  roa_prefix?: string;
  irr_prefix?: string;
  observations: Observation[];
  evidence: Evidence[];
}
export type DatabaseRecord = Partial<
  CountryResponse & CityResponse & AsnResponse & ConnectionTypeResponse
> & { dn42?: Dn42Metadata };
export interface Match {
  prefix_length: number;
  data: DatabaseRecord;
}
export interface LookupResult {
  ip: string;
  records: Partial<Record<ArtifactKey, Match>>;
}
export interface Bundle {
  lookup(ip: string): LookupResult;
  lookupAsn(asn: number): AsnInfo | undefined;
  releaseMetadata(): ReleaseMetadata;
  metadata(): Partial<Record<ArtifactKey, Reader<DatabaseRecord>["metadata"]>>;
  close(): void;
}

const observationSchema = z.object({
  asn: z.number().int().nonnegative().optional(),
  target: z.string(),
  kind: z.string(),
  value: z.string().optional(),
  status: z.string(),
  method: z.string(),
  source: z.string(),
  authority: z.string(),
  observed_at: z.string(),
});
const asnInfoSchema = z.object({
  asn: z.number().int().nonnegative(),
  as_name: z.string().optional(),
  registered_countries: z.array(
    z.object({ iso_code: z.string(), names: z.record(z.string(), z.string()) }),
  ),
  prefixes: z.array(z.string()),
  observed_network_types: z.array(z.string()),
  observations: z.array(observationSchema),
});
const asnIndexSchema = z.object({
  schema_version: z.literal("2"),
  asns: z.record(z.string().regex(/^[0-9]+$/), asnInfoSchema),
});
const releaseMetadataSchema = z
  .object({
    schema_version: z.string(),
    release_repository: z.string(),
    copyright: z.string(),
  })
  .catchall(z.json());
export type AsnInfo = z.infer<typeof asnInfoSchema>;
export type ReleaseMetadata = z.infer<typeof releaseMetadataSchema>;

async function readBounded(path: string, limit: number): Promise<Buffer> {
  const file = await open(path, "r");
  try {
    const info = await file.stat();
    if (!info.isFile() || info.size > limit)
      throw new Error(`Invalid cache file size: ${path}`);
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of file.createReadStream({ autoClose: false })) {
      const bytes = chunk as Buffer;
      size += bytes.length;
      if (size > limit) throw new Error(`Cache file exceeds size limit: ${path}`);
      chunks.push(bytes);
    }
    return Buffer.concat(chunks, size);
  } finally {
    await file.close();
  }
}

export async function openBundle(directory: string): Promise<Bundle> {
  const asnIndex = asnIndexSchema.parse(
    JSON.parse(
      (await readBounded(join(directory, "asn-index.json"), maxDatabaseBytes)).toString(
        "utf8",
      ),
    ),
  );
  const releaseMetadata = releaseMetadataSchema.parse(
    JSON.parse(
      (await readBounded(join(directory, "metadata.json"), maxDatabaseBytes)).toString(
        "utf8",
      ),
    ),
  );
  const readers = new Map<ArtifactKey, Reader<DatabaseRecord>>();
  for (const [key, [file, kind]] of Object.entries(artifactTypes)) {
    const reader = new Reader<DatabaseRecord>(
      await readBounded(join(directory, file), maxDatabaseBytes),
    );
    if (reader.metadata.databaseType !== kind)
      throw new Error(`${file}: expected ${kind} database`);
    readers.set(key as ArtifactKey, reader);
  }
  let closed = false;
  return {
    lookup(ip) {
      if (closed) throw new Error("DN42 bundle is closed");
      if (!isIP(ip) || ip.includes("%")) throw new Error(`Invalid IP address: ${ip}`);
      const records: LookupResult["records"] = {};
      for (const [key, reader] of readers) {
        const [data, prefixLength] = reader.getWithPrefixLength(ip);
        if (data && Object.keys(data).length > 0)
          records[key] = { prefix_length: prefixLength, data };
      }
      return { ip, records };
    },
    lookupAsn(asn) {
      if (closed) throw new Error("DN42 bundle is closed");
      if (!Number.isInteger(asn) || asn < 0 || asn > 4_294_967_295)
        throw new Error(`Invalid ASN: ${asn}`);
      return asnIndex.asns[String(asn)];
    },
    releaseMetadata() {
      return releaseMetadata;
    },
    metadata() {
      return Object.fromEntries(
        [...readers].map(([key, reader]) => [key, reader.metadata]),
      );
    },
    close() {
      closed = true;
      readers.clear();
    },
  };
}

export interface DownloadOptions {
  cacheDir: string;
  baseURL?: string;
  timeoutMs?: number;
  signal?: AbortSignal;
}
export interface DownloadResult {
  directory: string;
  changed: boolean;
  recoveredCache?: boolean;
}
const digest = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");

async function verifyFiles(directory: string, checksums: Checksums): Promise<void> {
  for (const file of artifactFiles) {
    if (
      digest(await readBounded(join(directory, file), maxDatabaseBytes)) !==
      checksums[file]
    )
      throw new Error(`Checksum mismatch: ${file}`);
  }
  (await openBundle(directory)).close();
}

export async function openCachedBundle(cacheDir: string): Promise<Bundle> {
  const cache = join(cacheDir, "typescript", "v2");
  let compromised: Error | undefined;
  const release = await lock(cache, {
    retries: 0,
    lockfilePath: join(cache, ".update.lock"),
    onCompromised: (error) => {
      compromised = error;
    },
  });
  try {
    const pointer = pointerSchema.parse(
      JSON.parse(
        (await readBounded(join(cache, "current.json"), maxManifestBytes)).toString(
          "utf8",
        ),
      ),
    );
    const directory = join(cache, pointer.version);
    await verifyFiles(directory, pointer.checksums);
    const bundle = await openBundle(directory);
    if (compromised) {
      bundle.close();
      throw compromised;
    }
    return bundle;
  } finally {
    await release();
  }
}

async function download(
  address: URL,
  limit: number,
  signal: AbortSignal,
): Promise<Buffer> {
  let current = address;
  let response: Response | undefined;
  for (let redirects = 0; redirects <= 10; redirects++) {
    if (
      current.username ||
      current.password ||
      (current.protocol !== "https:" &&
        !(address.protocol === "http:" && current.origin === address.origin))
    ) {
      throw new Error("Insecure release redirect");
    }
    response = await fetch(current, {
      signal,
      redirect: "manual",
      headers: { "user-agent": "DN42-IPDB-SDK-TypeScript" },
    });
    if (![301, 302, 303, 307, 308].includes(response.status)) break;
    await response.body?.cancel();
    const location = response.headers.get("location");
    if (!location || redirects === 10) throw new Error("Invalid release redirect");
    current = new URL(location, current);
  }
  if (!response) throw new Error("Missing release response");
  if (!response.ok || !response.body) {
    await response.body?.cancel();
    throw new Error(`Download ${address}: HTTP ${response.status}`);
  }
  const length = response.headers.get("content-length");
  if (length && Number(length) > limit) {
    await response.body.cancel();
    throw new Error(`Download ${address}: size limit exceeded`);
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const item = await reader.read();
      if (item.done) break;
      size += item.value.length;
      if (size > limit) throw new Error(`Download ${address}: size limit exceeded`);
      chunks.push(item.value);
    }
  } finally {
    await reader.cancel();
  }
  return Buffer.concat(chunks, size);
}

export async function downloadRelease(
  options: DownloadOptions,
): Promise<DownloadResult> {
  if (!options.cacheDir) throw new Error("cacheDir is required");
  const base = new URL(options.baseURL ?? defaultReleaseURL);
  const loopback =
    base.protocol === "http:" &&
    (base.hostname === "127.0.0.1" || base.hostname === "[::1]");
  if (base.username || base.password || (base.protocol !== "https:" && !loopback))
    throw new Error("Release URL requires HTTPS or loopback HTTP");
  if (!base.pathname.endsWith("/")) base.pathname += "/";
  const controller = new AbortController();
  const signals = [controller.signal, AbortSignal.timeout(options.timeoutMs ?? 30_000)];
  if (options.signal) signals.push(options.signal);
  const signal = AbortSignal.any(signals);
  signal.throwIfAborted();
  const cache = join(options.cacheDir, "typescript", "v2");
  await mkdir(cache, { recursive: true, mode: 0o700 });
  const release = await lock(cache, {
    retries: 0,
    lockfilePath: join(cache, ".update.lock"),
    onCompromised: (error) => controller.abort(error),
  });
  try {
    const checksums = checksumSchema.parse(
      JSON.parse(
        (
          await download(new URL("checksums.json", base), maxManifestBytes, signal)
        ).toString("utf8"),
      ),
    );
    let previous: string | undefined;
    let previousChecksums: Checksums | undefined;
    let recoveredCache = false;
    try {
      const bytes = await readBounded(join(cache, "current.json"), maxManifestBytes);
      try {
        const pointer = pointerSchema.safeParse(JSON.parse(bytes.toString("utf8")));
        if (pointer.success) {
          previous = pointer.data.version;
          previousChecksums = pointer.data.checksums;
        } else recoveredCache = true;
      } catch (error) {
        if (!(error instanceof SyntaxError)) throw error;
        recoveredCache = true;
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    if (
      previous &&
      previousChecksums &&
      artifactFiles.every((file) => checksums[file] === previousChecksums[file])
    ) {
      const directory = join(cache, previous);
      await verifyFiles(directory, checksums);
      return { directory, changed: false };
    }
    const stage = await mkdtemp(join(cache, ".stage-"));
    try {
      for (const file of artifactFiles) {
        const bytes = await download(new URL(file, base), maxDatabaseBytes, signal);
        if (digest(bytes) !== checksums[file])
          throw new Error(`Checksum mismatch: ${file}`);
        await writeFile(join(stage, file), bytes, { mode: 0o600 });
      }
      await verifyFiles(stage, checksums);
      signal.throwIfAborted();
      const current = randomBytes(32).toString("hex");
      const directory = join(cache, current);
      const pending = join(cache, `.current-${current}`);
      let committed = false;
      try {
        await writeFile(pending, JSON.stringify({ version: current, checksums }), {
          mode: 0o600,
        });
        for (const entry of await readdir(cache, { withFileTypes: true })) {
          if (
            !entry.isDirectory() ||
            !digestSchema.safeParse(entry.name).success ||
            entry.name === current ||
            entry.name === previous
          )
            continue;
          const old = join(cache, entry.name);
          const files = await readdir(old, { withFileTypes: true });
          if (
            files.length === artifactFiles.length &&
            files.every((file) => file.isFile() && artifactFiles.includes(file.name))
          )
            await rm(old, { recursive: true });
        }
        signal.throwIfAborted();
        renameSync(stage, directory);
        renameSync(pending, join(cache, "current.json"));
        committed = true;
        return recoveredCache
          ? { directory, changed: true, recoveredCache: true }
          : { directory, changed: true };
      } finally {
        if (!committed) await rm(directory, { recursive: true, force: true });
        await rm(pending, { force: true });
      }
    } finally {
      await rm(stage, { recursive: true, force: true });
    }
  } finally {
    await release();
  }
}
