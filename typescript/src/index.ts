import { createHash, randomBytes } from "node:crypto";
import { mkdir, mkdtemp, open, readdir, rename, rm, stat } from "node:fs/promises";
import { isIP } from "node:net";
import { basename, join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import ipaddr from "ipaddr.js";
import {
  Reader,
  type AsnResponse,
  type CityResponse,
  type CountryResponse,
  type ConnectionTypeResponse,
} from "maxmind";
import { lock } from "proper-lockfile";
import { z } from "zod";
import { followPointer } from "./follow-pointer.ts";

export const defaultReleaseURL =
  "https://github.com/bird-chinese-community/DN42-IPDB-Releases/releases/latest/download/";
const defaultTimeoutMs = 30_000;
/** Node timers fire at once for delays above 2^31 - 1 milliseconds. */
const maxTimerMs = 2_147_483_647;
const lockPollMs = 50;
const databaseLimit = 32 * 1024 * 1024;
const noticeLimit = 1024 * 1024;
const manifestLimit = 64 * 1024;

const databases = [
  { key: "country", file: "DN42-IPDB-Country.mmdb", type: "DN42-GeoIP2-Country" },
  { key: "city", file: "DN42-IPDB-City.mmdb", type: "DN42-GeoIP2-City" },
  { key: "asn", file: "DN42-IPDB-ASN.mmdb", type: "DN42-GeoLite2-ASN" },
  {
    key: "connection_type",
    file: "DN42-IPDB-Connection-Type.mmdb",
    type: "DN42-GeoIP2-Connection-Type",
  },
] as const;
const sidecars = ["asn-index.json", "metadata.json", "LICENSE-Unicode.txt"] as const;
type DatabaseKey = (typeof databases)[number]["key"];
type ReleaseFile = (typeof databases)[number]["file"] | (typeof sidecars)[number];
const releaseFiles: readonly ReleaseFile[] = [
  ...databases.map((database) => database.file),
  ...sidecars,
];
const sizeLimit = (file: ReleaseFile): number =>
  file === "metadata.json" || file === "LICENSE-Unicode.txt"
    ? noticeLimit
    : databaseLimit;

const errorCodes = [
  "DN42_INVALID_ADDRESS",
  "DN42_INVALID_ASN",
  "DN42_INVALID_URL",
  "DN42_INVALID_BUNDLE",
  "DN42_CHECKSUM_MISMATCH",
  "DN42_SIZE_LIMIT",
  "DN42_HTTP_STATUS",
  "DN42_LOCK_TIMEOUT",
  "DN42_CACHE_MISSING",
  "DN42_CLOSED",
] as const;
export type Dn42IpdbErrorCode = (typeof errorCodes)[number];
/** An Error whose `code` names the failure category. */
export type Dn42IpdbError = Error & { code: Dn42IpdbErrorCode };

function failure(
  code: Dn42IpdbErrorCode,
  message: string,
  cause?: unknown,
): Dn42IpdbError {
  return Object.assign(
    new Error(message, cause === undefined ? undefined : { cause }),
    {
      code,
    },
  );
}

export function isDn42IpdbError(
  error: unknown,
  code?: Dn42IpdbErrorCode,
): error is Dn42IpdbError {
  return (
    error instanceof Error &&
    "code" in error &&
    errorCodes.some((known) => known === error.code) &&
    (code === undefined || error.code === code)
  );
}

const hasErrno = (error: unknown, code: string): boolean =>
  error instanceof Error && "code" in error && error.code === code;

const digestSchema = z.string().regex(/^[0-9a-f]{64}$/);
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
const asnInfoSchema = z.looseObject({
  asn: z.number().int().min(0).max(4_294_967_295),
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
    schema_version: z.literal("2"),
    release_repository: z.string().min(1),
    copyright: z.string().min(1),
    release_tag: z.string().optional(),
    release_url: z.string().optional(),
    built_at: z.string().optional(),
    registry_commit: z.string().optional(),
    registry_committed_at: z.string().optional(),
    route_observed_at: z.object({ first: z.string(), last: z.string() }).optional(),
    database_types: z.record(z.string(), z.string()).optional(),
  })
  .catchall(z.json());
const pointerSchema = z.object({
  version: digestSchema,
  checksums: z.record(z.string(), z.json()),
});

export type Observation = z.infer<typeof observationSchema>;
export type AsnInfo = z.infer<typeof asnInfoSchema>;
export type ReleaseMetadata = z.infer<typeof releaseMetadataSchema>;

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
  /** source: attribute of the prefix's Registry object: DN42, ICVPN, CHAOSVPN, NEONETWORK or CRXN. */
  registry_source?: string;
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
export type DatabaseMetadata = Reader<DatabaseRecord>["metadata"];
export interface Match {
  /** Canonical CIDR of the matched network, in the address family of `ip`. */
  network: string;
  prefix_length: number;
  data: DatabaseRecord;
}
export interface LookupResult {
  /** Canonical address; IPv4-mapped IPv6 input is returned as IPv4. */
  ip: string;
  records: Partial<Record<DatabaseKey, Match>>;
}
export interface Bundle {
  lookup(ip: string): LookupResult;
  lookupAsn(asn: number): AsnInfo | undefined;
  /** Every ASN in the release, ordered by number. */
  asns(): readonly AsnInfo[];
  releaseMetadata(): ReleaseMetadata;
  metadata(): Record<DatabaseKey, DatabaseMetadata>;
  close(): void;
}

type ReleaseBytes = ReadonlyMap<ReleaseFile, Buffer>;
type Checksums = ReadonlyMap<ReleaseFile, string>;
interface Pointer {
  version: string;
  checksums: Checksums;
}

async function readBounded(path: string, limit: number): Promise<Buffer> {
  const info = await stat(path);
  if (!info.isFile())
    throw failure("DN42_INVALID_BUNDLE", `${path} is not a regular file`);
  const file = await open(path, "r");
  try {
    if (info.size > limit)
      throw failure("DN42_SIZE_LIMIT", `${path} exceeds ${limit} bytes`);
    const buffer = Buffer.allocUnsafe(info.size + 1);
    let size = 0;
    for (;;) {
      const { bytesRead } = await file.read(buffer, size, buffer.length - size, null);
      if (bytesRead === 0) return buffer.subarray(0, size);
      size += bytesRead;
      if (size > info.size)
        throw failure("DN42_INVALID_BUNDLE", `${path} changed while it was read`);
    }
  } finally {
    await file.close();
  }
}

function parseJson<T>(schema: z.ZodType<T>, bytes: Buffer, origin: string): T {
  let value: z.core.util.JSONType;
  try {
    value = z.json().parse(JSON.parse(bytes.toString("utf8")));
  } catch (error) {
    throw failure("DN42_INVALID_BUNDLE", `${origin}: invalid JSON`, error);
  }
  const result = schema.safeParse(value);
  if (!result.success)
    throw failure(
      "DN42_INVALID_BUNDLE",
      `${origin}: ${z.prettifyError(result.error)}`,
      result.error,
    );
  return result.data;
}

const sha256 = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");

async function readReleaseFile(directory: string, file: ReleaseFile): Promise<Buffer> {
  try {
    return await readBounded(join(directory, file), sizeLimit(file));
  } catch (error) {
    if (hasErrno(error, "ENOENT"))
      throw failure("DN42_INVALID_BUNDLE", `${directory} has no ${file}`, error);
    throw error;
  }
}

async function readRelease(directory: string): Promise<ReleaseBytes> {
  const files = new Map<ReleaseFile, Buffer>();
  for (const file of releaseFiles)
    files.set(file, await readReleaseFile(directory, file));
  return files;
}

function releaseFile(files: ReleaseBytes, file: ReleaseFile): Buffer {
  const bytes = files.get(file);
  if (!bytes) throw failure("DN42_INVALID_BUNDLE", `Missing release file: ${file}`);
  return bytes;
}

function verifyChecksums(
  files: ReleaseBytes,
  checksums: Checksums,
  origin: string,
): void {
  for (const file of releaseFiles)
    if (sha256(releaseFile(files, file)) !== checksums.get(file))
      throw failure("DN42_CHECKSUM_MISMATCH", `Checksum mismatch: ${origin}/${file}`);
}

function openReader(
  files: ReleaseBytes,
  release: ReleaseMetadata,
  key: DatabaseKey,
): Reader<DatabaseRecord> {
  const database = databases.find((entry) => entry.key === key);
  if (!database) throw failure("DN42_INVALID_BUNDLE", `Unknown database: ${key}`);
  let reader: Reader<DatabaseRecord>;
  try {
    reader = new Reader<DatabaseRecord>(releaseFile(files, database.file));
  } catch (error) {
    throw failure("DN42_INVALID_BUNDLE", `${database.file}: invalid MaxMind DB`, error);
  }
  const actual = reader.metadata.databaseType;
  if (actual !== database.type)
    throw failure(
      "DN42_INVALID_BUNDLE",
      `${database.file}: expected ${database.type} database, found ${actual}`,
    );
  const declared = release.database_types?.[database.file];
  if (declared !== undefined && declared !== actual)
    throw failure(
      "DN42_INVALID_BUNDLE",
      `metadata.json declares ${declared} for ${database.file}, found ${actual}`,
    );
  return reader;
}

function parseAddress(input: string): string {
  if (isIP(input) === 0 || input.includes("%"))
    throw failure("DN42_INVALID_ADDRESS", `Invalid IP address: ${input}`);
  return ipaddr.process(input).toString();
}

function networkOf(ip: string, prefixLength: number): string {
  const cidr = `${ip}/${prefixLength}`;
  const network =
    isIP(ip) === 4
      ? ipaddr.IPv4.networkAddressFromCIDR(cidr)
      : ipaddr.IPv6.networkAddressFromCIDR(cidr);
  return `${network.toString()}/${prefixLength}`;
}

function buildBundle(files: ReleaseBytes): Bundle {
  const release = parseJson(
    releaseMetadataSchema,
    releaseFile(files, "metadata.json"),
    "metadata.json",
  );
  const index = parseJson(
    asnIndexSchema,
    releaseFile(files, "asn-index.json"),
    "asn-index.json",
  );
  for (const [key, info] of Object.entries(index.asns))
    if (key !== String(info.asn))
      throw failure(
        "DN42_INVALID_BUNDLE",
        `asn-index.json: key ${key} holds AS${info.asn}`,
      );
  const readers: Record<DatabaseKey, Reader<DatabaseRecord>> = {
    country: openReader(files, release, "country"),
    city: openReader(files, release, "city"),
    asn: openReader(files, release, "asn"),
    connection_type: openReader(files, release, "connection_type"),
  };
  const sortedAsns = Object.values(index.asns).sort(
    (left, right) => left.asn - right.asn,
  );
  let closed = false;
  const assertOpen = (): void => {
    if (closed) throw failure("DN42_CLOSED", "DN42 bundle is closed");
  };
  return {
    lookup(input) {
      assertOpen();
      const ip = parseAddress(input);
      const records: LookupResult["records"] = {};
      for (const { key } of databases) {
        const [data, prefixLength] = readers[key].getWithPrefixLength(ip);
        if (data && Object.keys(data).length > 0)
          records[key] = {
            network: networkOf(ip, prefixLength),
            prefix_length: prefixLength,
            data,
          };
      }
      return { ip, records };
    },
    lookupAsn(asn) {
      assertOpen();
      if (!Number.isInteger(asn) || asn < 0 || asn > 4_294_967_295)
        throw failure("DN42_INVALID_ASN", `Invalid ASN: ${asn}`);
      return index.asns[String(asn)];
    },
    asns() {
      assertOpen();
      return sortedAsns;
    },
    releaseMetadata() {
      assertOpen();
      return release;
    },
    metadata() {
      assertOpen();
      return {
        country: readers.country.metadata,
        city: readers.city.metadata,
        asn: readers.asn.metadata,
        connection_type: readers.connection_type.metadata,
      };
    },
    close() {
      closed = true;
    },
  };
}

export async function openBundle(directory: string): Promise<Bundle> {
  return buildBundle(await readRelease(directory));
}

async function openVerified(directory: string, checksums: Checksums): Promise<Bundle> {
  const files = await readRelease(directory);
  verifyChecksums(files, checksums, directory);
  return buildBundle(files);
}

function pickChecksums(
  source: Record<string, z.core.util.JSONType>,
  origin: string,
): Checksums {
  const checksums = new Map<ReleaseFile, string>();
  for (const file of releaseFiles) {
    const digest = digestSchema.safeParse(source[file]);
    if (!digest.success)
      throw failure("DN42_INVALID_BUNDLE", `${origin}: invalid checksum for ${file}`);
    checksums.set(file, digest.data);
  }
  return checksums;
}

function canonicalChecksums(checksums: Checksums): string {
  return JSON.stringify(
    Object.fromEntries(
      [...checksums].sort(([left], [right]) => (left < right ? -1 : 1)),
    ),
  );
}

/** Content address of a release: SHA-256 of its sorted, compact checksum object. */
const releaseVersion = (checksums: Checksums): string =>
  sha256(Buffer.from(canonicalChecksums(checksums), "utf8"));

const sameChecksums = (left: Checksums, right: Checksums): boolean =>
  releaseFiles.every((file) => left.get(file) === right.get(file));

const cacheRoot = (cacheDir: string): string => join(cacheDir, "typescript", "v2");

async function readPointer(cache: string): Promise<Pointer> {
  const path = join(cache, "current.json");
  let bytes: Buffer;
  try {
    bytes = await readBounded(path, manifestLimit);
  } catch (error) {
    if (hasErrno(error, "ENOENT"))
      throw failure("DN42_CACHE_MISSING", `No DN42 release cached at ${path}`, error);
    throw error;
  }
  const pointer = parseJson(pointerSchema, bytes, path);
  return {
    version: pointer.version,
    checksums: pickChecksums(pointer.checksums, path),
  };
}

/** The release directory lost a file or changed under a reader. */
const isStaleRead = (error: unknown): boolean =>
  isDn42IpdbError(error, "DN42_CHECKSUM_MISMATCH") ||
  (isDn42IpdbError(error, "DN42_INVALID_BUNDLE") && hasErrno(error.cause, "ENOENT"));

/** A cached release that cannot be used and is replaced by a download. */
const isDamaged = (error: unknown): boolean =>
  isDn42IpdbError(error, "DN42_CHECKSUM_MISMATCH") ||
  isDn42IpdbError(error, "DN42_INVALID_BUNDLE") ||
  isDn42IpdbError(error, "DN42_SIZE_LIMIT");

/** Opens the current cached release without network access or locks. */
export async function openCachedBundle(cacheDir: string): Promise<Bundle> {
  const cache = cacheRoot(cacheDir);
  return followPointer(
    () => readPointer(cache),
    (pointer) => openVerified(join(cache, pointer.version), pointer.checksums),
    isStaleRead,
  );
}

export interface DownloadOptions {
  cacheDir: string;
  baseURL?: string;
  /** Covers the writer-lock wait and every request. Defaults to 30 seconds. */
  timeoutMs?: number;
  signal?: AbortSignal;
}
export interface DownloadResult {
  directory: string;
  changed: boolean;
  /** The previous pointer or bundle was unreadable and has been replaced. */
  recoveredCache: boolean;
  bundle: Bundle;
}

function isLoopbackHost(hostname: string): boolean {
  const host = hostname.replace(/^\[(.*)\]$/, "$1");
  return isIP(host) !== 0 && ipaddr.parse(host).range() === "loopback";
}

/**
 * The authority of a raw URL reference. A scheme is followed by any number of
 * slashes or backslashes before the authority, so "https:@host/" names "host";
 * without a scheme, two slashes introduce it.
 */
function rawAuthority(text: string): string {
  // URL parsers drop tabs and newlines and trim leading C0 controls and spaces.
  const raw = text.replace(/[\t\n\r]/g, "").replace(/^[^!-~]+/, "");
  const scheme = /^[a-z][a-z0-9+.-]*:/i.exec(raw)?.[0] ?? "";
  const rest = raw.slice(scheme.length);
  const authority = rest.replace(/^[/\\]+/, "");
  const slashes = rest.length - authority.length;
  return scheme || slashes >= 2 ? (/^[^/\\?#]*/.exec(authority)?.[0] ?? "") : "";
}

/** The URL parser drops empty user info, queries and fragments, so check the raw text. */
function checkReleaseText(text: string, hop: boolean): void {
  if (
    rawAuthority(text).includes("@") ||
    text.includes("#") ||
    (!hop && text.includes("?"))
  )
    throw failure(
      "DN42_INVALID_URL",
      `Release URL ${text} must not contain credentials, a fragment${hop ? "" : " or a query"}`,
    );
}

function parseReleaseURL(text: string, current?: URL): URL {
  checkReleaseText(text, current !== undefined);
  try {
    return new URL(text, current);
  } catch (error) {
    throw failure("DN42_INVALID_URL", `Invalid release URL: ${text}`, error);
  }
}

function checkReleaseURL(url: URL, base?: URL): void {
  const allowed =
    !url.username &&
    !url.password &&
    !url.hash &&
    (base !== undefined || !url.search) &&
    (url.protocol === "https:" ||
      (url.protocol === "http:" &&
        isLoopbackHost(url.hostname) &&
        (base === undefined || (base.protocol === "http:" && base.host === url.host))));
  if (!allowed)
    throw failure(
      "DN42_INVALID_URL",
      `Release URL ${url.href} must use HTTPS or loopback HTTP without credentials`,
    );
}

function releaseBase(address: string): URL {
  const base = parseReleaseURL(address);
  checkReleaseURL(base);
  if (!base.pathname.endsWith("/")) base.pathname += "/";
  return base;
}

const redirectStatuses = new Set([301, 302, 303, 307, 308]);
const maxRedirects = 10;

async function fetchRelease(
  address: URL,
  base: URL,
  signal: AbortSignal,
): Promise<Response> {
  let current = address;
  for (let redirects = 0; ; redirects++) {
    checkReleaseURL(current, base);
    const response = await fetch(current, {
      signal,
      redirect: "manual",
      headers: { "user-agent": "DN42-IPDB-SDK-TypeScript" },
    });
    if (!redirectStatuses.has(response.status)) return response;
    await response.body?.cancel();
    const location = response.headers.get("location");
    if (!location || redirects === maxRedirects)
      throw failure(
        "DN42_INVALID_URL",
        `Invalid release redirect from ${current.href}`,
      );
    current = parseReleaseURL(location, current);
  }
}

async function download(
  address: URL,
  base: URL,
  limit: number,
  signal: AbortSignal,
): Promise<Buffer> {
  const response = await fetchRelease(address, base, signal);
  if (response.status !== 200 || !response.body) {
    await response.body?.cancel();
    throw failure(
      "DN42_HTTP_STATUS",
      `Download ${address.href}: HTTP ${response.status}`,
    );
  }
  const length = Number(response.headers.get("content-length") ?? 0);
  if (length > limit) {
    await response.body.cancel();
    throw failure("DN42_SIZE_LIMIT", `Download ${address.href} exceeds ${limit} bytes`);
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const item = await reader.read();
      if (item.done) return Buffer.concat(chunks, size);
      size += item.value.length;
      if (size > limit)
        throw failure(
          "DN42_SIZE_LIMIT",
          `Download ${address.href} exceeds ${limit} bytes`,
        );
      chunks.push(item.value);
    }
  } finally {
    await reader.cancel();
  }
}

async function fetchChecksums(base: URL, signal: AbortSignal): Promise<Checksums> {
  const address = new URL("checksums.json", base);
  const manifest = parseJson(
    z.record(z.string(), z.json()),
    await download(address, base, manifestLimit, signal),
    address.href,
  );
  return pickChecksums(manifest, address.href);
}

async function acquireWriterLock(
  cache: string,
  signal: AbortSignal,
  deadline: AbortSignal,
  onCompromised: (error: Error) => void,
): Promise<() => Promise<void>> {
  const lockfilePath = join(cache, ".update.lock");
  for (;;) {
    try {
      return await lock(cache, { retries: 0, lockfilePath, onCompromised });
    } catch (error) {
      if (!hasErrno(error, "ELOCKED")) throw error;
    }
    try {
      await sleep(lockPollMs, undefined, { signal });
    } catch (error) {
      if (deadline.aborted)
        throw failure(
          "DN42_LOCK_TIMEOUT",
          `Timed out waiting for ${lockfilePath}`,
          error,
        );
      throw error;
    }
  }
}

/** Reads the active pointer; an unreadable pointer is reported instead of thrown. */
async function readPreviousPointer(
  cache: string,
): Promise<{ pointer?: Pointer; recovered: boolean }> {
  try {
    return { pointer: await readPointer(cache), recovered: false };
  } catch (error) {
    if (isDn42IpdbError(error, "DN42_CACHE_MISSING")) return { recovered: false };
    if (
      isDn42IpdbError(error, "DN42_INVALID_BUNDLE") ||
      isDn42IpdbError(error, "DN42_SIZE_LIMIT")
    )
      return { recovered: true };
    throw error;
  }
}

async function downloadFiles(
  base: URL,
  checksums: Checksums,
  stage: string,
  signal: AbortSignal,
): Promise<ReleaseBytes> {
  const files = new Map<ReleaseFile, Buffer>();
  for (const file of releaseFiles) {
    const address = new URL(file, base);
    const bytes = await download(address, base, sizeLimit(file), signal);
    if (sha256(bytes) !== checksums.get(file))
      throw failure("DN42_CHECKSUM_MISMATCH", `Checksum mismatch: ${address.href}`);
    const handle = await open(join(stage, file), "wx", 0o600);
    try {
      await handle.writeFile(bytes);
      await handle.sync();
    } finally {
      await handle.close();
    }
    files.set(file, bytes);
  }
  return files;
}

/** Moves the stage to its version directory; returns true when this call created it. */
async function placeRelease(
  stage: string,
  directory: string,
  checksums: Checksums,
): Promise<boolean> {
  try {
    await stat(directory);
  } catch (error) {
    if (!hasErrno(error, "ENOENT")) throw error;
    await rename(stage, directory);
    return true;
  }
  try {
    verifyChecksums(await readRelease(directory), checksums, directory);
    return false;
  } catch (error) {
    if (!isDamaged(error)) throw error;
  }
  await rm(directory, { recursive: true });
  await rename(stage, directory);
  return true;
}

const isOwnedRelease = async (directory: string): Promise<boolean> => {
  const entries = await readdir(directory, { withFileTypes: true });
  return (
    entries.length === releaseFiles.length &&
    entries.every(
      (entry) => entry.isFile() && releaseFiles.some((file) => file === entry.name),
    )
  );
};

/** Removes leftovers of earlier runs and releases other than the kept versions. */
async function pruneCache(cache: string, keep: ReadonlySet<string>): Promise<void> {
  for (const entry of await readdir(cache, { withFileTypes: true })) {
    if (keep.has(entry.name)) continue;
    const path = join(cache, entry.name);
    if (entry.name.startsWith(".stage-") || entry.name.startsWith(".current-"))
      await rm(path, { recursive: true, force: true });
    else if (
      entry.isDirectory() &&
      digestSchema.safeParse(entry.name).success &&
      (await isOwnedRelease(path))
    )
      await rm(path, { recursive: true });
  }
}

async function commitPointer(
  cache: string,
  pointer: Pointer,
  signal: AbortSignal,
): Promise<void> {
  const pending = join(cache, `.current-${randomBytes(16).toString("hex")}`);
  try {
    const handle = await open(pending, "wx", 0o600);
    try {
      await handle.writeFile(
        `{"version":${JSON.stringify(pointer.version)},"checksums":${canonicalChecksums(pointer.checksums)}}`,
      );
      await handle.sync();
    } finally {
      await handle.close();
    }
    signal.throwIfAborted();
    await rename(pending, join(cache, "current.json"));
  } finally {
    await rm(pending, { force: true });
  }
}

async function installRelease(
  cache: string,
  base: URL,
  checksums: Checksums,
  previous: string | undefined,
  signal: AbortSignal,
): Promise<{ directory: string; bundle: Bundle }> {
  const stage = await mkdtemp(join(cache, ".stage-"));
  try {
    const bundle = buildBundle(await downloadFiles(base, checksums, stage, signal));
    const version = releaseVersion(checksums);
    const directory = join(cache, version);
    signal.throwIfAborted();
    const created = await placeRelease(stage, directory, checksums);
    try {
      const keep = new Set([version, basename(stage)]);
      if (previous) keep.add(previous);
      await pruneCache(cache, keep);
      await commitPointer(cache, { version, checksums }, signal);
    } catch (error) {
      if (created) await rm(directory, { recursive: true, force: true });
      throw error;
    }
    return { directory, bundle };
  } finally {
    await rm(stage, { recursive: true, force: true });
  }
}

/**
 * Verifies a complete release and activates it in `cacheDir/typescript/v2`.
 * The cache keeps the current and previous release.
 */
export async function downloadRelease(
  options: DownloadOptions,
): Promise<DownloadResult> {
  if (!options.cacheDir) throw new TypeError("cacheDir is required");
  const base = releaseBase(options.baseURL ?? defaultReleaseURL);
  const timeoutMs = options.timeoutMs ?? defaultTimeoutMs;
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > maxTimerMs)
    throw new RangeError(`timeoutMs must be an integer from 1 to ${maxTimerMs}`);
  const compromised = new AbortController();
  const deadline = AbortSignal.timeout(timeoutMs);
  const signal = AbortSignal.any(
    options.signal
      ? [compromised.signal, deadline, options.signal]
      : [compromised.signal, deadline],
  );
  signal.throwIfAborted();
  const cache = cacheRoot(options.cacheDir);
  await mkdir(cache, { recursive: true, mode: 0o700 });
  const release = await acquireWriterLock(cache, signal, deadline, (error) =>
    compromised.abort(error),
  );
  try {
    const checksums = await fetchChecksums(base, signal);
    const previous = await readPreviousPointer(cache);
    let recoveredCache = previous.recovered;
    if (previous.pointer && sameChecksums(previous.pointer.checksums, checksums)) {
      const directory = join(cache, previous.pointer.version);
      try {
        const bundle = await openVerified(directory, checksums);
        return { directory, changed: false, recoveredCache: false, bundle };
      } catch (error) {
        if (!isDamaged(error)) throw error;
        recoveredCache = true;
      }
    }
    const installed = await installRelease(
      cache,
      base,
      checksums,
      previous.pointer?.version,
      signal,
    );
    return { ...installed, changed: true, recoveredCache };
  } finally {
    // A compromised lock is already released; the abort reason is the error to report.
    if (!compromised.signal.aborted) await release();
  }
}
