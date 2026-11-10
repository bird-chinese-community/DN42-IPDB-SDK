import asyncio
import hashlib
import ipaddress
import json
import os
import re
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from importlib.metadata import version
from io import BytesIO
from pathlib import Path
from secrets import token_hex
from urllib.parse import urljoin, urlsplit

import httpx
import maxminddb
from filelock import AsyncFileLock, FileLock

__version__ = version("dn42-ipdb")
DEFAULT_RELEASE_URL = "https://github.com/bird-chinese-community/DN42-IPDB-Releases/releases/latest/download/"
MAX_DATABASE_BYTES = 32 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
ARTIFACT_TYPES = {
    "country": ("country.mmdb", "DN42-GeoIP2-Country", "DN42-Country"),
    "city": ("city.mmdb", "DN42-GeoIP2-City", "DN42-City"),
    "asn": ("asn.mmdb", "DN42-GeoLite2-ASN", "DN42-ASN"),
    "connection_type": (
        "connection-type.mmdb",
        "DN42-GeoIP2-Connection-Type",
        "DN42-Connection-Type",
    ),
}
ARTIFACT_FILES = [item[0] for item in ARTIFACT_TYPES.values()] + [
    "asn-index.json",
    "metadata.json",
    "LICENSE-Unicode.txt",
]
type Record = dict[str, object]
type Bundle = tuple[dict[str, maxminddb.Reader], dict[str, Record], Record]


def _read_bounded(path: Path, limit: int) -> bytes:
    with path.open("rb") as stream:
        if not path.is_file() or os.fstat(stream.fileno()).st_size > limit:
            raise ValueError(f"Invalid cache file size: {path}")
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError(f"Cache file exceeds size limit: {path}")
        return data


@contextmanager
def open_bundle(directory: str | Path) -> Iterator[Bundle]:
    """Load an immutable in-memory release for local lookups."""
    path = Path(directory)
    index = json.loads(_read_bounded(path / "asn-index.json", MAX_DATABASE_BYTES))
    release = json.loads(_read_bounded(path / "metadata.json", MAX_DATABASE_BYTES))
    if (
        not isinstance(index, dict)
        or index.get("schema_version") != "2"
        or not isinstance(index.get("asns"), dict)
    ):
        raise ValueError("Invalid ASN index schema")
    if (
        not isinstance(release, dict)
        or not release.get("release_repository")
        or not release.get("copyright")
    ):
        raise ValueError("Invalid release metadata")
    readers = {}
    try:
        for key, (filename, kind, legacy) in ARTIFACT_TYPES.items():
            data = _read_bounded(path / filename, MAX_DATABASE_BYTES)
            reader = maxminddb.open_database(BytesIO(data), mode=maxminddb.MODE_FD)
            readers[key] = reader
            if reader.metadata().database_type not in {kind, legacy}:
                raise ValueError(f"{filename}: expected {kind} database")
        yield readers, index["asns"], release
    finally:
        for reader in readers.values():
            reader.close()


def lookup(bundle: Bundle, address: str) -> Record:
    """Return raw GeoIP2-compatible records, preserving the dn42 extension."""
    if "%" in address:
        raise ValueError(f"Invalid IP address: {address}")
    ip = ipaddress.ip_address(address)
    records = {}
    for key, reader in bundle[0].items():
        record, prefix_length = reader.get_with_prefix_len(str(ip))
        if record:
            records[key] = {"prefix_length": prefix_length, "data": record}
    return {"ip": str(ip), "records": records}


def lookup_asn(bundle: Bundle, asn: int) -> Record | None:
    """Return member-prefix observations without classifying the entire AS."""
    if isinstance(asn, bool) or not isinstance(asn, int) or not 0 <= asn <= 4294967295:
        raise ValueError(f"Invalid ASN: {asn}")
    return bundle[1].get(str(asn))


def metadata(bundle: Bundle) -> dict[str, Record]:
    output = {}
    for key, reader in bundle[0].items():
        value = reader.metadata()
        output[key] = {
            "database_type": value.database_type,
            "description": value.description,
            "build_epoch": value.build_epoch,
            "languages": value.languages,
            "ip_version": value.ip_version,
        }
    return output


def release_metadata(bundle: Bundle) -> Record:
    return bundle[2]


def _verify(directory: Path, checksums: dict[str, str]) -> None:
    for filename in ARTIFACT_FILES:
        data = _read_bounded(directory / filename, MAX_DATABASE_BYTES)
        if hashlib.sha256(data).hexdigest() != checksums[filename]:
            raise ValueError(f"Checksum mismatch: {filename}")
    with open_bundle(directory):
        pass


def _read_pointer(cache: Path) -> tuple[str, dict[str, str]] | None:
    data = _read_bounded(cache / "current.json", MAX_MANIFEST_BYTES)
    try:
        pointer = json.loads(data)
    except json.JSONDecodeError:
        return None
    if not isinstance(pointer, dict):
        return None
    current = pointer.get("version")
    checksums = pointer.get("checksums")
    if (
        not isinstance(current, str)
        or re.fullmatch(r"[0-9a-f]{64}", current) is None
        or not isinstance(checksums, dict)
    ):
        return None
    for filename in ARTIFACT_FILES:
        digest = checksums.get(filename)
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            return None
    return current, checksums


@contextmanager
def open_cached_bundle(cache_dir: str | Path) -> Iterator[Bundle]:
    """Read the verified current cache without network activity."""
    cache = Path(cache_dir) / "python"
    with ExitStack() as stack:
        with FileLock(cache / ".update.lock", timeout=0):
            pointer = _read_pointer(cache)
            if pointer is None:
                raise ValueError(f"Invalid cache pointer: {cache / 'current.json'}")
            current, checksums = pointer
            directory = cache / current
            _verify(directory, checksums)
            bundle = stack.enter_context(open_bundle(directory))
        yield bundle


async def _download(
    client: httpx.AsyncClient, address: str, limit: int, base: str
) -> bytes:
    initial = urlsplit(base)
    current = address
    for redirects in range(11):
        target = urlsplit(current)
        if (
            target.username
            or target.password
            or (
                target.scheme != "https"
                and not (
                    initial.scheme == "http"
                    and target.netloc == initial.netloc
                    and target.scheme == "http"
                )
            )
        ):
            raise ValueError("Insecure release redirect")
        async with client.stream("GET", current, follow_redirects=False) as response:
            if response.is_redirect:
                location = response.headers.get("location")
                if not location or redirects == 10:
                    raise ValueError("Invalid release redirect")
                current = urljoin(current, location)
                continue
            response.raise_for_status()
            length = response.headers.get("content-length")
            if length is not None and int(length) > limit:
                raise ValueError(f"Download {address}: size limit exceeded")
            chunks = []
            size = 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > limit:
                    raise ValueError(f"Download {address}: size limit exceeded")
                chunks.append(chunk)
            return b"".join(chunks)
    raise ValueError("Invalid release redirect")


async def download_release(
    cache_dir: str | Path,
    *,
    base_url: str = DEFAULT_RELEASE_URL,
    timeout: float = 30,
) -> Record:
    """Verify seven files before activating a bundle in cache_dir/python."""
    if not cache_dir:
        raise ValueError("cache_dir is required")
    base = urlsplit(base_url)
    loopback = base.scheme == "http" and base.hostname in {"127.0.0.1", "::1"}
    if (
        not base.hostname
        or base.username
        or base.password
        or (base.scheme != "https" and not loopback)
    ):
        raise ValueError("Release URL requires HTTPS or loopback HTTP")
    if not base_url.endswith("/"):
        base_url += "/"
    cache = Path(cache_dir) / "python"
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    async with (
        asyncio.timeout(timeout),
        AsyncFileLock(cache / ".update.lock", timeout=timeout),
        httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            headers={"user-agent": f"DN42-IPDB-SDK-Python/{__version__}"},
        ) as client,
    ):
        checksums = json.loads(
            await _download(
                client,
                urljoin(base_url, "checksums.json"),
                MAX_MANIFEST_BYTES,
                base_url,
            )
        )
        if not isinstance(checksums, dict):
            raise TypeError("Invalid checksum manifest")
        for filename in ARTIFACT_FILES:
            digest = checksums.get(filename)
            if (
                not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            ):
                raise ValueError(f"Invalid checksum for {filename}")
        previous = None
        recovered_cache = False
        current = cache / "current.json"
        if current.exists():
            pointer = _read_pointer(cache)
            if pointer is None:
                recovered_cache = True
            else:
                previous, old_checksums = pointer
                directory = cache / previous
                if all(
                    old_checksums[name] == checksums[name] for name in ARTIFACT_FILES
                ):
                    _verify(directory, checksums)
                    return {"directory": str(directory), "changed": False}
        stage = Path(tempfile.mkdtemp(prefix=".stage-", dir=cache))
        try:
            for filename in ARTIFACT_FILES:
                data = await _download(
                    client, urljoin(base_url, filename), MAX_DATABASE_BYTES, base_url
                )
                if hashlib.sha256(data).hexdigest() != checksums[filename]:
                    raise ValueError(f"Checksum mismatch: {filename}")
                (stage / filename).write_bytes(data)
            _verify(stage, checksums)
            current_version = token_hex(32)
            destination = cache / current_version
            pending = cache / f".current-{current_version}"
            committed = False
            try:
                pending.write_text(
                    json.dumps({"version": current_version, "checksums": checksums}),
                    encoding="utf-8",
                )
                for entry in cache.iterdir():
                    if (
                        entry.is_symlink()
                        or not entry.is_dir()
                        or re.fullmatch(r"[0-9a-f]{64}", entry.name) is None
                        or entry.name in {current_version, previous}
                    ):
                        continue
                    files = list(entry.iterdir())
                    if len(files) == len(ARTIFACT_FILES) and all(
                        not file.is_symlink()
                        and file.is_file()
                        and file.name in ARTIFACT_FILES
                        for file in files
                    ):
                        shutil.rmtree(entry)
                os.replace(stage, destination)
                os.replace(pending, current)
                committed = True
                result: Record = {"directory": str(destination), "changed": True}
                if recovered_cache:
                    result["recovered_cache"] = True
                return result
            finally:
                if not committed and destination.exists():
                    shutil.rmtree(destination)
                pending.unlink(missing_ok=True)
        finally:
            if stage.exists():
                shutil.rmtree(stage)
