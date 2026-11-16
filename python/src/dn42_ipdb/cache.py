"""Cache layout, pointer file and verified reads."""

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import NamedTuple

from .bundle import (
    ARTIFACT_FILES,
    DIGEST,
    MAX_MANIFEST_BYTES,
    Bundle,
    build_bundle,
    load_json,
    read_file,
    read_release_file,
)
from .errors import CacheMissingError, ChecksumMismatchError, InvalidBundleError

POINTER_FILE = "current.json"
LOCK_FILE = ".update.lock"
MAX_ATTEMPTS = 3

Pointer = NamedTuple(  # noqa: UP014 (functional form is the project style)
    "Pointer", [("version", str), ("checksums", dict[str, str])]
)


def cache_directory(cache_dir: str | Path) -> Path:
    return Path(cache_dir) / "python" / "v2"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def required_checksums(checksums: dict[str, str], source: str) -> dict[str, str]:
    """Return the digests of the seven bundle files, ignoring other keys.

    `source` names the manifest or pointer file that supplied them.
    """
    for name in ARTIFACT_FILES:
        digest = checksums.get(name)
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise InvalidBundleError(source, f"{name} needs a sha256 digest")
    return {name: checksums[name] for name in sorted(ARTIFACT_FILES)}


def content_version(checksums: dict[str, str]) -> str:
    """Name a bundle after the digests of its files."""
    canonical = json.dumps(checksums, sort_keys=True, separators=(",", ":"))
    return sha256(canonical.encode())


def read_pointer(cache: Path) -> Pointer:
    """Read current.json; a missing file is a cache-missing error."""
    path = cache / POINTER_FILE
    try:
        data = read_file(path, MAX_MANIFEST_BYTES)
    except FileNotFoundError as error:
        raise CacheMissingError(str(path)) from error
    pointer = load_json(data, POINTER_FILE)
    if not isinstance(pointer, dict) or not isinstance(pointer.get("checksums"), dict):
        raise InvalidBundleError(POINTER_FILE, "must hold a version and checksums")
    version = pointer.get("version")
    if not isinstance(version, str) or not DIGEST.fullmatch(version):
        raise InvalidBundleError(POINTER_FILE, "version must be 64 hex digits")
    return Pointer(version, required_checksums(pointer["checksums"], POINTER_FILE))


def read_verified(directory: Path, checksums: dict[str, str]) -> Bundle:
    """Read the seven files once, compare digests and build the bundle."""
    files = {}
    for name in ARTIFACT_FILES:
        files[name] = read_release_file(directory, name)
        if sha256(files[name]) != checksums[name]:
            raise ChecksumMismatchError(name)
    return build_bundle(files)


def _is_retryable(error: InvalidBundleError) -> bool:
    """A file that vanished or changed may belong to a version a writer replaced."""
    return isinstance(error, ChecksumMismatchError) or isinstance(
        error.__cause__, FileNotFoundError
    )


def open_current(
    cache: Path,
    read: Callable[[Path, dict[str, str]], Bundle] = read_verified,
) -> Bundle:
    """Open the current version, following the pointer if a writer moves it."""
    pointer = read_pointer(cache)
    for _ in range(MAX_ATTEMPTS - 1):
        try:
            return read(cache / pointer.version, pointer.checksums)
        except InvalidBundleError as error:
            if not _is_retryable(error):
                raise
            moved = read_pointer(cache)
            if moved.version == pointer.version:
                raise
            pointer = moved
    return read(cache / pointer.version, pointer.checksums)


def open_cached_bundle(cache_dir: str | Path) -> Bundle:
    """Read the verified current cache without network activity or locking."""
    return open_current(cache_directory(cache_dir))
