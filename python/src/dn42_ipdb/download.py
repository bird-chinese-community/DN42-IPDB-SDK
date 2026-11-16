"""Verified release download into the cache."""

import asyncio
import concurrent.futures
import ipaddress
import json
import os
import shutil
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from collections.abc import Callable
from http.client import HTTPException, HTTPResponse
from pathlib import Path
from typing import NamedTuple, TypedDict
from urllib.parse import SplitResult, urljoin, urlsplit

from filelock import FileLock, Timeout

from ._version import __version__
from .bundle import (
    ARTIFACT_FILES,
    DIGEST,
    MAX_MANIFEST_BYTES,
    Bundle,
    build_bundle,
    file_limit,
    load_json,
)
from .cache import (
    LOCK_FILE,
    POINTER_FILE,
    Pointer,
    cache_directory,
    content_version,
    read_pointer,
    read_verified,
    required_checksums,
    sha256,
)
from .errors import (
    CacheMissingError,
    ChecksumMismatchError,
    HttpStatusError,
    InvalidBundleError,
    InvalidUrlError,
    LockTimeoutError,
    SizeLimitError,
)

DEFAULT_RELEASE_URL = "https://github.com/bird-chinese-community/DN42-IPDB-Releases/releases/latest/download/"
MANIFEST_FILE = "checksums.json"
USER_AGENT = f"DN42-IPDB-SDK-Python/{__version__}"
MAX_REDIRECTS = 10
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
WINDOWS = sys.platform == "win32"
POLL_SECONDS = 0.05
MIN_REQUEST_SECONDS = 0.001
# Largest whole number of seconds whose milliseconds fit a signed 32-bit integer,
# the bound of Windows socket timeouts and TypeScript timers.
MAX_TIMEOUT_SECONDS = min(threading.TIMEOUT_MAX, 2_147_483)
CHUNK_BYTES = 64 * 1024
TEMP_PREFIXES = (".stage-", ".current-")

DownloadResult = TypedDict(
    "DownloadResult",
    {"directory": str, "changed": bool, "recovered_cache": bool, "bundle": Bundle},
)
Session = NamedTuple(  # noqa: UP014 (functional form is the project style)
    "Session",
    [
        ("cache", Path),
        ("base", str),
        ("origin", SplitResult),
        ("deadline", float),
        ("stop", threading.Event),
    ],
)


def _split(url: str) -> SplitResult:
    try:
        parts = urlsplit(url)
        _ = parts.port
    except ValueError as error:
        raise InvalidUrlError(f"invalid URL {url!r}: {error}") from error
    return parts


def _is_loopback(host: str | None) -> bool:
    if host is None:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv4Address):
        return address.is_loopback
    return address == ipaddress.IPv6Address("::1")


def _check_hop(url: str, origin: SplitResult) -> None:
    """Allow https, or http to the loopback origin of an http base URL."""
    parts = _split(url)
    if not parts.hostname or "@" in parts.netloc:
        raise InvalidUrlError(f"URL needs a host and no credentials: {url!r}")
    if parts.scheme == "https":
        return
    same_origin = (
        origin.scheme == "http"
        and _is_loopback(origin.hostname)
        and parts.hostname == origin.hostname
        and (parts.port or 80) == (origin.port or 80)
    )
    if parts.scheme != "http" or not same_origin:
        raise InvalidUrlError(f"URL requires https or loopback http: {url!r}")


def _validate_base_url(base_url: str) -> tuple[str, SplitResult]:
    origin = _split(base_url)
    if "?" in base_url or "#" in base_url:
        raise InvalidUrlError(f"base URL has a query or fragment: {base_url!r}")
    _check_hop(base_url, origin)
    return (base_url if base_url.endswith("/") else base_url + "/"), origin


def _validate_timeout(timeout: float) -> float:
    if isinstance(timeout, bool) or not 0 < timeout <= MAX_TIMEOUT_SECONDS:
        raise ValueError(
            f"timeout must be a number of seconds in (0, {MAX_TIMEOUT_SECONDS}]: "
            f"{timeout!r}"
        )
    return float(timeout)


def _opener() -> urllib.request.OpenerDirector:
    """Build an opener that honors proxy variables and never follows redirects."""
    opener = urllib.request.OpenerDirector()
    for handler in (
        urllib.request.ProxyHandler(),
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(),
        urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.HTTPErrorProcessor(),
    ):
        opener.add_handler(handler)
    return opener


def _transport_error(url: str, error: OSError | HTTPException) -> OSError:
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(reason, TimeoutError):
        return TimeoutError(f"GET {url} timed out")
    return ConnectionError(f"GET {url} failed: {reason}")


def _read_body(
    response: HTTPResponse, url: str, limit: int, stop: threading.Event
) -> bytes:
    length = response.headers.get("Content-Length", "")
    if length.strip().isdigit() and int(length) > limit:
        raise SizeLimitError(url, limit)
    chunks = []
    size = 0
    while chunk := response.read(CHUNK_BYTES):
        size += len(chunk)
        if size > limit:
            raise SizeLimitError(url, limit)
        if stop.is_set():
            raise InterruptedError(f"download of {url} was cancelled")
        chunks.append(chunk)
    return b"".join(chunks)


def _redirect_target(url: str, error: urllib.error.HTTPError) -> str:
    location = error.headers.get("Location")
    error.close()
    if error.code not in REDIRECT_STATUSES:
        raise HttpStatusError(url, error.code) from error
    if not location:
        raise InvalidUrlError(
            f"redirect {error.code} from {url} has no Location header"
        ) from error
    if "#" in location or "@" in _split(location).netloc:
        raise InvalidUrlError(
            f"redirect Location has a fragment or credentials: {location!r}"
        )
    try:
        return urljoin(url, location)
    except ValueError as reason:
        raise InvalidUrlError(f"unparsable redirect Location {location!r}") from reason


def fetch_bytes(
    url: str,
    origin: SplitResult,
    limit: int,
    timeout: float,
    stop: threading.Event,
) -> bytes:
    """GET one URL, validating every redirect hop and bounding the body."""
    opener = _opener()
    for _ in range(MAX_REDIRECTS + 1):
        _check_hop(url, origin)
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with opener.open(request, timeout=timeout) as response:
                if response.status != 200:
                    raise HttpStatusError(url, response.status)
                return _read_body(response, url, limit, stop)
        except urllib.error.HTTPError as error:
            url = _redirect_target(url, error)
        except (OSError, HTTPException) as error:
            raise _transport_error(url, error) from error
    raise InvalidUrlError(f"more than {MAX_REDIRECTS} redirects from {url}")


async def _wait_thread[**P, T](
    stop: threading.Event,
    function: Callable[P, T],
    *args: P.args,
    **kwargs: P.kwargs,
) -> T:
    """Run blocking work in a thread; on cancellation let it finish first."""
    task = asyncio.ensure_future(asyncio.to_thread(function, *args, **kwargs))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        stop.set()
        await asyncio.wait([task])
        if not task.cancelled():
            task.exception()
        raise


async def _finish_thread[**P, T](
    stop: threading.Event,
    function: Callable[P, T],
    *args: P.args,
    **kwargs: P.kwargs,
) -> T:
    """Run publishing work in a thread; a call that completed is never reported
    as cancelled, because its effects are already visible."""
    task = asyncio.ensure_future(asyncio.to_thread(function, *args, **kwargs))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        stop.set()
        await asyncio.wait([task])
        if task.cancelled() or task.exception() is not None:
            raise
        return task.result()


async def _abandon_thread[**P, T](
    stop: threading.Event,
    function: Callable[P, T],
    *args: P.args,
    **kwargs: P.kwargs,
) -> T:
    """Run a network request in a daemon thread that cancellation leaves behind."""
    outcome: concurrent.futures.Future[T] = concurrent.futures.Future()

    def run() -> None:
        if not outcome.set_running_or_notify_cancel():
            return
        try:
            outcome.set_result(function(*args, **kwargs))
        except Exception as error:  # noqa: BLE001 (forwarded to the awaiting future)
            outcome.set_exception(error)

    threading.Thread(target=run, daemon=True).start()
    try:
        return await asyncio.wrap_future(outcome)
    except asyncio.CancelledError:
        stop.set()
        raise


async def _acquire_lock(path: Path, deadline: float) -> FileLock:
    """Poll the exclusive writer lock until the deadline."""
    lock = FileLock(path, mode=0o600)
    loop = asyncio.get_running_loop()
    while True:
        try:
            lock.acquire(blocking=False)
            return lock
        except Timeout as error:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise LockTimeoutError(f"cache writer lock is held: {path}") from error
            await asyncio.sleep(min(POLL_SECONDS, remaining))


async def _fetch(session: Session, name: str, limit: int) -> bytes:
    remaining = session.deadline - asyncio.get_running_loop().time()
    return await _abandon_thread(
        session.stop,
        fetch_bytes,
        urljoin(session.base, name),
        session.origin,
        limit,
        max(remaining, MIN_REQUEST_SECONDS),
        session.stop,
    )


def _parse_manifest(data: bytes) -> dict[str, str]:
    manifest = load_json(data, MANIFEST_FILE)
    if not isinstance(manifest, dict):
        raise InvalidBundleError(MANIFEST_FILE, "must be an object")
    return required_checksums(manifest, MANIFEST_FILE)


def _create_cache(cache: Path) -> None:
    cache.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    cache.mkdir(mode=0o700, exist_ok=True)


def _make_stage(cache: Path) -> Path:
    return Path(tempfile.mkdtemp(prefix=".stage-", dir=cache))


def _read_previous(cache: Path) -> tuple[Pointer | None, bool]:
    """Return the current pointer and whether an unusable one was ignored."""
    try:
        return read_pointer(cache), False
    except CacheMissingError:
        return None, False
    except (InvalidBundleError, SizeLimitError):
        return None, True


def _read_reusable(directory: Path, checksums: dict[str, str]) -> Bundle | None:
    try:
        return read_verified(directory, checksums)
    except (InvalidBundleError, SizeLimitError):
        return None


def _write_private(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _store(stage: Path, name: str, data: bytes, digest: str) -> None:
    if sha256(data) != digest:
        raise ChecksumMismatchError(name)
    _write_private(stage / name, data)


async def _download_files(
    session: Session, stage: Path, checksums: dict[str, str]
) -> dict[str, bytes]:
    files = {}
    for name in ARTIFACT_FILES:
        data = await _fetch(session, name, file_limit(name))
        await _wait_thread(session.stop, _store, stage, name, data, checksums[name])
        files[name] = data
    return files


def _is_bundle_directory(entry: Path) -> bool:
    children = list(entry.iterdir())
    return {child.name for child in children} == set(ARTIFACT_FILES) and all(
        child.is_file() and not child.is_symlink() for child in children
    )


def _retry_denied[T](stop: threading.Event, operation: Callable[[], T]) -> T:
    """Run a rename or removal; on Windows a reader that still has the target
    open denies it, so retry until the download is cancelled or times out."""
    while True:
        try:
            return operation()
        except PermissionError:
            if not WINDOWS or stop.is_set():
                raise
            stop.wait(POLL_SECONDS)


def _remove(stop: threading.Event, entry: Path) -> None:
    if entry.is_dir() and not entry.is_symlink():
        _retry_denied(stop, lambda: shutil.rmtree(entry))
    else:
        _retry_denied(stop, entry.unlink)


def _prune(stop: threading.Event, cache: Path, keep: set[str]) -> None:
    """Remove leftovers of earlier runs and superseded bundle directories."""
    for entry in cache.iterdir():
        if entry.name.startswith(TEMP_PREFIXES) or (
            DIGEST.fullmatch(entry.name)
            and entry.name not in keep
            and entry.is_dir()
            and not entry.is_symlink()
            and _is_bundle_directory(entry)
        ):
            _remove(stop, entry)


def _place_stage(
    stop: threading.Event, stage: Path, destination: Path, checksums: dict[str, str]
) -> bool:
    """Move the stage to its version directory; False if a valid one exists."""
    if destination.exists():
        if _read_reusable(destination, checksums) is not None:
            _remove(stop, stage)
            return False
        _remove(stop, destination)
    _retry_denied(stop, lambda: os.replace(stage, destination))
    return True


def _write_pointer(
    stop: threading.Event, cache: Path, version: str, checksums: dict[str, str]
) -> None:
    descriptor, name = tempfile.mkstemp(prefix=".current-", dir=cache)
    pending = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump({"version": version, "checksums": checksums}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        if stop.is_set():
            raise InterruptedError("download was cancelled before publication")
        _retry_denied(stop, lambda: os.replace(pending, cache / POINTER_FILE))
    except BaseException:
        pending.unlink(missing_ok=True)
        raise


def _commit(
    stop: threading.Event,
    cache: Path,
    stage: Path,
    checksums: dict[str, str],
    previous: Pointer | None,
) -> str:
    """Publish the staged bundle; return its version directory."""
    version = content_version(checksums)
    destination = cache / version
    created = _place_stage(stop, stage, destination, checksums)
    try:
        _prune(stop, cache, {version} | ({previous.version} if previous else set()))
        _write_pointer(stop, cache, version, checksums)
    except BaseException:
        if created:
            shutil.rmtree(destination, ignore_errors=True)
        raise
    return str(destination)


async def _stage_and_commit(
    session: Session,
    checksums: dict[str, str],
    previous: Pointer | None,
    recovered_cache: bool,
) -> DownloadResult:
    stage = await _wait_thread(session.stop, _make_stage, session.cache)
    try:
        files = await _download_files(session, stage, checksums)
        bundle = await _wait_thread(session.stop, build_bundle, files)
        directory = await _finish_thread(
            session.stop,
            _commit,
            session.stop,
            session.cache,
            stage,
            checksums,
            previous,
        )
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return {
        "directory": directory,
        "changed": True,
        "recovered_cache": recovered_cache,
        "bundle": bundle,
    }


async def _refresh(session: Session) -> DownloadResult:
    checksums = _parse_manifest(
        await _fetch(session, MANIFEST_FILE, MAX_MANIFEST_BYTES)
    )
    previous, recovered_cache = await _wait_thread(
        session.stop, _read_previous, session.cache
    )
    if previous is not None and previous.checksums == checksums:
        directory = session.cache / previous.version
        bundle = await _wait_thread(session.stop, _read_reusable, directory, checksums)
        if bundle is not None:
            return {
                "directory": str(directory),
                "changed": False,
                "recovered_cache": False,
                "bundle": bundle,
            }
        recovered_cache = True
    return await _stage_and_commit(session, checksums, previous, recovered_cache)


async def download_release(
    cache_dir: str | Path,
    *,
    base_url: str = DEFAULT_RELEASE_URL,
    timeout: float = 30,
) -> DownloadResult:
    """Verify seven files before activating a bundle in cache_dir/python/v2."""
    if not os.fspath(cache_dir):
        raise ValueError("cache_dir is required")
    base, origin = _validate_base_url(base_url)
    seconds = _validate_timeout(timeout)
    deadline = asyncio.get_running_loop().time() + seconds
    cache = cache_directory(cache_dir)
    stop = threading.Event()
    await _wait_thread(stop, _create_cache, cache)
    lock = await _acquire_lock(cache / LOCK_FILE, deadline)
    try:
        async with asyncio.timeout_at(deadline):
            return await _refresh(Session(cache, base, origin, deadline, stop))
    finally:
        lock.release()
