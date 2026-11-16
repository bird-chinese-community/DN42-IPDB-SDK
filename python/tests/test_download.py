import asyncio
import json
import os
import stat
import sys
import threading
import time
from pathlib import Path

import pytest
from dn42_ipdb import (
    ARTIFACT_FILES,
    ChecksumMismatchError,
    HttpStatusError,
    InvalidBundleError,
    InvalidUrlError,
    LockTimeoutError,
    SizeLimitError,
    download_release,
    lookup,
    lookup_asn,
    open_cached_bundle,
    release_metadata,
)
from dn42_ipdb.download import _finish_thread, _retry_denied, _validate_base_url
from support import EXPECTED_VERSION, fixture_server, held_lock

REQUESTS_PER_DOWNLOAD = len(ARTIFACT_FILES) + 1


def download(tmp_path, url, **options):
    return asyncio.run(download_release(tmp_path, base_url=url, **options))


def revision_metadata(revision):
    return json.dumps(
        {
            "schema_version": "2",
            "release_repository": "test",
            "copyright": "BIRDCC",
            "revision": revision,
        }
    ).encode()


def stage_leftovers(cache):
    return [entry for entry in cache.iterdir() if entry.name.startswith((".s", ".c"))]


def test_download_into_empty_cache(tmp_path, server):
    url, state = server
    language = tmp_path / "python"
    language.mkdir()
    existing = language / "current.json"
    existing.write_text("existing cache layout")
    result = download(tmp_path, url)
    assert result["changed"] is True
    assert result["recovered_cache"] is False
    assert Path(result["directory"]) == language / "v2" / EXPECTED_VERSION
    assert existing.read_text() == "existing cache layout"
    assert len(state["requests"]) == REQUESTS_PER_DOWNLOAD
    assert lookup(result["bundle"], "172.20.0.1")["records"]["city"]
    assert lookup_asn(open_cached_bundle(tmp_path), 4242420001)["asn"] == 4242420001
    pointer = json.loads((language / "v2/current.json").read_text())
    assert pointer["version"] == EXPECTED_VERSION
    assert sorted(pointer["checksums"]) == sorted(ARTIFACT_FILES)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_download_permissions(tmp_path, server):
    url, _ = server
    result = download(tmp_path, url)
    cache = tmp_path / "python/v2"
    assert stat.S_IMODE(cache.stat().st_mode) == 0o700
    assert stat.S_IMODE(Path(result["directory"]).stat().st_mode) == 0o700
    for entry in [*Path(result["directory"]).iterdir(), cache / "current.json"]:
        assert stat.S_IMODE(entry.stat().st_mode) == 0o600


def test_download_reuse_and_local_cache(tmp_path, server):
    url, state = server
    first = download(tmp_path, url)
    second = download(tmp_path, url)
    assert second["changed"] is False
    assert second["recovered_cache"] is False
    assert second["directory"] == first["directory"]
    assert lookup_asn(second["bundle"], 4242420001) is not None
    assert len(state["requests"]) == REQUESTS_PER_DOWNLOAD + 1
    lookup(open_cached_bundle(tmp_path), "172.20.0.1")
    assert len(state["requests"]) == REQUESTS_PER_DOWNLOAD + 1


def test_download_follows_same_origin_redirects(tmp_path, server):
    url, state = server
    state["redirect_to_files"] = True
    assert download(tmp_path, url)["changed"] is True
    assert len(state["requests"]) == 2 * REQUESTS_PER_DOWNLOAD


def test_recover_corrupted_cached_file(tmp_path, server):
    url, _ = server
    first = download(tmp_path, url)
    target = Path(first["directory"]) / "DN42-IPDB-Country.mmdb"
    target.write_bytes(b"corrupt")
    second = download(tmp_path, url)
    assert second["changed"] is True
    assert second["recovered_cache"] is True
    assert Path(second["directory"]).name == EXPECTED_VERSION
    assert lookup_asn(open_cached_bundle(tmp_path), 4242420001) is not None


def test_recover_missing_cached_file(tmp_path, server):
    url, _ = server
    first = download(tmp_path, url)
    (Path(first["directory"]) / "metadata.json").unlink()
    second = download(tmp_path, url)
    assert second["recovered_cache"] is True
    assert "release_repository" in release_metadata(open_cached_bundle(tmp_path))


@pytest.mark.parametrize(
    "content", ["{", "[]", '{"version": "short", "checksums": {}}', "x" * 70000]
)
def test_recover_malformed_pointer(tmp_path, server, content):
    url, _ = server
    download(tmp_path, url)
    (tmp_path / "python/v2/current.json").write_text(content)
    result = download(tmp_path, url)
    assert result["changed"] is True
    assert result["recovered_cache"] is True
    assert lookup_asn(open_cached_bundle(tmp_path), 4242420001) is not None


def test_update_failures_preserve_pointer(tmp_path, server):
    url, state = server
    download(tmp_path, url)
    cache = tmp_path / "python/v2"
    original = (cache / "current.json").read_bytes()
    state["files"]["metadata.json"] = revision_metadata(1)
    state["failure"] = "DN42-IPDB-ASN.mmdb"
    with pytest.raises(HttpStatusError) as status:
        download(tmp_path, url)
    assert status.value.status == 503
    assert status.value.url.endswith("/DN42-IPDB-ASN.mmdb")
    assert (cache / "current.json").read_bytes() == original
    state["failure"] = ""
    state["files"]["DN42-IPDB-City.mmdb"] = state["files"]["DN42-IPDB-ASN.mmdb"]
    with pytest.raises(InvalidBundleError) as wrong_type:
        download(tmp_path, url)
    assert wrong_type.value.file == "DN42-IPDB-City.mmdb"
    assert (cache / "current.json").read_bytes() == original
    state["bad_checksum"] = True
    with pytest.raises(ChecksumMismatchError) as mismatch:
        download(tmp_path, url)
    assert mismatch.value.file == "DN42-IPDB-City.mmdb"
    assert (cache / "current.json").read_bytes() == original
    state["bad_manifest"] = True
    with pytest.raises(InvalidBundleError) as manifest:
        download(tmp_path, url)
    assert manifest.value.file == "checksums.json"
    assert (cache / "current.json").read_bytes() == original
    assert stage_leftovers(cache) == []
    assert [e.name for e in cache.iterdir() if len(e.name) == 64] == [EXPECTED_VERSION]
    assert lookup_asn(open_cached_bundle(tmp_path), 4242420001) is not None


@pytest.mark.parametrize("mode", ["", "chunked"])
def test_manifest_size_limit(tmp_path, server, mode):
    url, state = server
    state["oversize"] = mode or "length"
    with pytest.raises(SizeLimitError) as caught:
        download(tmp_path, url)
    assert caught.value.target.endswith("checksums.json")


def test_reject_insecure_redirect_before_request(tmp_path):
    with fixture_server() as (url, state), fixture_server() as (target, target_state):
        state["redirect"] = f"{target}checksums.json"
        with pytest.raises(InvalidUrlError):
            download(tmp_path, url)
        assert len(state["requests"]) == 1
        assert target_state["requests"] == []


@pytest.mark.parametrize(
    "location",
    [
        "https://@example.com/checksums.json",
        "//@example.com/checksums.json",
        "https://example.com/checksums.json#fragment",
        "/files/checksums.json#",
        "http://[::ffff:127.0.0.1]/checksums.json",
        "http://[bad/checksums.json",
    ],
)
def test_reject_invalid_redirect_locations(tmp_path, server, location):
    url, state = server
    state["redirect"] = location
    with pytest.raises(InvalidUrlError):
        download(tmp_path, url)
    assert len(state["requests"]) == 1


def test_reject_redirect_without_location(tmp_path, server):
    url, state = server
    state["redirect_without_location"] = True
    with pytest.raises(InvalidUrlError):
        download(tmp_path, url)
    assert len(state["requests"]) == 1


def test_redirect_may_carry_a_query(tmp_path, server):
    url, state = server
    state["redirect_to_files"] = True
    state["redirect_query"] = "token=1"
    assert download(tmp_path, url)["changed"] is True


def test_reject_credentials_and_redirect_loops(tmp_path, server):
    url, state = server
    state["redirect"] = "http://user:secret@127.0.0.1/checksums.json"
    with pytest.raises(InvalidUrlError):
        download(tmp_path, url)
    state["redirect"] = "/loop"
    with pytest.raises(InvalidUrlError):
        download(tmp_path, url)
    assert len(state["requests"]) == 1 + 11


@pytest.mark.parametrize(
    "url",
    [
        "https://user@example.com/",
        "https://user:pass@example.com/",
        "https://example.com/?token=1",
        "https://example.com/#fragment",
        "https://example.com/?",
        "https://example.com/#",
        "https://@example.com/",
        "http://@127.0.0.1/",
        "http://example.com/",
        "http://localhost/",
        "ftp://example.com/",
        "file:///tmp/",
        "https:///path/",
        "not a url",
        "http://127.0.0.1:bad/",
        "http://[::ffff:127.0.0.1]/",
        "http://[::ffff:7f00:1]/",
        "http://[::2]/",
        "http://127.0.0.1.example.com/",
    ],
)
def test_invalid_base_urls(tmp_path, url):
    with pytest.raises(InvalidUrlError):
        asyncio.run(download_release(tmp_path, base_url=url))
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    ("url", "normalized"),
    [
        ("http://127.0.0.2/", "http://127.0.0.2/"),
        ("http://127.0.0.1:8080", "http://127.0.0.1:8080/"),
        ("http://[::1]:8080/releases", "http://[::1]:8080/releases/"),
        ("https://example.com/a/b/", "https://example.com/a/b/"),
    ],
)
def test_accepted_base_urls(url, normalized):
    assert _validate_base_url(url)[0] == normalized


@pytest.mark.parametrize(
    "timeout",
    [0, -1, float("inf"), float("nan"), True, 1e10, 2_147_484],
)
def test_invalid_timeout(tmp_path, timeout):
    with pytest.raises(ValueError, match="timeout"):
        asyncio.run(
            download_release(tmp_path, base_url="http://127.0.0.1:9/", timeout=timeout)
        )
    assert list(tmp_path.iterdir()) == []


def test_largest_timeout_is_accepted(tmp_path, server):
    url, _ = server
    assert download(tmp_path, url, timeout=2_147_483)["changed"] is True


def test_download_with_ipv6_loopback_in_no_proxy(tmp_path, server, monkeypatch):
    monkeypatch.setenv("NO_PROXY", "::1")
    monkeypatch.setenv("no_proxy", "::1")
    url, _ = server
    assert download(tmp_path, url)["changed"] is True


def test_cancel_before_publication(tmp_path, server):
    url, state = server
    state["stall"] = True

    async def run():
        task = asyncio.create_task(download_release(tmp_path, base_url=url))
        await asyncio.sleep(0.3)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    started = time.monotonic()
    asyncio.run(run())
    assert time.monotonic() - started < 5
    cache = tmp_path / "python/v2"
    assert not (cache / "current.json").exists()
    assert stage_leftovers(cache) == []
    state["stall"] = False
    assert download(tmp_path, url)["changed"] is True


def test_timeout_is_not_a_lock_timeout(tmp_path, server):
    url, state = server
    state["stall"] = True
    with pytest.raises(TimeoutError) as caught:
        download(tmp_path, url, timeout=0.5)
    assert not isinstance(caught.value, LockTimeoutError)
    assert not (tmp_path / "python/v2/current.json").exists()


def test_retention_with_loaded_bundle(tmp_path, server):
    url, state = server
    first = download(tmp_path, url)
    cache = tmp_path / "python/v2"
    custom = cache / ("f" * 64)
    custom.mkdir()
    (custom / "user.txt").write_text("keep")
    database = open_cached_bundle(tmp_path)
    for revision in [1, 2, 3]:
        state["files"]["metadata.json"] = revision_metadata(revision)
        download(tmp_path, url)
    assert not Path(first["directory"]).exists()
    assert lookup(database, "172.20.0.1")["records"]["city"]["data"]["dn42"]
    assert (custom / "user.txt").read_text() == "keep"
    assert len([entry for entry in cache.iterdir() if len(entry.name) == 64]) == 3


def test_stale_stage_and_pending_entries_are_removed(tmp_path, server):
    url, _ = server
    cache = tmp_path / "python/v2"
    cache.mkdir(parents=True)
    (cache / ".stage-x").mkdir()
    (cache / ".stage-x" / "partial").write_text("partial")
    (cache / ".current-x").write_text("{}")
    unrelated = cache / "notes.txt"
    unrelated.write_text("keep")
    download(tmp_path, url)
    assert stage_leftovers(cache) == []
    assert unrelated.read_text() == "keep"


def test_writer_waits_for_the_lock(tmp_path, server):
    url, _ = server
    download(tmp_path, url)
    cache = tmp_path / "python/v2"
    with held_lock(cache) as release:
        timer = threading.Timer(0.4, release)
        timer.start()
        started = time.monotonic()
        result = download(tmp_path, url, timeout=10)
        waited = time.monotonic() - started
        timer.join()
    assert waited >= 0.3
    assert result["changed"] is False


def test_lock_timeout(tmp_path, server):
    url, state = server
    download(tmp_path, url)
    cache = tmp_path / "python/v2"
    requests = len(state["requests"])
    with held_lock(cache):
        with pytest.raises(LockTimeoutError) as caught:
            download(tmp_path, url, timeout=0.2)
        assert isinstance(caught.value, TimeoutError)
        lookup_asn(open_cached_bundle(tmp_path), 4242420001)
    assert len(state["requests"]) == requests


def test_concurrent_writers_serialize(tmp_path, server):
    url, _ = server

    async def run():
        return await asyncio.gather(
            *[download_release(tmp_path, base_url=url) for _ in range(3)]
        )

    results = asyncio.run(run())
    assert sorted(result["changed"] for result in results) == [False, False, True]
    assert {result["directory"] for result in results} == {
        str(tmp_path / "python/v2" / EXPECTED_VERSION)
    }


def test_download_replaces_files_held_open_by_readers(tmp_path, server):
    url, state = server
    first = download(tmp_path, url)
    state["files"]["metadata.json"] = revision_metadata(1)
    second = download(tmp_path, url)
    cache = tmp_path / "python/v2"
    state["files"]["metadata.json"] = revision_metadata(2)
    held = [
        (Path(first["directory"]) / "DN42-IPDB-Country.mmdb").open("rb"),
        (cache / "current.json").open("rb"),
    ]

    def release():
        for stream in held:
            stream.close()

    timer = threading.Timer(0.2, release)
    timer.start()
    try:
        third = download(tmp_path, url, timeout=10)
    finally:
        timer.join()
        release()
    assert third["changed"] is True
    assert not Path(first["directory"]).exists()
    assert Path(second["directory"]).exists()
    assert json.loads((cache / "current.json").read_text())["version"] == (
        Path(third["directory"]).name
    )
    assert lookup_asn(open_cached_bundle(tmp_path), 4242420001) is not None


def test_denied_operations_are_retried_on_windows(monkeypatch):
    monkeypatch.setattr("dn42_ipdb.download.WINDOWS", True)
    monkeypatch.setattr("dn42_ipdb.download.POLL_SECONDS", 0.01)
    attempts = []

    def operation():
        attempts.append(1)
        if len(attempts) < 3:
            raise PermissionError("access denied")
        return "done"

    assert _retry_denied(threading.Event(), operation) == "done"
    assert len(attempts) == 3


def test_denied_operations_stop_when_cancelled(monkeypatch):
    monkeypatch.setattr("dn42_ipdb.download.WINDOWS", True)
    stop = threading.Event()
    stop.set()

    def operation():
        raise PermissionError("access denied")

    with pytest.raises(PermissionError):
        _retry_denied(stop, operation)


def test_denied_operations_are_not_retried_elsewhere(monkeypatch):
    monkeypatch.setattr("dn42_ipdb.download.WINDOWS", False)
    attempts = []

    def operation():
        attempts.append(1)
        raise PermissionError("access denied")

    with pytest.raises(PermissionError):
        _retry_denied(threading.Event(), operation)
    assert len(attempts) == 1


def test_cancelled_publication_that_finished_returns_its_result():
    stop = threading.Event()

    def publish():
        time.sleep(0.2)
        return "published"

    async def run():
        task = asyncio.create_task(_finish_thread(stop, publish))
        await asyncio.sleep(0.05)
        task.cancel()
        return await task

    assert asyncio.run(run()) == "published"
    assert stop.is_set()


def test_cancelled_publication_that_failed_is_cancelled():
    stop = threading.Event()

    def publish():
        stop.wait(5)
        raise InterruptedError("cancelled before publication")

    async def run():
        task = asyncio.create_task(_finish_thread(stop, publish))
        await asyncio.sleep(0.05)
        task.cancel()
        await task

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(run())


def test_files_are_not_group_writable_after_umask(tmp_path, server):
    url, _ = server
    previous = os.umask(0)
    try:
        result = download(tmp_path, url)
    finally:
        os.umask(previous)
    if sys.platform != "win32":
        assert stat.S_IMODE(Path(result["directory"]).stat().st_mode) == 0o700
