import asyncio
import hashlib
import json
import subprocess
import sys
import threading
from contextlib import contextmanager
from pathlib import Path

import httpx
import pytest
from aiohttp import web
from dn42_ipdb import (
    ARTIFACT_FILES,
    download_release,
    lookup,
    lookup_asn,
    metadata,
    open_bundle,
    open_cached_bundle,
    release_metadata,
)
from filelock import Timeout

FIXTURES = Path(__file__).with_name("data")


@contextmanager
def fixture_server():
    files = {name: (FIXTURES / name).read_bytes() for name in ARTIFACT_FILES}
    state = {
        "files": files,
        "requests": [],
        "failure": "",
        "stall": False,
        "bad_manifest": False,
        "bad_checksum": False,
        "redirect": "",
    }
    loop = asyncio.new_event_loop()

    async def handle(request):
        name = request.match_info["name"]
        state["requests"].append(name)
        if state["redirect"]:
            raise web.HTTPFound(state["redirect"])
        if name == state["failure"]:
            return web.Response(status=503)
        if name == "checksums.json":
            checksums = (
                {}
                if state["bad_manifest"]
                else {
                    name: hashlib.sha256(data).hexdigest()
                    for name, data in files.items()
                }
            )
            if state["bad_checksum"]:
                checksums["city.mmdb"] = "0" * 64
            return web.json_response(checksums)
        if state["stall"] and name == "city.mmdb":
            await asyncio.sleep(10)
        data = files.get(name)
        return web.Response(body=data) if data is not None else web.Response(status=404)

    async def start():
        app = web.Application()
        app.router.add_get("/{name}", handle)
        runner = web.AppRunner(app, shutdown_timeout=0.1)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        return runner

    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    runner = asyncio.run_coroutine_threadsafe(start(), loop).result(5)
    address = runner.addresses[0]
    try:
        yield f"http://127.0.0.1:{address[1]}/", state
    finally:
        asyncio.run_coroutine_threadsafe(runner.cleanup(), loop).result(5)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(5)
        loop.close()


def test_local_lookup():
    with open_bundle(FIXTURES) as database:
        for address in ["172.20.0.1", "fd42:1234::1"]:
            result = lookup(database, address)
            assert (
                result["records"]["asn"]["data"]["autonomous_system_number"]
                == 4242420001
            )
            assert (
                result["records"]["city"]["data"]["country"]["names"]["en"]
                == "United States"
            )
            assert result["records"]["city"]["data"]["dn42"]["schema_version"] == "2"
        assert lookup_asn(database, 4242420001)["asn"] == 4242420001
        assert lookup_asn(database, 4242420999) is None
        assert lookup(database, "203.0.113.1")["records"] == {}
        with pytest.raises(ValueError):
            lookup(database, "bad-ip")
        with pytest.raises(ValueError):
            lookup_asn(database, -1)
        assert len(metadata(database)) == 4
        assert "DN42-IPDB-Releases" in release_metadata(database)["release_repository"]


def test_download_reuse_and_local_cache(tmp_path):
    with fixture_server() as (url, state):
        first = asyncio.run(download_release(tmp_path, base_url=url))
        assert first["changed"] is True
        assert len(state["requests"]) == 8
        second = asyncio.run(download_release(tmp_path, base_url=url))
        assert second == {"directory": first["directory"], "changed": False}
        assert len(state["requests"]) == 9
        with open_cached_bundle(tmp_path) as database:
            assert lookup_asn(database, 4242420001)["asn"] == 4242420001
            lookup(database, "172.20.0.1")
        assert len(state["requests"]) == 9


def test_reject_insecure_redirect_before_request(tmp_path):
    with fixture_server() as (url, state), fixture_server() as (target, target_state):
        state["redirect"] = f"{target}checksums.json"
        with pytest.raises(ValueError, match="Insecure release redirect"):
            asyncio.run(download_release(tmp_path, base_url=url))
        assert len(state["requests"]) == 1
        assert target_state["requests"] == []


def test_update_failures_preserve_pointer(tmp_path):
    with fixture_server() as (url, state):
        asyncio.run(download_release(tmp_path, base_url=url))
        pointer = tmp_path / "python/current.json"
        original = pointer.read_bytes()
        state["files"]["metadata.json"] = json.dumps(
            {
                "schema_version": "2",
                "release_repository": "test",
                "copyright": "BIRDCC",
                "revision": 1,
            }
        ).encode()
        state["failure"] = "asn.mmdb"
        with pytest.raises(httpx.HTTPStatusError, match="503"):
            asyncio.run(download_release(tmp_path, base_url=url))
        assert pointer.read_bytes() == original
        state["failure"] = ""
        state["files"]["city.mmdb"] = state["files"]["asn.mmdb"]
        with pytest.raises(ValueError, match="expected.*City"):
            asyncio.run(download_release(tmp_path, base_url=url))
        assert pointer.read_bytes() == original
        state["bad_checksum"] = True
        with pytest.raises(ValueError, match="Checksum mismatch"):
            asyncio.run(download_release(tmp_path, base_url=url))
        assert pointer.read_bytes() == original
        state["bad_manifest"] = True
        with pytest.raises(ValueError, match="Invalid checksum"):
            asyncio.run(download_release(tmp_path, base_url=url))
        assert pointer.read_bytes() == original
        with open_cached_bundle(tmp_path) as database:
            assert lookup_asn(database, 4242420001)["asn"] == 4242420001


def test_cancel_before_publication(tmp_path):
    with fixture_server() as (url, state):
        state["stall"] = True

        async def run():
            task = asyncio.create_task(download_release(tmp_path, base_url=url))
            await asyncio.sleep(0.1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        asyncio.run(run())
        assert not (tmp_path / "python/current.json").exists()


def test_retention_with_loaded_reader(tmp_path):
    with fixture_server() as (url, state):
        first = asyncio.run(download_release(tmp_path, base_url=url))
        custom = tmp_path / "python" / ("f" * 64)
        custom.mkdir()
        (custom / "user.txt").write_text("keep")
        with open_cached_bundle(tmp_path) as database:
            for revision in [1, 2, 3]:
                state["files"]["metadata.json"] = json.dumps(
                    {
                        "schema_version": "2",
                        "release_repository": "test",
                        "copyright": "BIRDCC",
                        "revision": revision,
                    }
                ).encode()
                asyncio.run(download_release(tmp_path, base_url=url))
            assert not Path(first["directory"]).exists()
            assert (
                lookup(database, "172.20.0.1")["records"]["city"]["data"]["dn42"][
                    "schema_version"
                ]
                == "2"
            )
            assert lookup_asn(database, 4242420001)["asn"] == 4242420001
        assert (custom / "user.txt").read_text() == "keep"
        assert (
            len(
                [
                    entry
                    for entry in (tmp_path / "python").iterdir()
                    if len(entry.name) == 64
                ]
            )
            == 3
        )


def test_cross_process_lock(tmp_path):
    with fixture_server() as (url, _):
        asyncio.run(download_release(tmp_path, base_url=url))
        child = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).with_name("hold_lock.py")),
                str(tmp_path / "python"),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            assert child.stdout.readline() == "locked\n"
            with pytest.raises(Timeout), open_cached_bundle(tmp_path):
                pass
            with pytest.raises(TimeoutError):
                asyncio.run(download_release(tmp_path, base_url=url, timeout=0.1))
        finally:
            child.communicate("x", timeout=5)
        assert child.returncode == 0


def test_recover_malformed_pointer(tmp_path):
    with fixture_server() as (url, _):
        asyncio.run(download_release(tmp_path, base_url=url))
        (tmp_path / "python/current.json").write_text("{")
        result = asyncio.run(download_release(tmp_path, base_url=url))
        assert result["changed"] is True
        assert result["recovered_cache"] is True
        with open_cached_bundle(tmp_path) as database:
            assert lookup_asn(database, 4242420001)["asn"] == 4242420001
