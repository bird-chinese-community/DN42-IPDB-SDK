import asyncio
import contextlib
import hashlib
import subprocess
import sys
import threading
from contextlib import contextmanager
from pathlib import Path

from aiohttp import web
from dn42_ipdb import ARTIFACT_FILES, MAX_MANIFEST_BYTES

FIXTURES = Path(__file__).with_name("data")
EXPECTED_VERSION = "ac95640bbd1d1c9d3f75239dbf7fd242b0c5f8fb5aa5332480220c904a22c157"


def new_state():
    return {
        "files": {name: (FIXTURES / name).read_bytes() for name in ARTIFACT_FILES},
        "requests": [],
        "failure": "",
        "stall": False,
        "bad_manifest": False,
        "bad_checksum": False,
        "redirect": "",
        "redirect_without_location": False,
        "redirect_to_files": False,
        "redirect_query": "",
        "oversize": "",
    }


def manifest_response(state):
    checksums = (
        {}
        if state["bad_manifest"]
        else {
            name: hashlib.sha256(data).hexdigest()
            for name, data in state["files"].items()
        }
    )
    if state["bad_checksum"]:
        checksums["DN42-IPDB-City.mmdb"] = "0" * 64
    return web.json_response(checksums)


async def oversize_response(request, state):
    if state["oversize"] == "chunked":
        response = web.StreamResponse()
        await response.prepare(request)
        await response.write(b"x" * (MAX_MANIFEST_BYTES + 1))
        return response
    return web.Response(body=b"x" * (MAX_MANIFEST_BYTES + 1))


@contextmanager
def fixture_server():
    state = new_state()
    loop = asyncio.new_event_loop()
    unstall = asyncio.Event()

    async def handle(request):
        name = request.match_info["name"]
        state["requests"].append(name)
        if state["redirect_without_location"]:
            return web.Response(status=302)
        if state["redirect"]:
            return web.Response(status=302, headers={"Location": state["redirect"]})
        if state["redirect_to_files"] and not request.path.startswith("/files/"):
            query = f"?{state['redirect_query']}" if state["redirect_query"] else ""
            raise web.HTTPFound(f"/files/{name}{query}")
        if name == state["failure"]:
            return web.Response(status=503)
        if name == "checksums.json":
            if state["oversize"]:
                return await oversize_response(request, state)
            return manifest_response(state)
        if state["stall"] and name == "DN42-IPDB-City.mmdb":
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(unstall.wait(), 10)
        data = state["files"].get(name)
        return web.Response(body=data) if data is not None else web.Response(status=404)

    async def start():
        app = web.Application()
        app.router.add_get("/files/{name}", handle)
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
        loop.call_soon_threadsafe(unstall.set)
        asyncio.run_coroutine_threadsafe(runner.cleanup(), loop).result(5)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(5)
        loop.close()


@contextmanager
def held_lock(cache):
    """Hold the writer lock in another process; yield a function that frees it."""
    child = subprocess.Popen(
        [sys.executable, str(Path(__file__).with_name("hold_lock.py")), str(cache)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout.readline() == "locked\n"

        def release():
            child.stdin.write("x")
            child.stdin.flush()

        yield release
    finally:
        child.communicate("x", timeout=5)
    assert child.returncode == 0
