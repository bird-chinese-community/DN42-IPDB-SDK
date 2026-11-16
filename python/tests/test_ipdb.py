import asyncio
import json
import shutil
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from dn42_ipdb import (
    ARTIFACT_FILES,
    CacheMissingError,
    ChecksumMismatchError,
    Dn42IpdbError,
    InvalidAddressError,
    InvalidAsnError,
    InvalidBundleError,
    SizeLimitError,
    asns,
    download_release,
    lookup,
    lookup_asn,
    metadata,
    open_bundle,
    open_cached_bundle,
    release_metadata,
)
from dn42_ipdb.cache import open_current, read_verified
from support import EXPECTED_VERSION, FIXTURES


def copy_bundle(tmp_path: Path) -> Path:
    directory = tmp_path / "bundle"
    shutil.copytree(FIXTURES, directory)
    return directory


def edit_json(path: Path, change) -> None:
    document = json.loads(path.read_text())
    change(document)
    path.write_text(json.dumps(document))


def test_local_lookup():
    database = open_bundle(FIXTURES)
    for address in ["172.20.0.1", "fd42:1234::1"]:
        result = lookup(database, address)
        assert (
            result["records"]["asn"]["data"]["autonomous_system_number"] == 4242420001
        )
        assert (
            result["records"]["city"]["data"]["country"]["names"]["en"]
            == "United States"
        )
        assert result["records"]["city"]["data"]["dn42"]["schema_version"] == "2"
    assert lookup_asn(database, 4242420001)["asn"] == 4242420001
    assert lookup_asn(database, 4242420999) is None
    assert lookup(database, "203.0.113.1")["records"] == {}
    assert len(metadata(database)) == 4
    assert "DN42-IPDB-Releases" in release_metadata(database)["release_repository"]


@pytest.mark.parametrize(
    ("address", "ip", "network", "prefix_length"),
    [
        ("172.20.0.1", "172.20.0.1", "172.20.0.1/32", 32),
        ("::ffff:172.20.0.1", "172.20.0.1", "172.20.0.1/32", 32),
        ("::FFFF:AC14:1", "172.20.0.1", "172.20.0.1/32", 32),
        ("fd42:1234::1", "fd42:1234::1", "fd42:1234::1/128", 128),
        ("FD42:1234:0:0:0:0:0:1", "fd42:1234::1", "fd42:1234::1/128", 128),
    ],
)
def test_lookup_canonical_address_and_network(address, ip, network, prefix_length):
    result = lookup(open_bundle(FIXTURES), address)
    assert result["ip"] == ip
    for match in result["records"].values():
        assert match["network"] == network
        assert match["prefix_length"] == prefix_length
    assert set(result["records"]) == {"country", "city", "asn", "connection_type"}


@pytest.mark.parametrize(
    "address", ["bad-ip", "", "172.20.0.1%eth0", "fe80::1%eth0", "172.20.0", None, 5]
)
def test_lookup_rejects_invalid_address(address):
    with pytest.raises(InvalidAddressError) as caught:
        lookup(open_bundle(FIXTURES), address)
    assert isinstance(caught.value, ValueError)
    assert isinstance(caught.value, Dn42IpdbError)


@pytest.mark.parametrize("asn", [-1, 4294967296, True, 1.0, "4242420001", None])
def test_lookup_asn_rejects_invalid_asn(asn):
    with pytest.raises(InvalidAsnError):
        lookup_asn(open_bundle(FIXTURES), asn)


def test_asns_are_ordered(tmp_path):
    directory = copy_bundle(tmp_path)

    def add(document):
        template = document["asns"]["4242420001"]
        for asn in (4242420003, 4242420002):
            document["asns"][str(asn)] = {**template, "asn": asn}

    edit_json(directory / "asn-index.json", add)
    records = asns(open_bundle(directory))
    assert [record["asn"] for record in records] == [
        4242420001,
        4242420002,
        4242420003,
    ]
    assert [record["asn"] for record in asns(open_bundle(FIXTURES))] == [4242420001]


def test_release_metadata_typed_field(tmp_path):
    directory = copy_bundle(tmp_path)
    window = {"first": "2026-11-15T07:43:11Z", "last": "2026-11-15T10:59:05Z"}
    edit_json(
        directory / "metadata.json",
        lambda doc: doc.update(release_tag="v9", route_observed_at=window),
    )
    release = release_metadata(open_bundle(directory))
    assert release["release_tag"] == "v9"
    assert release["route_observed_at"] == window
    assert release["schema_version"] == "2"
    assert "release_tag" not in release_metadata(open_bundle(FIXTURES))


def break_schema(document):
    document["schema_version"] = "1"


def break_database_types(document):
    document["database_types"]["DN42-IPDB-City.mmdb"] = "DN42-GeoIP2-Country"


def break_asn_key(document):
    document["asns"]["4242420002"] = document["asns"].pop("4242420001")


def break_asn_info(document):
    del document["asns"]["4242420001"]["prefixes"]


def break_observation(document):
    document["asns"]["4242420001"]["observations"] = [{"target": "x"}]


def break_repository(document):
    document["release_repository"] = ""


def null_as_name(document):
    document["asns"]["4242420001"]["as_name"] = None


def null_observation_asn(document):
    document["asns"]["4242420001"]["observations"][0]["asn"] = None


def null_observation_value(document):
    document["asns"]["4242420001"]["observations"][1]["value"] = None


def null_metadata_field(key):
    def change(document):
        document[key] = None

    return change


@pytest.mark.parametrize(
    ("file", "change"),
    [
        ("metadata.json", break_schema),
        ("metadata.json", break_database_types),
        ("metadata.json", break_repository),
        ("asn-index.json", break_asn_key),
        ("asn-index.json", break_asn_info),
        ("asn-index.json", break_observation),
        ("asn-index.json", null_as_name),
        ("asn-index.json", null_observation_asn),
        ("asn-index.json", null_observation_value),
        *[
            ("metadata.json", null_metadata_field(key))
            for key in (
                "release_tag",
                "release_url",
                "built_at",
                "registry_commit",
                "registry_committed_at",
                "route_observed_at",
                "database_types",
            )
        ],
    ],
)
def test_invalid_json_sidecars(tmp_path, file, change):
    directory = copy_bundle(tmp_path)
    edit_json(directory / file, change)
    with pytest.raises(InvalidBundleError) as caught:
        open_bundle(directory)
    assert caught.value.file == file


def test_invalid_bundle_files(tmp_path):
    directory = copy_bundle(tmp_path)
    (directory / "LICENSE-Unicode.txt").unlink()
    with pytest.raises(InvalidBundleError) as missing:
        open_bundle(directory)
    assert missing.value.file == "LICENSE-Unicode.txt"
    directory = copy_bundle(tmp_path / "other")
    (directory / "DN42-IPDB-City.mmdb").write_bytes(b"not a database")
    with pytest.raises(InvalidBundleError) as garbage:
        open_bundle(directory)
    assert garbage.value.file == "DN42-IPDB-City.mmdb"
    shutil.copy(directory / "DN42-IPDB-ASN.mmdb", directory / "DN42-IPDB-City.mmdb")
    with pytest.raises(InvalidBundleError) as wrong_type:
        open_bundle(directory)
    assert wrong_type.value.file == "DN42-IPDB-City.mmdb"
    (directory / "metadata.json").write_text("{")
    with pytest.raises(InvalidBundleError):
        open_bundle(directory)


def test_size_limit_and_special_files(tmp_path):
    directory = copy_bundle(tmp_path)
    (directory / "metadata.json").write_bytes(b" " * (1024 * 1024 + 1))
    with pytest.raises(SizeLimitError):
        open_bundle(directory)
    (directory / "metadata.json").unlink()
    (directory / "metadata.json").mkdir()
    with pytest.raises(InvalidBundleError):
        open_bundle(directory)


def test_download_then_open_cached(tmp_path, server):
    url, _ = server
    result = asyncio.run(download_release(tmp_path, base_url=url))
    assert Path(result["directory"]).name == EXPECTED_VERSION
    database = open_cached_bundle(tmp_path)
    assert lookup_asn(database, 4242420001)["asn"] == 4242420001
    assert {path.name for path in Path(result["directory"]).iterdir()} == set(
        ARTIFACT_FILES
    )


def test_cache_missing(tmp_path):
    with pytest.raises(CacheMissingError) as caught:
        open_cached_bundle(tmp_path)
    assert isinstance(caught.value, FileNotFoundError)
    assert "current.json" in str(caught.value)


def test_open_cached_accepts_any_hex_version(tmp_path, server):
    url, _ = server
    result = asyncio.run(download_release(tmp_path, base_url=url))
    cache = tmp_path / "python/v2"
    old = "b" * 64
    Path(result["directory"]).rename(cache / old)
    edit_json(cache / "current.json", lambda doc: doc.update(version=old))
    assert lookup_asn(open_cached_bundle(tmp_path), 4242420001) is not None


def test_concurrent_open_cached(tmp_path, server):
    url, _ = server
    asyncio.run(download_release(tmp_path, base_url=url))
    with ThreadPoolExecutor(4) as pool:
        bundles = list(pool.map(lambda _: open_cached_bundle(tmp_path), range(8)))
    assert all(lookup_asn(item, 4242420001) for item in bundles)


def test_open_cached_checksum_mismatch(tmp_path, server):
    url, _ = server
    result = asyncio.run(download_release(tmp_path, base_url=url))
    target = Path(result["directory"]) / "DN42-IPDB-City.mmdb"
    target.write_bytes(target.read_bytes() + b"x")
    with pytest.raises(ChecksumMismatchError) as caught:
        open_cached_bundle(tmp_path)
    assert caught.value.file == "DN42-IPDB-City.mmdb"
    assert isinstance(caught.value, InvalidBundleError)
    target.unlink()
    with pytest.raises(InvalidBundleError) as missing:
        open_cached_bundle(tmp_path)
    assert missing.value.file == "DN42-IPDB-City.mmdb"
    assert isinstance(missing.value.__cause__, FileNotFoundError)
    assert not isinstance(missing.value, CacheMissingError)


def test_open_cached_missing_version_directory(tmp_path, server):
    url, _ = server
    result = asyncio.run(download_release(tmp_path, base_url=url))
    shutil.rmtree(result["directory"])
    with pytest.raises(InvalidBundleError) as missing:
        open_cached_bundle(tmp_path)
    assert isinstance(missing.value.__cause__, FileNotFoundError)


@pytest.mark.parametrize(
    "checksums", [{}, {name: "xyz" for name in ARTIFACT_FILES}], ids=["empty", "short"]
)
def test_invalid_pointer_checksums_name_the_pointer(tmp_path, server, checksums):
    url, _ = server
    asyncio.run(download_release(tmp_path, base_url=url))
    cache = tmp_path / "python/v2"
    edit_json(cache / "current.json", lambda doc: doc.update(checksums=checksums))
    with pytest.raises(InvalidBundleError) as caught:
        open_cached_bundle(tmp_path)
    assert caught.value.file == "current.json"
    assert not isinstance(caught.value, CacheMissingError)


def test_open_cached_retries_when_pointer_moves(tmp_path, server):
    url, _ = server
    result = asyncio.run(download_release(tmp_path, base_url=url))
    cache = tmp_path / "python/v2"
    good = (cache / "current.json").read_text()
    missing = json.loads(good)
    missing["version"] = "a" * 64
    (cache / "current.json").write_text(json.dumps(missing))
    attempts = []

    def read(directory, checksums):
        attempts.append(directory.name)
        if len(attempts) == 1:
            (cache / "current.json").write_text(good)
        return read_verified(directory, checksums)

    database = open_current(cache, read)
    assert attempts == ["a" * 64, Path(result["directory"]).name]
    assert lookup_asn(database, 4242420001) is not None


def test_open_cached_gives_up_without_a_moved_pointer(tmp_path, server):
    url, _ = server
    asyncio.run(download_release(tmp_path, base_url=url))
    cache = tmp_path / "python/v2"
    pointer = json.loads((cache / "current.json").read_text())
    pointer["version"] = "a" * 64
    (cache / "current.json").write_text(json.dumps(pointer))
    attempts = []

    def read(directory, checksums):
        attempts.append(directory.name)
        return read_verified(directory, checksums)

    with pytest.raises(InvalidBundleError) as caught:
        open_current(cache, read)
    assert isinstance(caught.value.__cause__, FileNotFoundError)
    assert len(attempts) == 1


def test_open_cached_does_not_retry_other_invalid_bundles(tmp_path, server):
    url, _ = server
    asyncio.run(download_release(tmp_path, base_url=url))
    cache = tmp_path / "python/v2"
    attempts = []

    def read(directory, checksums):
        attempts.append(directory.name)
        edit_json(cache / "current.json", lambda doc: doc.update(version="c" * 64))
        raise InvalidBundleError("metadata.json", "broken")

    with pytest.raises(InvalidBundleError) as caught:
        open_current(cache, read)
    assert caught.value.file == "metadata.json"
    assert len(attempts) == 1


def test_open_cached_stops_after_three_attempts(tmp_path, server):
    url, _ = server
    asyncio.run(download_release(tmp_path, base_url=url))
    cache = tmp_path / "python/v2"
    pointer = json.loads((cache / "current.json").read_text())
    pointer["version"] = "9" * 64
    (cache / "current.json").write_text(json.dumps(pointer))
    attempts = []

    def read(directory, checksums):
        attempts.append(directory.name)
        pointer["version"] = chr(ord("a") + len(attempts)) * 64
        (cache / "current.json").write_text(json.dumps(pointer))
        return read_verified(directory, checksums)

    with pytest.raises(InvalidBundleError) as caught:
        open_current(cache, read)
    assert isinstance(caught.value.__cause__, FileNotFoundError)
    assert len(attempts) == 3
