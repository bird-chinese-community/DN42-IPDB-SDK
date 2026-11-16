"""Release bundle layout, validation, in-memory readers and lookups."""

import ipaddress
import json
import os
import re
import stat
from io import BytesIO
from pathlib import Path
from typing import Any, NamedTuple, NotRequired, TypedDict, cast

import maxminddb

from .errors import (
    InvalidAddressError,
    InvalidAsnError,
    InvalidBundleError,
    SizeLimitError,
)

MAX_DATABASE_BYTES = 32 * 1024 * 1024
MAX_METADATA_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
MAX_ASN = 4294967295
SCHEMA_VERSION = "2"
DIGEST = re.compile(r"^[0-9a-f]{64}$")

INDEX_FILE = "asn-index.json"
METADATA_FILE = "metadata.json"
LICENSE_FILE = "LICENSE-Unicode.txt"
ARTIFACT_TYPES = {
    "country": ("DN42-IPDB-Country.mmdb", "DN42-GeoIP2-Country"),
    "city": ("DN42-IPDB-City.mmdb", "DN42-GeoIP2-City"),
    "asn": ("DN42-IPDB-ASN.mmdb", "DN42-GeoLite2-ASN"),
    "connection_type": (
        "DN42-IPDB-Connection-Type.mmdb",
        "DN42-GeoIP2-Connection-Type",
    ),
}
ARTIFACT_FILES = [file for file, _ in ARTIFACT_TYPES.values()] + [
    INDEX_FILE,
    METADATA_FILE,
    LICENSE_FILE,
]
_SMALL_FILES = {METADATA_FILE, LICENSE_FILE}

Observation = TypedDict(
    "Observation",
    {
        "target": str,
        "asn": NotRequired[int],
        "kind": str,
        "value": NotRequired[str],
        "status": str,
        "method": str,
        "source": str,
        "authority": str,
        "observed_at": str,
    },
)
RegisteredCountry = TypedDict(
    "RegisteredCountry", {"iso_code": str, "names": dict[str, str]}
)
AsnInfo = TypedDict(
    "AsnInfo",
    {
        "asn": int,
        "as_name": NotRequired[str],
        "registered_countries": list[RegisteredCountry],
        "prefixes": list[str],
        "observed_network_types": list[str],
        "observations": list[Observation],
    },
)
RouteWindow = TypedDict("RouteWindow", {"first": str, "last": str})
ReleaseMetadata = TypedDict(
    "ReleaseMetadata",
    {
        "schema_version": str,
        "release_repository": str,
        "copyright": str,
        "release_tag": NotRequired[str],
        "release_url": NotRequired[str],
        "built_at": NotRequired[str],
        "registry_commit": NotRequired[str],
        "registry_committed_at": NotRequired[str],
        "route_observed_at": NotRequired[RouteWindow],
        "database_types": NotRequired[dict[str, str]],
    },
)
Match = TypedDict(
    "Match", {"network": str, "prefix_length": int, "data": dict[str, Any]}
)
LookupResult = TypedDict("LookupResult", {"ip": str, "records": dict[str, Match]})
DatabaseMetadata = TypedDict(
    "DatabaseMetadata",
    {
        "database_type": str,
        "description": dict[str, str],
        "build_epoch": int,
        "languages": list[str],
        "ip_version": int,
    },
)
Bundle = NamedTuple(  # noqa: UP014 (functional form is the project style)
    "Bundle",
    [
        ("readers", dict[str, maxminddb.Reader]),
        ("asns", dict[str, AsnInfo]),
        ("release", ReleaseMetadata),
    ],
)

_RELEASE_OPTIONAL_STRINGS = (
    "release_tag",
    "release_url",
    "built_at",
    "registry_commit",
    "registry_committed_at",
)
_OBSERVATION_STRINGS = (
    "target",
    "kind",
    "status",
    "method",
    "source",
    "authority",
    "observed_at",
)


def file_limit(name: str) -> int:
    return MAX_METADATA_BYTES if name in _SMALL_FILES else MAX_DATABASE_BYTES


def read_file(path: Path, limit: int) -> bytes:
    """Read one regular file, enforcing the size limit while reading."""
    if path.is_dir():
        raise InvalidBundleError(str(path), "not a regular file")
    with path.open("rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise InvalidBundleError(str(path), "not a regular file")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise SizeLimitError(str(path), limit)
    return data


def read_release_file(directory: Path, name: str) -> bytes:
    """Read one release file; a missing file is an invalid bundle."""
    try:
        return read_file(directory / name, file_limit(name))
    except FileNotFoundError as error:
        raise InvalidBundleError(name, "file is missing") from error


def read_bundle_files(directory: Path) -> dict[str, bytes]:
    """Read each of the seven files once."""
    return {name: read_release_file(directory, name) for name in ARTIFACT_FILES}


def _require(condition: bool, file: str, reason: str) -> None:
    if not condition:
        raise InvalidBundleError(file, reason)


def load_json(data: bytes, file: str) -> Any:
    try:
        return json.loads(data)
    except ValueError as error:
        raise InvalidBundleError(file, "not valid JSON") from error


def _is_uint32(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and (0 <= value <= MAX_ASN)
    )


def _is_route_window(value: Any) -> bool:
    return isinstance(value, dict) and all(
        isinstance(value.get(key), str) for key in ("first", "last")
    )


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _check_observation(item: Any, where: str) -> None:
    _require(isinstance(item, dict), INDEX_FILE, f"{where} must be an object")
    for key in _OBSERVATION_STRINGS:
        _require(
            isinstance(item.get(key), str),
            INDEX_FILE,
            f"{where}.{key} must be a string",
        )
    _require(
        "asn" not in item or _is_uint32(item["asn"]),
        INDEX_FILE,
        f"{where}.asn must be a uint32",
    )
    _require(
        "value" not in item or isinstance(item["value"], str),
        INDEX_FILE,
        f"{where}.value must be a string",
    )


def _check_country(item: Any, where: str) -> None:
    _require(isinstance(item, dict), INDEX_FILE, f"{where} must be an object")
    _require(
        isinstance(item.get("iso_code"), str), INDEX_FILE, f"{where}.iso_code invalid"
    )
    names = item.get("names")
    _require(
        isinstance(names, dict)
        and all(isinstance(k, str) and isinstance(v, str) for k, v in names.items()),
        INDEX_FILE,
        f"{where}.names must map strings to strings",
    )


def _check_asn_info(key: str, info: Any) -> None:
    where = f"asns[{key}]"
    _require(isinstance(info, dict), INDEX_FILE, f"{where} must be an object")
    _require(
        _is_uint32(info.get("asn")) and key == str(info["asn"]),
        INDEX_FILE,
        f"{where} key does not match its asn",
    )
    _require(
        "as_name" not in info or isinstance(info["as_name"], str),
        INDEX_FILE,
        f"{where}.as_name must be a string",
    )
    for field in ("prefixes", "observed_network_types"):
        _require(
            _is_string_list(info.get(field)),
            INDEX_FILE,
            f"{where}.{field} must be a string list",
        )
    for field, check in (
        ("registered_countries", _check_country),
        ("observations", _check_observation),
    ):
        items = info.get(field)
        _require(isinstance(items, list), INDEX_FILE, f"{where}.{field} must be a list")
        for position, item in enumerate(items):
            check(item, f"{where}.{field}[{position}]")


def _parse_index(data: bytes) -> dict[str, AsnInfo]:
    index = load_json(data, INDEX_FILE)
    _require(isinstance(index, dict), INDEX_FILE, "must be an object")
    _require(
        index.get("schema_version") == SCHEMA_VERSION,
        INDEX_FILE,
        f"schema_version must be {SCHEMA_VERSION!r}",
    )
    asns = index.get("asns")
    _require(isinstance(asns, dict), INDEX_FILE, "asns must be an object")
    for key, info in asns.items():
        _check_asn_info(key, info)
    return cast(dict[str, AsnInfo], asns)


def _parse_release(data: bytes) -> ReleaseMetadata:
    release = load_json(data, METADATA_FILE)
    _require(isinstance(release, dict), METADATA_FILE, "must be an object")
    _require(
        release.get("schema_version") == SCHEMA_VERSION,
        METADATA_FILE,
        f"schema_version must be {SCHEMA_VERSION!r}",
    )
    for key in ("release_repository", "copyright"):
        value = release.get(key)
        _require(
            isinstance(value, str) and value != "",
            METADATA_FILE,
            f"{key} must be a non-empty string",
        )
    for key in _RELEASE_OPTIONAL_STRINGS:
        _require(
            key not in release or isinstance(release[key], str),
            METADATA_FILE,
            f"{key} must be a string",
        )
    _require(
        "route_observed_at" not in release
        or _is_route_window(release["route_observed_at"]),
        METADATA_FILE,
        "route_observed_at must hold first and last strings",
    )
    declared = release.get("database_types", {})
    _require(
        isinstance(declared, dict)
        and all(isinstance(value, str) for value in declared.values()),
        METADATA_FILE,
        "database_types must map files to strings",
    )
    return cast(ReleaseMetadata, release)


def _open_reader(file: str, expected: str, data: bytes) -> maxminddb.Reader:
    try:
        reader = maxminddb.open_database(BytesIO(data), mode=maxminddb.MODE_FD)
    except maxminddb.InvalidDatabaseError as error:
        raise InvalidBundleError(file, "not a MaxMind database") from error
    actual = reader.metadata().database_type
    _require(
        actual == expected, file, f"database_type is {actual}, expected {expected}"
    )
    return reader


def build_bundle(files: dict[str, bytes]) -> Bundle:
    """Validate the seven files and keep them in memory."""
    release = _parse_release(files[METADATA_FILE])
    asns = _parse_index(files[INDEX_FILE])
    declared = release.get("database_types", {})
    readers = {}
    for key, (file, expected) in ARTIFACT_TYPES.items():
        readers[key] = _open_reader(file, expected, files[file])
        _require(
            declared.get(file, expected) == expected,
            METADATA_FILE,
            f"database_types lists {declared.get(file)} for {file}",
        )
    return Bundle(readers, asns, release)


def open_bundle(directory: str | Path) -> Bundle:
    """Load an immutable in-memory release for local lookups."""
    return build_bundle(read_bundle_files(Path(directory)))


def _parse_address(address: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not isinstance(address, str) or "%" in address:
        raise InvalidAddressError(f"invalid IP address: {address!r}")
    try:
        ip = ipaddress.ip_address(address)
    except ValueError as error:
        raise InvalidAddressError(f"invalid IP address: {address!r}") from error
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def lookup(bundle: Bundle, address: str) -> LookupResult:
    """Return raw GeoIP2-compatible records, preserving the dn42 extension."""
    ip = _parse_address(address)
    records: dict[str, Match] = {}
    for key, reader in bundle.readers.items():
        data, prefix_length = reader.get_with_prefix_len(str(ip))
        if not data:
            continue
        if not isinstance(data, dict):
            raise InvalidBundleError(ARTIFACT_TYPES[key][0], "record is not a map")
        network = ipaddress.ip_network(f"{ip}/{prefix_length}", strict=False)
        records[key] = {
            "network": str(network),
            "prefix_length": prefix_length,
            "data": data,
        }
    return {"ip": str(ip), "records": records}


def lookup_asn(bundle: Bundle, asn: int) -> AsnInfo | None:
    """Return member-prefix observations without classifying the entire AS."""
    if not _is_uint32(asn):
        raise InvalidAsnError(f"invalid ASN: {asn!r}")
    return bundle.asns.get(str(asn))


def asns(bundle: Bundle) -> list[AsnInfo]:
    """Return every ASN record ordered by ASN."""
    return sorted(bundle.asns.values(), key=lambda info: info["asn"])


def metadata(bundle: Bundle) -> dict[str, DatabaseMetadata]:
    return {
        key: {
            "database_type": value.database_type,
            "description": value.description,
            "build_epoch": value.build_epoch,
            "languages": value.languages,
            "ip_version": value.ip_version,
        }
        for key, reader in bundle.readers.items()
        for value in [reader.metadata()]
    }


def release_metadata(bundle: Bundle) -> ReleaseMetadata:
    return bundle.release
