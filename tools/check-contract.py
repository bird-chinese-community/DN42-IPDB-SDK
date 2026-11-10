import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    "country.mmdb",
    "city.mmdb",
    "asn.mmdb",
    "connection-type.mmdb",
    "asn-index.json",
    "metadata.json",
    "LICENSE-Unicode.txt",
)
COPIES = ("go/testdata", "python/tests/data", "rust/tests/data")


def main() -> None:
    for name in FILES:
        expected = hashlib.sha256((ROOT / "testdata" / name).read_bytes()).digest()
        for directory in COPIES:
            path = ROOT / directory / name
            if hashlib.sha256(path.read_bytes()).digest() != expected:
                raise ValueError(f"Contract fixture differs: {path}")
    print(json.dumps({"artifacts": len(FILES), "package_copies": len(COPIES)}))


if __name__ == "__main__":
    main()
