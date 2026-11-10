import argparse
import json
import tomllib
from pathlib import Path

from semver import Version

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("tag")
    arguments = parser.parse_args()
    if not arguments.tag.startswith("v"):
        raise ValueError("Release tag must begin with v")
    version = Version.parse(arguments.tag.removeprefix("v"))
    manifests = {
        "typescript": json.loads((ROOT / "typescript/package.json").read_text())[
            "version"
        ],
        "python": tomllib.loads((ROOT / "python/pyproject.toml").read_text())[
            "project"
        ]["version"],
        "rust": tomllib.loads((ROOT / "rust/Cargo.toml").read_text())["package"][
            "version"
        ],
    }
    for name, value in manifests.items():
        if Version.parse(value) != version:
            raise ValueError(
                f"{name} manifest version {value} does not match {version}"
            )
    print(f"version={version}")
    print(f"tag=v{version}")
    print(f"npm_tag={'next' if version.prerelease else 'latest'}")


if __name__ == "__main__":
    main()
