#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
export TMPDIR="$PWD/.cache/tmp"
export GOTMPDIR="$TMPDIR"
mkdir -p "$TMPDIR"

pnpm install --frozen-lockfile --ignore-scripts
pnpm build
pnpm test
pnpm lint
pnpm format
uv sync --frozen --project python --python 3.14
uv run --project python python tools/check-contract.py
uv run --project python pytest python/tests
uv run --project python mypy --config-file python/pyproject.toml python/src
uv run --project python ruff check --config python/pyproject.toml python tools
uv run --project python ruff format --check --config python/pyproject.toml python tools
(cd go && go test -race -count=1 ./... && go vet ./...)
test -z "$(gofmt -l go/*.go go/examples/live/*.go)"
cargo fmt --manifest-path rust/Cargo.toml --all -- --check
cargo clippy --manifest-path rust/Cargo.toml --all-targets --locked -- -D warnings
cargo test --manifest-path rust/Cargo.toml --locked
