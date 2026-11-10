#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
output=.cache/typescript-runtime-tests
pnpm exec tsc -p tsconfig.json --rootDir . --outDir "$output"
mkdir -p "$output/typescript/test" "$output/testdata"
cp typescript/package.json "$output/typescript/"
cp typescript/test/hold-lock.mjs "$output/typescript/test/"
cp testdata/*.mmdb testdata/*.json testdata/LICENSE-Unicode.txt "$output/testdata/"
test -e "$output/typescript/node_modules" || ln -s "$PWD/typescript/node_modules" "$output/typescript/node_modules"
