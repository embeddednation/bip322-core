#!/usr/bin/env bash
# Build the btcd BIP-322 wrapper. Needs Go >= 1.25 (refcheck/bin/go/bin/go is used if present).
set -euo pipefail
cd "$(dirname "$0")"
GO=go
if [ -x ../bin/go/bin/go ]; then GO=../bin/go/bin/go; fi
export GOFLAGS=-mod=mod GOTOOLCHAIN=local
"$GO" mod tidy
"$GO" build -o btcd-bip322 .
echo "built $(pwd)/btcd-bip322"
