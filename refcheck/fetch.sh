#!/usr/bin/env bash
# Download the reference binaries used by run_refcheck.py into refcheck/bin (gitignored).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p bin && cd bin
CORE=31.1
KNOTS=29.4.1.knots20260508
GO=1.27.1
[ -d bitcoin-$CORE ] || { curl -fL -o core.tar.gz https://bitcoincore.org/bin/bitcoin-core-$CORE/bitcoin-$CORE-x86_64-linux-gnu.tar.gz && tar -xzf core.tar.gz && rm core.tar.gz; }
[ -d bitcoin-$KNOTS ] || { curl -fL -o knots.tar.gz https://github.com/bitcoinknots/bitcoin/releases/download/v$KNOTS/bitcoin-$KNOTS-x86_64-linux-gnu.tar.gz && tar -xzf knots.tar.gz && rm knots.tar.gz; }
[ -d go ] || { curl -fL -o go.tar.gz https://go.dev/dl/go$GO.linux-amd64.tar.gz && tar -xzf go.tar.gz && rm go.tar.gz; }
[ -d btcd-src ] || git clone --depth 1 -b bip-322 https://github.com/guggero/btcd btcd-src
echo "reference binaries ready in $(pwd)"
