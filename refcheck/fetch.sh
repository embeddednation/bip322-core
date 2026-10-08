#!/usr/bin/env bash
# Download the reference binaries used by run_refcheck.py into refcheck/bin (gitignored).
# All of it gets executed later, so every tarball is pinned by sha256 and btcd by commit.
set -euo pipefail
# The URLs below are x86_64 Linux builds; refuse rather than fetch binaries that cannot run.
[ "$(uname -s) $(uname -m)" = "Linux x86_64" ] || { echo "fetch.sh: needs Linux x86_64, this is $(uname -s) $(uname -m)" >&2; exit 1; }
cd "$(dirname "$0")"
mkdir -p bin && cd bin

CORE=31.1
CORE_SHA256=b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e   # bitcoincore.org/bin/bitcoin-core-31.1/SHA256SUMS
KNOTS=29.4.1.knots20260508
KNOTS_SHA256=0d0b435ae67dd38d150c048a388be821ad0ca8b46d6dcace5c34d4ba2977801b  # SHA256SUMS of the same GitHub release
GO=1.27.1
GO_SHA256=63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445     # go.dev/dl/?mode=json&include=all
BTCD_URL=https://github.com/guggero/btcd
# Tip of branch bip-322 on 2026-09-11. The branch of this personal fork gets rebased, hence the pin.
BTCD_COMMIT=32841bed43875a29eb17d38b3db530d07f27c002

# Everything is staged in a temp dir inside bin/ (same filesystem) and renamed into place when
# complete, so an interrupted run never leaves a half-extracted directory that looks done.
tmp=$(mktemp -d "$PWD/tmp.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

# fetch_tar DIR SHA256 URL: download, verify, unpack, move the tarball's top-level DIR into place.
# Call it as a plain statement: after || or && bash would switch off set -e inside it.
fetch_tar() {
  local dir=$1 sha=$2 url=$3 tgz=$tmp/$1.tar.gz
  if [ -d "$dir" ]; then return; fi
  curl -fL -o "$tgz" "$url"
  echo "$sha  $tgz" | sha256sum -c - || { rm -f "$tgz"; echo "fetch.sh: sha256 mismatch for $url (expected $sha), not unpacked" >&2; exit 1; }
  tar -xzf "$tgz" -C "$tmp"
  mv -T "$tmp/$dir" "$dir"
  rm -f "$tgz"
}
fetch_tar "bitcoin-$CORE" "$CORE_SHA256" "https://bitcoincore.org/bin/bitcoin-core-$CORE/bitcoin-$CORE-x86_64-linux-gnu.tar.gz"
fetch_tar "bitcoin-$KNOTS" "$KNOTS_SHA256" "https://github.com/bitcoinknots/bitcoin/releases/download/v$KNOTS/bitcoin-$KNOTS-x86_64-linux-gnu.tar.gz"
fetch_tar go "$GO_SHA256" "https://go.dev/dl/go$GO.linux-amd64.tar.gz"

# btcd: shallow-fetch exactly the pinned commit instead of whatever the branch points at today.
if [ ! -d btcd-src ]; then
  git init -q "$tmp/btcd-src"
  git -C "$tmp/btcd-src" remote add origin "$BTCD_URL"
  git -C "$tmp/btcd-src" fetch --depth 1 origin "$BTCD_COMMIT"
  git -C "$tmp/btcd-src" checkout -q --detach FETCH_HEAD
  [ "$(git -C "$tmp/btcd-src" rev-parse HEAD)" = "$BTCD_COMMIT" ] || { echo "fetch.sh: btcd checkout is not $BTCD_COMMIT" >&2; exit 1; }
  mv -T "$tmp/btcd-src" btcd-src
fi
echo "reference binaries ready in $(pwd)"
