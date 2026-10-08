#!/usr/bin/env bash
# End-to-end walkthrough with dummy keys: three software "cosigners" stand in for
# the hardware signers.  Run from anywhere:  examples/walkthrough.sh [workdir]
# The work directory is a fresh temporary one, or WORKDIR if it does not exist
# yet or is empty; nothing is ever deleted here.
set -euo pipefail
case ${1:-} in "" | /*) WORK=${1:-} ;; *) WORK=$PWD/$1 ;; esac
cd "$(dirname "$0")/.."
[ -x .venv/bin/bip322 ] || { echo "walkthrough.sh: .venv/bin/bip322 not found; run ./setup.sh first" >&2; exit 1; }
if [ -z "$WORK" ]; then
  WORK=$(mktemp -d "${TMPDIR:-/tmp}/bip322-walkthrough.XXXXXX")
elif [ -e "$WORK" ] && { [ ! -d "$WORK" ] || [ -n "$(ls -A "$WORK")" ]; }; then
  echo "walkthrough.sh: $WORK exists and is not an empty directory; name a new one" >&2
  exit 1
else
  mkdir -p "$WORK"
fi
PY=.venv/bin/python
CLI=".venv/bin/bip322 --network regtest"   # protocol commands (no private keys); the demo keys are regtest keys
DEV=.venv/bin/bip322-dev                   # scaffolding: dummy keys, wallet assembly, software signing
MSG="bip322 demo: the 2-of-3 quorum controls this address"
field() { $PY -c "import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$1" "$2"; }
step() { printf '\n\033[1m=== %s ===\033[0m\n' "$*"; }
run() { printf '$ %s\n' "$*" >&2; "$@"; }

step "1. dummy cosigner keys (deterministic seeds - never use for real funds)"
for L in A B C; do
  run $DEV keygen --label "$L" --seed "demo cosigner $L" > "$WORK/cosigner-$L.json"
  echo "  $L: fingerprint $(field "$WORK/cosigner-$L.json" fingerprint)  $(field "$WORK/cosigner-$L.json" xpub_expression | cut -c1-60)..."
done

step "2. wallet descriptor built from the three cosigner files (a real quorum: export it from the wallet software or a signing device)"
run $DEV makewallet -t 2 --name demo-2of3 "$WORK"/cosigner-{A,B,C}.json -o "$WORK/wallet.desc"
cat "$WORK/wallet.desc"
run $CLI wallet -w "$WORK/wallet.desc" | $PY -c "import json,sys;d=json.load(sys.stdin);print(json.dumps({k:d[k] for k in ('policy','script','cosigners')},indent=2))"
run $CLI deriveaddresses -w "$WORK/wallet.desc" 0 2
ADDR=$($CLI deriveaddresses -w "$WORK/wallet.desc" 0)
run $CLI getaddressinfo -w "$WORK/wallet.desc" "$ADDR"

step "3. create the BIP-322 PSBT for address $ADDR"
run $CLI createpsbt -w "$WORK/wallet.desc" "$ADDR" "$MSG" --strict-message -o "$WORK/proof.psbt"
echo "PSBT (base64): $(cut -c1-72 "$WORK/proof.psbt")..."

step "4. inspect the unsigned PSBT (the BIP-322 'PSBT signer' checks a signing device performs)"
run $CLI analyzepsbt "$WORK/proof.psbt"

step "5. cosigners A and C sign separately (this is where two hardware signers would sign)"
run $DEV signpsbt "$WORK/proof.psbt" "$WORK/cosigner-A.json" -o "$WORK/proof-A.psbt"
run $DEV signpsbt "$WORK/proof.psbt" "$WORK/cosigner-C.json" -o "$WORK/proof-C.psbt"
echo "partial signatures in proof-A.psbt:"; $CLI analyzepsbt "$WORK/proof-A.psbt" | $PY -c "import json,sys;print(json.dumps(json.load(sys.stdin)['partial_sigs'],indent=2))"

step "6. combine the two signed PSBTs"
run $CLI combinepsbt "$WORK/proof-A.psbt" "$WORK/proof-C.psbt" -o "$WORK/proof-AC.psbt"

step "7. finalize: check the partial signatures, build the witness, encode as smp"
run $CLI finalizepsbt "$WORK/proof-AC.psbt" -o "$WORK/proof.sig"
SIG=$(cat "$WORK/proof.sig")
echo "$SIG"
$CLI finalizepsbt "$WORK/proof-AC.psbt" --json | $PY -c "import json,sys;d=json.load(sys.stdin);d.pop('signature');print(json.dumps(d,indent=2))"

step "8. verify with the tool (every installed engine: btclib policy engine + Bitcoin Core kernel engine)"
run $CLI verifymessage "$ADDR" "$SIG" "$MSG"

step "9. negative checks: wrong message, wrong address, one signature only"
if $CLI verifymessage "$ADDR" "$SIG" "$MSG (tampered)"; then echo "UNEXPECTED"; exit 1; fi
ADDR2=$($CLI deriveaddresses -w "$WORK/wallet.desc" 1)
if $CLI verifymessage "$ADDR2" "$SIG" "$MSG"; then echo "UNEXPECTED"; exit 1; fi
if $CLI finalizepsbt "$WORK/proof-A.psbt" 2>"$WORK/finalize-A.err"; then echo "UNEXPECTED"; exit 1; else cat "$WORK/finalize-A.err"; fi

step "10. independent verification: btclib, btcd reference, Bitcoin Knots, Bitcoin Core"
run .venv/bin/python -m refcheck.verify_one "$ADDR" "$MSG" --signature-file "$WORK/proof.sig"

step "done - artifacts in $WORK"
ls -1 "$WORK"
