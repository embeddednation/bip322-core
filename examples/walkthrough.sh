#!/usr/bin/env bash
# End-to-end walkthrough with dummy keys: three software "cosigners" stand in for
# the Coldcards.  Run from the repository root:  examples/walkthrough.sh [workdir]
set -euo pipefail
cd "$(dirname "$0")/.."
PY=.venv/bin/python
CLI=.venv/bin/bip322ms
WORK=${1:-examples/out}
rm -rf "$WORK" && mkdir -p "$WORK"
MSG="bip322ms demo: the 2-of-3 quorum controls this address"
field() { $PY -c "import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$1" "$2"; }
step() { printf '\n\033[1m=== %s ===\033[0m\n' "$*"; }
run() { printf '$ %s\n' "$*" >&2; "$@"; }

step "1. dummy cosigner keys (deterministic seeds - never use for real funds)"
for L in A B C; do
  run $CLI keygen --label "$L" --seed "demo cosigner $L" > "$WORK/cosigner-$L.json"
  echo "  $L: fingerprint $(field "$WORK/cosigner-$L.json" fingerprint)  $(field "$WORK/cosigner-$L.json" coldcard_line | cut -c1-40)..."
done

step "2. wallet descriptor built from the three cosigner files (a Coldcard export file works too)"
run $CLI makewallet -t 2 --name demo-2of3 "$WORK"/cosigner-{A,B,C}.json -o "$WORK/wallet.desc"
cat "$WORK/wallet.desc"
echo "(same wallet as a Coldcard would export it:)"
run $CLI makewallet -t 2 --name demo-2of3 --format coldcard "$WORK"/cosigner-{A,B,C}.json 2>/dev/null
run $CLI wallet -w "$WORK/wallet.desc" --addresses 2 > "$WORK/wallet.json"
$PY -c "import json;d=json.load(open('$WORK/wallet.json'));print(json.dumps({k:d[k] for k in ('policy','script','descriptor','addresses')},indent=2))"
ADDR=$($PY -c "import json;print(json.load(open('$WORK/wallet.json'))['addresses'][0]['address'])")

step "3. create the BIP-322 PSBT for address $ADDR"
run $CLI create -w "$WORK/wallet.desc" -a "$ADDR" -m "$MSG" --strict-coldcard -o "$WORK/proof.psbt"
echo "PSBT (base64): $(cut -c1-72 "$WORK/proof.psbt")..."

step "4. inspect the unsigned PSBT (the BIP-322 'PSBT signer' checks a Coldcard performs)"
run $CLI inspect "$WORK/proof.psbt"

step "5. cosigners A and C sign separately (this is where two Coldcards would sign)"
run $CLI sign "$WORK/proof.psbt" -k "$WORK/cosigner-A.json" -o "$WORK/proof-A.psbt"
run $CLI sign "$WORK/proof.psbt" -k "$WORK/cosigner-C.json" -o "$WORK/proof-C.psbt"
echo "partial signatures in proof-A.psbt:"; $CLI inspect "$WORK/proof-A.psbt" | $PY -c "import json,sys;print(json.dumps(json.load(sys.stdin)['partial_sigs'],indent=2))"

step "6. combine the two signed PSBTs"
run $CLI combine "$WORK/proof-A.psbt" "$WORK/proof-C.psbt" -o "$WORK/proof-AC.psbt"

step "7. finalize: check partial sigs, build the witness, self-verify, encode as smp"
run $CLI finalize "$WORK/proof-AC.psbt" --engines btclib,kernel --signature-file "$WORK/proof.sig" --json > "$WORK/finalize.json"
$PY -c "import json;d=json.load(open('$WORK/finalize.json'));d['self_verification'].pop('engines');print(json.dumps(d,indent=2))"
SIG=$(cat "$WORK/proof.sig")

step "8. verify with the tool (btclib policy engine + Bitcoin Core kernel engine)"
run $CLI verify -a "$ADDR" -m "$MSG" -s "$SIG" --engines btclib,kernel

step "9. negative checks: wrong message, wrong address, one signature only"
if $CLI verify -a "$ADDR" -m "$MSG (tampered)" -s "$SIG"; then echo "UNEXPECTED"; exit 1; fi
ADDR2=$($PY -c "import json;print(json.load(open('$WORK/wallet.json'))['addresses'][1]['address'])")
if $CLI verify -a "$ADDR2" -m "$MSG" -s "$SIG"; then echo "UNEXPECTED"; exit 1; fi
if $CLI finalize "$WORK/proof-A.psbt" 2>"$WORK/finalize-A.err"; then echo "UNEXPECTED"; exit 1; else cat "$WORK/finalize-A.err"; fi

step "10. independent verification: btclib, btcd reference, Bitcoin Knots, Bitcoin Core"
run $PY -m refcheck.verify_one -a "$ADDR" -m "$MSG" --signature-file "$WORK/proof.sig"

step "done - artifacts in $WORK"
ls -1 "$WORK"
