#!/usr/bin/env bash
# The audit workflow end to end on a throwaway regtest node: fund the demo wallet,
# snapshot, sign with the dummy cosigners, finalize, verify, spend a coin, verify again.
# Needs the Core binary from refcheck/fetch.sh.  Run from the repository root.
set -euo pipefail
cd "$(dirname "$0")/.."
CORE=$(ls -d refcheck/bin/bitcoin-31.* | head -1)
DATADIR=$(mktemp -d)
PORT=18773
CLI="$CORE/bin/bitcoin-cli -regtest -datadir=$DATADIR -rpcport=$PORT -rpcuser=demo -rpcpassword=demo"
WORK=${1:-examples/audit-out}; rm -rf "$WORK"; mkdir -p "$WORK"
DEV=.venv/bin/bip322-dev; AUDIT=.venv/bin/bip322-audit
step() { printf '\n\033[1m=== %s ===\033[0m\n' "$*"; }
run() { printf '$ %s\n' "$*" >&2; "$@"; }
cleanup() { $CLI stop >/dev/null 2>&1 || true; sleep 1; rm -rf "$DATADIR"; }
trap cleanup EXIT

step "0. a private regtest node with a wallet (-txindex so spent coins can still be explained)"
"$CORE/bin/bitcoind" -regtest -datadir="$DATADIR" -rpcport=$PORT -rpcuser=demo -rpcpassword=demo -listen=0 -connect=0 -txindex=1 -fallbackfee=0.0001 -daemonwait >/dev/null
$CLI createwallet miner >/dev/null; MINE=$($CLI -rpcwallet=miner getnewaddress); $CLI -rpcwallet=miner generatetoaddress 101 "$MINE" >/dev/null
echo "node at height $($CLI getblockcount)"

step "1. the wallet: dummy cosigners, descriptor (regtest encoding), watch-only import into Core"
for L in A B C; do $DEV keygen --label $L --seed "demo cosigner $L" --network regtest -o "$WORK/cosigner-$L.json"; done
$DEV makewallet -t 2 --name demo-2of3 --network regtest "$WORK"/cosigner-{A,B,C}.json -o "$WORK/wallet.desc" 2>/dev/null
cat "$WORK/wallet.desc"
$CLI createwallet watch true true "" false true >/dev/null
DESC0=$(.venv/bin/bip322 -w "$WORK/wallet.desc" wallet | .venv/bin/python -c "import json,sys;print(json.load(sys.stdin)['descriptor'])")
.venv/bin/python - "$CLI" "$DESC0" <<'PY'
import json, subprocess, sys
cli, desc = sys.argv[1].split(), sys.argv[2]
body = desc.split("#")[0]
descs = [subprocess.run([*cli, "getdescriptorinfo", body.replace("<0;1>", b)], capture_output=True, text=True, check=True).stdout for b in ("0", "1")]
req = [{"desc": json.loads(d)["descriptor"], "timestamp": "now", "range": [0, 50], "active": False} for d in descs]
print(subprocess.run([*cli, "-rpcwallet=watch", "importdescriptors", json.dumps(req)], capture_output=True, text=True, check=True).stdout.strip())
PY

step "2. fund two wallet addresses and confirm (7 blocks, so a depth-6 stamp covers them)"
A0=$(.venv/bin/bip322 -w "$WORK/wallet.desc" --network regtest deriveaddresses 0); A1=$(.venv/bin/bip322 -w "$WORK/wallet.desc" --network regtest deriveaddresses 2 --change)
$CLI -rpcwallet=miner sendtoaddress "$A0" 0.5 >/dev/null; $CLI -rpcwallet=miner sendtoaddress "$A1" 0.1 >/dev/null
$CLI -rpcwallet=miner generatetoaddress 7 "$MINE" >/dev/null
$CLI -rpcwallet=watch listunspent 1 | .venv/bin/python -c "import json,sys;[print(u['address'], u['amount'], 'conf', u['confirmations']) for u in json.load(sys.stdin)]"

step "3. snapshot: stamp block, coins as of that block, message, one PSBT per funded address"
run $AUDIT --cli "$CLI" -w watch snapshot --text "Annual audit {date}" -o "$WORK/bundle"
cat "$WORK/bundle/message.txt"; echo; ls "$WORK/bundle"

step "4. cosigners A and C sign every PSBT (Coldcards in real life), results go to bundle/signed/"
for P in "$WORK"/bundle/to_sign/*.psbt; do
  N=$(basename "$P" .psbt)
  $DEV signpsbt "$P" "$WORK/cosigner-A.json" -o "$WORK/bundle/signed/$N-ccA-part.psbt"
  $DEV signpsbt "$P" "$WORK/cosigner-C.json" -o "$WORK/bundle/signed/$N-ccC-part.psbt"
done

step "5. finalize into proofs.json (combines the partial signatures, self-verifies, records spends since the snapshot: none yet)"
run $AUDIT --cli "$CLI" finalize "$WORK/bundle"

step "6. the auditor verifies against their own node"
run $AUDIT --cli "$CLI" verify "$WORK/bundle" --report "$WORK/report.json"

step "7. a coin is spent after the snapshot: reported, the proof of control still stands"
CHANGE=$(.venv/bin/bip322 -w "$WORK/wallet.desc" --network regtest deriveaddresses 5 --change)
FUNDED=$($CLI -rpcwallet=watch walletcreatefundedpsbt '[]' "[{\"$MINE\":0.2}]" 0 "{\"subtractFeeFromOutputs\":[0],\"changeAddress\":\"$CHANGE\"}" | .venv/bin/python -c "import json,sys;print(json.load(sys.stdin)['psbt'])")
PRIV=$(.venv/bin/python - "$WORK" <<'PY'
import json, sys
from pathlib import Path
w = Path(sys.argv[1])
keys = [json.loads((w / f"cosigner-{l}.json").read_text()) for l in "ABC"]
def desc(holder):
    parts = [(k["xprv_expression"] if i == holder else k["xpub_expression"]) for i, k in enumerate(keys)]
    return "wsh(sortedmulti(2," + ",".join(parts) + "))"
print(json.dumps([desc(0), desc(1)]))
PY
)
SIGNED=$($CLI descriptorprocesspsbt "$FUNDED" "$PRIV" | .venv/bin/python -c "import json,sys;d=json.load(sys.stdin);assert d['complete'];print(d['hex'])")
$CLI sendrawtransaction "$SIGNED" >/dev/null; $CLI -rpcwallet=miner generatetoaddress 1 "$MINE" >/dev/null
run $AUDIT --cli "$CLI" verify "$WORK/bundle"

step "8. the owner re-runs finalize: proofs.json now records the spend, and the auditor sees the coin was unspent at the snapshot"
run $AUDIT --cli "$CLI" finalize "$WORK/bundle"
run $AUDIT --cli "$CLI" verify "$WORK/bundle"

step "done - artifacts in $WORK"
