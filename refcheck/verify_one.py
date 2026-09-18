#!/usr/bin/env python3
"""Check ONE BIP-322 signature against every available reference implementation.

    bip322-refcheck ADDRESS SIGNATURE MESSAGE      (--signature-file / --message-file instead of the value)
    bip322-refcheck corpus            # the 46-case corpus run (refcheck/run_refcheck.py)

Verifiers: ours (btclib + kernel), btclib's own BIP-322 module, the btcd
reference package (refcheck/btcd/btcd-bip322), Bitcoin Knots `verifymessage`
(daemon started on the address's chain, no network, no wallet) and Bitcoin
Core's `signrawtransactionwithkey` re-running VerifyScript with STANDARD flags
over the witness.  Exit code 0 only if our verdict is *valid* and no reference
disagrees.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from embit.script import Script  # noqa: E402

from bip322core.core import (  # noqa: E402
    PREFIX_FULL,
    PREFIX_POF,
    PREFIX_SIMPLE,
    SignatureFormatError,
    build_to_sign,
    build_to_spend,
    decode_signature,
    parse_transaction,
    parse_witness,
)
from bip322core.engines import available_engines  # noqa: E402
from bip322core.verify import is_script_hex, script_pubkey_from_address, verify_message  # noqa: E402
from refcheck.daemons import Daemon, RPCError  # noqa: E402
from refcheck.run_refcheck import BTCD_BIN, CORE_DIR, KNOTS_DIR, OUT  # noqa: E402


def chain_of(address: str) -> str:
    a = address.strip().lower()
    if a.startswith("bcrt1"):
        return "regtest"
    if a.startswith("tb1") or a[:1] in ("m", "n", "2"):
        return "signet"  # any test chain decodes tb1/m/n/2 addresses; verification is chain-independent
    return "main"


def btcd_network(chain: str) -> str:
    return {"main": "mainnet", "regtest": "regtest", "signet": "signet"}[chain]


def check_btcd(address: str, message: bytes, signature: str, chain: str) -> tuple[str, str]:
    if not BTCD_BIN.exists():
        return "n/a", "btcd-bip322 not built (refcheck/btcd/build.sh)"
    req = json.dumps({"id": "x", "network": btcd_network(chain), "address": address, "message_hex": message.hex(), "signature": signature})
    proc = subprocess.run([str(BTCD_BIN)], input=req + "\n", capture_output=True, text=True, check=False)
    if not proc.stdout.strip():
        return "error", proc.stderr.strip()[:200]
    r = json.loads(proc.stdout.splitlines()[0])
    if r.get("valid"):
        detail = ""
        if r.get("constrained"):
            detail = f"valid at time {r['valid_at_time']} and age {r['valid_at_age']}"
        return "valid", detail
    err = r.get("error") or ""
    return ("inconclusive" if "inconclusive" in err.lower() else "invalid"), err


def check_btclib(address: str, message: bytes, signature: str) -> tuple[str, str]:
    from btclib.bip322 import assert_as_valid
    from btclib.exceptions import BTClibRuntimeError, BTClibValueError, InconclusiveError

    try:
        assert_as_valid(message, address, signature)
        return "valid", ""
    except InconclusiveError as exc:
        return "inconclusive", str(exc)[:120]
    except (BTClibValueError, BTClibRuntimeError, ValueError, RuntimeError) as exc:
        return "invalid", f"{type(exc).__name__}: {str(exc)[:100]}"


def check_knots(address: str, message: bytes, signature: str, chain: str) -> tuple[str, str]:
    if KNOTS_DIR is None:
        return "n/a", "Knots not downloaded (refcheck/fetch.sh)"
    if signature[:3] == PREFIX_POF:
        return "n/a", "Knots has no proof-of-funds support"
    try:
        text = message.decode("utf-8")
    except UnicodeDecodeError:
        return "n/a", "RPC needs UTF-8 text"
    sig = signature[3:] if signature[:3] in (PREFIX_SIMPLE, PREFIX_FULL) else signature
    with Daemon(KNOTS_DIR / "bin", OUT / f"knots-{chain}", 18663, "knots", chain=chain) as knots:
        try:
            ok = knots.rpc("verifymessage", address, sig, text)
        except RPCError as exc:
            if "not yet supported" in exc.message:
                return "inconclusive", exc.message
            return "invalid", exc.message
    return ("valid" if ok else "invalid"), ""


def check_core(address: str, message: bytes, signature: str) -> tuple[str, str]:
    """Re-run Core's VerifyScript (STANDARD flags) over the witness via signrawtransactionwithkey."""
    if CORE_DIR is None:
        return "n/a", "Core not downloaded (refcheck/fetch.sh)"
    try:
        spk = script_pubkey_from_address(address)
        decoded = decode_signature(signature)
        if decoded.variant == PREFIX_SIMPLE:
            to_sign = build_to_sign(build_to_spend(message, spk).txid(), witness=parse_witness(decoded.payload))
        elif decoded.variant == PREFIX_FULL:
            to_sign = parse_transaction(decoded.payload)
        else:
            return "n/a", f"{decoded.variant} not supported by this probe"
    except SignatureFormatError as exc:
        return "invalid", str(exc)
    kind = Script(spk).script_type()
    if kind not in ("p2wsh", "p2wpkh"):
        return "n/a", f"probe supports p2wsh/p2wpkh only (got {kind})"
    prevtx = {"txid": build_to_spend(message, spk).txid().hex(), "vout": 0, "scriptPubKey": spk.hex(), "amount": 0}
    items = to_sign.vin[0].witness.items
    if kind == "p2wsh":
        if not items:
            return "invalid", "empty witness"
        prevtx["witnessScript"] = items[-1].hex()
    with Daemon(CORE_DIR / "bin", OUT / "core-probe", 18673, "core", chain="regtest") as core:
        try:
            res = core.rpc("signrawtransactionwithkey", to_sign.serialize().hex(), [], [prevtx])
        except RPCError as exc:
            return "error", exc.message
    if res.get("complete") and not res.get("errors"):
        return "valid", "VerifyScript with STANDARD_SCRIPT_VERIFY_FLAGS passed"
    return "invalid", json.dumps(res.get("errors", ""))[:200]


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["corpus"]:
        from refcheck.run_refcheck import main as corpus_main

        return corpus_main(argv[1:])
    parser = argparse.ArgumentParser(prog="bip322-refcheck", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("address")
    parser.add_argument("values", nargs="*", metavar="SIGNATURE MESSAGE")
    parser.add_argument("--signature-file", metavar="FILE")
    parser.add_argument("--message-file", metavar="FILE")
    parser.add_argument("--no-knots", action="store_true")
    parser.add_argument("--no-core", action="store_true")
    parser.add_argument("--no-btcd", action="store_true")
    parser.add_argument("--network", default="main", help="when ADDRESS is a scriptPubKey as hex: the network whose address encoding the reference implementations get")
    args = parser.parse_args(argv)
    if is_script_hex(args.address):  # the references take addresses; encode the same bytes for them
        from embit.networks import NETWORKS
        from embit.script import Script

        script_hex, args.address = args.address, Script(bytes.fromhex(args.address)).address(NETWORKS[args.network])
        print(f"scriptPubKey {script_hex} = address {args.address} ({args.network})", file=sys.stderr)

    expected = [n for n, f in (("signature", args.signature_file), ("message", args.message_file)) if not f]
    if len(args.values) != len(expected):
        parser.error(f"expected {' '.join(n.upper() for n in expected) or 'no further values'} after the address")
    values = dict(zip(expected, args.values, strict=True))
    message = Path(args.message_file).read_bytes() if args.message_file else values["message"].encode("utf-8")
    signature = Path(args.signature_file).read_text().strip() if args.signature_file else values["signature"].strip()
    chain = chain_of(args.address)
    OUT.mkdir(parents=True, exist_ok=True)

    engines = tuple(available_engines())
    ours = verify_message(args.address, signature, message, engines=engines)
    rows = [(f"bip322 ({'+'.join(engines)})", ours.state.value, ours.reason)]
    rows.append(("btclib.bip322", *check_btclib(args.address, message, signature)))
    if not args.no_btcd:
        rows.append(("btcd bip322 (PR #2521)", *check_btcd(args.address, message, signature, chain)))
    if not args.no_knots:
        rows.append((f"Bitcoin Knots verifymessage ({chain})", *check_knots(args.address, message, signature, chain)))
    if not args.no_core:
        rows.append(("Bitcoin Core signrawtransactionwithkey", *check_core(args.address, message, signature)))

    print(f"address   {args.address}")
    print(f"message   {message!r}" if len(message) <= 80 else f"message   {len(message)} bytes")
    print(f"signature {signature[:60]}{'...' if len(signature) > 60 else ''}  ({signature[:3]} variant, to_spend {ours.to_spend_txid})")
    print()
    width = max(len(r[0]) for r in rows)
    for name, state, detail in rows:
        print(f"  {name:{width}}  {state.upper():13} {detail}")
    verdicts = {state for _, state, _ in rows if state != "n/a"}
    agree = len(verdicts) == 1
    print()
    if agree and ours.ok:
        print(f"RESULT: VALID - {sum(1 for r in rows if r[1] != 'n/a')} verifiers agree")
        return 0
    if agree:
        print(f"RESULT: {ours.state.value.upper()} - all verifiers agree")
        return 1
    print("RESULT: DISAGREEMENT between verifiers (see above)")
    return 2


if __name__ == "__main__":
    sys.exit(main())
