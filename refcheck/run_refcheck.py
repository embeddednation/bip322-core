#!/usr/bin/env python3
"""Cross-check bip322ms against independent implementations.

For every case in the corpus (refcheck/corpus.py) the signature is checked by:

  ours    bip322ms.verify (btclib engine + libbitcoinkernel consensus engine)
  btclib  btclib.bip322.verify - an independent Python implementation of the
          BIP-322 framing on top of btclib's own script engine
  btcd    the btcd BIP-322 reference package (btcsuite/btcd PR #2521), which
          is the implementation the BIP names as "complete" and the source of
          the official test vectors (refcheck/btcd/btcd-bip322)
  knots   Bitcoin Knots' `verifymessage`, i.e. the Bitcoin Core PR #24058 code
          running Core's script interpreter with the BIP-322 flag sets

and Bitcoin Core 31.1 is used as an independent *producer*: it derives the
addresses, signs our PSBT with `descriptorprocesspsbt`, finalizes it with
`finalizepsbt`, and re-verifies witnesses with `signrawtransactionwithkey`.

Run from the repository root:  .venv/bin/python -m refcheck.run_refcheck
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bip322ms.core import build_to_spend, encode_full, encode_simple, parse_transaction  # noqa: E402
from bip322ms.engines import available_engines  # noqa: E402
from bip322ms.psbt import extract_tx, finalize_psbt, parse_psbt, sign_psbt  # noqa: E402
from bip322ms.verify import State, verify_message  # noqa: E402
from refcheck.corpus import Case, Fixture, build_corpus  # noqa: E402
from refcheck.daemons import Daemon, RPCError  # noqa: E402

BIN = ROOT / "refcheck" / "bin"
OUT = ROOT / "refcheck" / "out"
CORE_DIR = next(iter(sorted(BIN.glob("bitcoin-31.*"))), None)
KNOTS_DIR = next(iter(sorted(BIN.glob("bitcoin-*knots*"))), None)
BTCD_BIN = ROOT / "refcheck" / "btcd" / "btcd-bip322"


# --------------------------------------------------------------------------- #
# per-implementation verifiers
# --------------------------------------------------------------------------- #


def check_ours(case: Case, engines) -> tuple[str, str]:
    result = verify_message(case.address_main, case.signature, case.message, engines=engines)
    return result.state.value, result.reason


def check_btclib(case: Case) -> tuple[str, str]:
    from btclib.bip322 import assert_as_valid
    from btclib.exceptions import BTClibRuntimeError, BTClibValueError, InconclusiveError

    try:
        assert_as_valid(case.message, case.address_main, case.signature)
        return "valid", ""
    except InconclusiveError as exc:
        return "inconclusive", str(exc)[:120]
    except (BTClibValueError, BTClibRuntimeError, ValueError, RuntimeError) as exc:
        return "invalid", f"{type(exc).__name__}: {str(exc)[:100]}"


def check_btcd(cases: list[Case]) -> dict[str, tuple[str, str]]:
    if not BTCD_BIN.exists():
        return {c.id: ("n/a", "btcd-bip322 not built (refcheck/btcd/build.sh)") for c in cases}
    lines = [
        json.dumps({"id": c.id, "network": "regtest", "address": c.address_regtest, "message_hex": c.message.hex(), "signature": c.signature})
        for c in cases
    ]
    proc = subprocess.run([str(BTCD_BIN)], input="\n".join(lines) + "\n", capture_output=True, text=True, check=False)
    out: dict[str, tuple[str, str]] = {}
    for line in proc.stdout.splitlines():
        r = json.loads(line)
        if r.get("valid"):
            state = "valid"
        elif "inconclusive" in (r.get("error") or "").lower():
            state = "inconclusive"
        else:
            state = "invalid"
        out[r["id"]] = (state, r.get("error") or "")
    for c in cases:
        out.setdefault(c.id, ("error", proc.stderr.strip()[:200] or "no response"))
    return out


def check_knots(knots: Daemon, case: Case) -> tuple[str, str]:
    if "knots" in case.skip:
        return "n/a", case.skip["knots"]
    sig = case.signature
    if sig[:3] == "pof":
        return "n/a", "Knots has no proof-of-funds support"
    if sig[:3] in ("smp", "ful"):
        sig = sig[3:]  # Knots predates the prefixes
    try:
        message = case.message.decode("utf-8")
    except UnicodeDecodeError:
        return "n/a", "RPC needs UTF-8 text"
    try:
        ok = knots.rpc("verifymessage", case.address_regtest, sig, message)
    except RPCError as exc:
        if "not yet supported" in exc.message:
            return "inconclusive", exc.message
        return "invalid", exc.message
    return ("valid" if ok else "invalid"), ""


# --------------------------------------------------------------------------- #
# Bitcoin Core as an independent producer
# --------------------------------------------------------------------------- #


def core_checks(core: Daemon, fx: Fixture) -> list[dict]:
    """Return a list of {check, ok, detail} dicts."""
    results: list[dict] = []

    def rec(check: str, ok: bool, detail: str = "") -> None:
        results.append({"check": check, "ok": bool(ok), "detail": detail})

    wallet = fx.wallet
    desc_no_sum = wallet.to_descriptor(checksum=False, branches="0")
    info = core.rpc("getdescriptorinfo", desc_no_sum)
    ours = wallet.to_descriptor(branches="0").split("#")[1]
    rec("descriptor checksum matches Core", info["checksum"] == ours, f"core={info['checksum']} ours={ours}")
    for branch in (0, 1):
        desc = wallet.to_descriptor(branches=str(branch))
        addrs = core.rpc("deriveaddresses", desc, [0, 5])
        mine = [wallet.derive(i, branch).address for i in range(6)]
        rec(f"deriveaddresses branch {branch} matches", addrs == mine, "" if addrs == mine else f"core={addrs[:2]} ours={mine[:2]}")

    message = b"Core cross-check: 2-of-3 quorum message"
    index = 2
    derived = wallet.derive(index)
    unsigned = fx.unsigned(message, index)
    unsigned_b64 = unsigned.to_string()
    decoded = core.rpc("decodepsbt", unsigned_b64)
    tx = decoded["tx"]
    rec("Core decodes PSBT tx version 0 / sequence 0 / 1 OP_RETURN output",
        tx["version"] == 0 and tx["vin"][0]["sequence"] == 0 and len(tx["vout"]) == 1 and tx["vout"][0]["value"] == 0,
        f"version={tx['version']} sequence={tx['vin'][0]['sequence']} vout={len(tx['vout'])}")
    unknown = decoded.get("unknown", {})
    rec("Core keeps PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE (0x09) as unknown global", unknown.get("09") == message.hex(), json.dumps(unknown)[:120])
    rec("Core sees the witness script and 3 derivations", decoded["inputs"][0].get("witness_script", {}).get("hex") == derived.witness_script.hex() and len(decoded["inputs"][0].get("bip32_derivs", [])) == 3)
    rec("Core sees 3 global xpubs", len(decoded.get("global_xpubs", [])) == 3)
    analysis = core.rpc("analyzepsbt", unsigned_b64)
    rec("analyzepsbt: next role is signer, 3 signatures missing", analysis.get("next") == "signer" and len(analysis["inputs"][0].get("missing", {}).get("signatures", [])) == 3, json.dumps(analysis)[:160])

    # Core signs with cosigners A and B, and finalizes.
    signed_ab = core.rpc("descriptorprocesspsbt", unsigned_b64, fx.private_descriptors[:2])
    rec("descriptorprocesspsbt(A,B) completes", signed_ab["complete"] is True)
    core_hex = signed_ab.get("hex")
    our_psbt = fx.finalized(message, (0, 1), index)
    our_hex = extract_tx(our_psbt).serialize().hex()
    rec("Core's finalized to_sign equals ours byte for byte (RFC6979 low-R signatures)", core_hex == our_hex, "" if core_hex == our_hex else f"core={core_hex[:80]}.. ours={our_hex[:80]}..")
    core_tx = parse_transaction(bytes.fromhex(core_hex))
    for engines in (("btclib",), ("btclib", "kernel")):
        r = verify_message(derived.address, encode_simple(core_tx.vin[0].witness.items), message, engines=engines)
        rec(f"our verifier accepts Core-produced witness ({'+'.join(engines)})", r.ok, r.reason)
    # Core signs A only, we add B, we finalize; and the reverse via Core's finalizer.
    signed_a = core.rpc("descriptorprocesspsbt", unsigned_b64, fx.private_descriptors[:1])
    rec("descriptorprocesspsbt(A) is incomplete", signed_a["complete"] is False)
    mixed = parse_psbt(signed_a["psbt"])
    rec("Core-signed PSBT parses with message intact", mixed.message == message and len(mixed.inputs[0].partial_sigs) == 1)
    rec("our signer adds B to Core-signed PSBT", sign_psbt(mixed, fx.signers[1]) == 1)
    mixed_b64 = mixed.to_string()
    finalize_psbt(mixed)
    mixed_hex = extract_tx(mixed).serialize().hex()
    rec("mixed (Core A + ours B) equals Core (A,B)", mixed_hex == core_hex)
    fin = core.rpc("finalizepsbt", mixed_b64)
    rec("Core finalizepsbt accepts our partial signature (runs VerifyScript with STANDARD flags)", fin.get("complete") is True and fin.get("hex") == mixed_hex, json.dumps({k: v for k, v in fin.items() if k != 'psbt'})[:160])
    ours_signed = fx.signed(message, (1, 2), index).to_string()
    fin2 = core.rpc("finalizepsbt", ours_signed)
    rec("Core finalizepsbt completes our (B,C)-signed PSBT", fin2.get("complete") is True)
    r = verify_message(derived.address, encode_full(parse_transaction(bytes.fromhex(fin2["hex"]))), message)
    rec("our verifier accepts Core-finalized (B,C) proof", r.ok, r.reason)

    # signrawtransactionwithkey with no keys re-runs VerifyScript over an existing witness.
    prevtx = {"txid": build_to_spend(message, derived.script_pubkey).txid().hex(), "vout": 0,
              "scriptPubKey": derived.script_pubkey.hex(), "witnessScript": derived.witness_script.hex(), "amount": 0}
    try:
        good = core.rpc("signrawtransactionwithkey", our_hex, [], [prevtx])
        rec("signrawtransactionwithkey (no keys) accepts our witness", good.get("complete") is True and not good.get("errors"), json.dumps(good.get("errors", ""))[:160])
        from tests.helpers import high_s

        witness = list(core_tx.vin[0].witness.items)
        witness[1] = high_s(witness[1])
        from bip322ms.core import build_to_sign

        bad_tx = build_to_sign(build_to_spend(message, derived.script_pubkey).txid(), witness=witness)
        bad = core.rpc("signrawtransactionwithkey", bad_tx.serialize().hex(), [], [prevtx])
        rec("signrawtransactionwithkey rejects a high-S witness (policy flags)", bad.get("complete") is False, json.dumps(bad.get("errors", ""))[:200])
    except RPCError as exc:
        rec("signrawtransactionwithkey probe", False, f"RPC error: {exc}")
    return results


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--no-knots", action="store_true")
    parser.add_argument("--no-core", action="store_true")
    parser.add_argument("--no-btcd", action="store_true")
    parser.add_argument("--json", default=str(OUT / "report.json"))
    args = parser.parse_args(argv)
    OUT.mkdir(parents=True, exist_ok=True)

    engines = tuple(available_engines())
    fx = Fixture()
    cases = build_corpus(fx)
    print(f"corpus: {len(cases)} cases; local engines: {', '.join(engines)}")

    btcd = {} if args.no_btcd else check_btcd(cases)
    knots = None
    core = None
    report = {"engines": engines, "cases": [], "core": [], "versions": {}}
    try:
        if not args.no_knots and KNOTS_DIR:
            knots = Daemon(KNOTS_DIR / "bin", OUT / "knots-data", 18643, "knots").start()
            report["versions"]["knots"] = knots.version()
        if not args.no_core and CORE_DIR:
            core = Daemon(CORE_DIR / "bin", OUT / "core-data", 18653, "core").start()
            report["versions"]["core"] = core.version()

        mismatches = 0
        header = f"{'case':28} {'expect':12} {'ours':12} {'btclib':12} {'btcd':12} {'knots':12}"
        print(header)
        print("-" * len(header))
        for case in cases:
            ours = check_ours(case, engines)
            bl = check_btclib(case)
            bd = btcd.get(case.id, ("n/a", "skipped"))
            kn = check_knots(knots, case) if knots else ("n/a", "skipped")
            verdicts = {"ours": ours, "btclib": bl, "btcd": bd, "knots": kn}
            deviations = [name for name, v in verdicts.items() if v[0] not in (case.kind, "n/a")]
            unexplained = [name for name in deviations if name not in case.known]
            agree = not unexplained
            if not agree:
                mismatches += 1
            if unexplained:
                flag = "   <-- MISMATCH"
            elif deviations:
                flag = "   (known deviation: " + "; ".join(f"{n}: {case.known[n]}" for n in deviations) + ")"
            else:
                flag = ""
            print(f"{case.id:28} {case.kind:12} {ours[0]:12} {bl[0]:12} {bd[0]:12} {kn[0]:12}{flag}")
            report["cases"].append({"id": case.id, "expected": case.kind, "note": case.note, "address": case.address_regtest,
                                    "signature": case.signature, "message_hex": case.message.hex(),
                                    "verdicts": {k: {"state": v[0], "detail": v[1]} for k, v in verdicts.items()}, "agree": agree,
                                    "known_deviations": {n: case.known[n] for n in deviations if n in case.known}})
        print()
        if core:
            print("Bitcoin Core producer checks:")
            core_results = core_checks(core, fx)
            for item in core_results:
                mark = "ok " if item["ok"] else "FAIL"
                print(f"  [{mark}] {item['check']}" + (f"  ({item['detail']})" if item["detail"] and not item["ok"] else ""))
                if not item["ok"]:
                    mismatches += 1
            report["core"] = core_results
    finally:
        if knots:
            knots.stop()
        if core:
            core.stop()

    Path(args.json).write_text(json.dumps(report, indent=2))
    print(f"\nreport written to {args.json}")
    if mismatches:
        print(f"{mismatches} mismatch(es)")
        return 1
    print("all implementations agree on every case")
    return 0


if __name__ == "__main__":
    sys.exit(main())
