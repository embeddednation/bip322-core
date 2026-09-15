"""Finalize a snapshot bundle into proofs, and verify proofs against a node.

``proofs.json`` is the artifact handed to the auditor: the snapshot (stamp,
addresses, UTXOs, message) plus one BIP-322 signature per address.  ``verify``
re-checks every part of it: the signatures with ``bip322``, the stamp with
``getblockheader``, every listed output with ``gettxout``.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from bip322.engines import available_engines
from bip322.psbt import BIP322PSBT, FinalizeError, combine_psbts, finalize_psbt, parse_psbt, signature_from_psbt
from bip322.verify import verify_message

from . import TOOL
from .rpc import BitcoinCli, RpcError, to_sat
from .snapshot import load_snapshot
from .stamp import Stamp, check_stamp, parse_stamp


class AuditError(Exception):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- #
# finalize
# --------------------------------------------------------------------------- #


def collect_psbts(directory: Path) -> dict[str, list[BIP322PSBT]]:
    """Every parseable PSBT in the bundle and its ``signed/`` folder, grouped by to_sign txid."""
    groups: dict[str, list[BIP322PSBT]] = {}
    for folder in (directory, directory / "signed"):
        if not folder.is_dir():
            continue
        for path in sorted(folder.iterdir()):
            if path.suffix.lower() != ".psbt" or not path.is_file():
                continue
            try:
                psbt = parse_psbt(path.read_bytes())
            except Exception:  # noqa: BLE001 - foreign files in the folder are ignored
                continue
            groups.setdefault(psbt.tx.txid().hex(), []).append(psbt)
    return groups


def finalize_bundle(directory: Path, *, lenient: bool = False, engines=None) -> dict:
    """Combine and finalize the signed PSBTs of every address; return the proofs document."""
    snapshot = load_snapshot(directory)
    groups = collect_psbts(directory)
    message = snapshot["message"].encode("utf-8")
    proofs = []
    missing = []
    for entry in snapshot["addresses"]:
        address, txid = entry["address"], entry["to_sign_txid"]
        candidates = groups.get(txid, [])
        if not candidates:
            missing.append(f"{address}: no PSBT found for to_sign {txid[:16]}...")
            continue
        try:
            combined = combine_psbts(candidates)
            finalize_psbt(combined, strict=not lenient)
            signature = signature_from_psbt(combined)
        except FinalizeError as exc:
            missing.append(f"{address}: {exc}")
            continue
        result = verify_message(address, signature, message, engines=engines or available_engines())
        if not result.ok:
            missing.append(f"{address}: finalized proof does not verify: {result.reason}")
            continue
        proofs.append({**entry, "signature": signature, "variant": signature[:3]})
    if missing:
        raise AuditError("cannot finalize every address:\n  " + "\n  ".join(missing))
    document = dict(snapshot)
    document.update({"tool": TOOL, "finalized_utc": _now(), "message_hex": message.hex(), "proofs": proofs})
    document.pop("addresses", None)
    return document


# --------------------------------------------------------------------------- #
# verify
# --------------------------------------------------------------------------- #


def _check_utxo(cli: BitcoinCli, tip_height: int, stamp: Stamp, address: str, utxo: dict, *, txindex: bool) -> dict:
    """One listed output against the node.

    ``verified``: the node confirms it existed at the snapshot block with the claimed
    amount and address.  ``contradiction``: the node shows something that disagrees
    with the claim.  Neither: the output is gone and this node cannot say more.
    """
    row = {**utxo, "status": "unknown", "verified": False, "contradiction": False}
    out = cli.call("gettxout", utxo["txid"], int(utxo["vout"]), False)
    if out:
        created = tip_height - int(out["confirmations"]) + 1
        row.update(
            {
                "status": "unspent",
                "node_amount_sat": to_sat(out["value"]),
                "node_address": out.get("scriptPubKey", {}).get("address"),
                "created_height": created,
                "confirmations": int(out["confirmations"]),
            }
        )
        matches = row["node_amount_sat"] == utxo["amount_sat"] and row["node_address"] == address and created == utxo["height"] and created <= stamp.height
        row["verified"] = matches
        row["contradiction"] = not matches
        if not matches:
            row["problem"] = "amount, address or creation height differs from the snapshot"
        return row
    if txindex:
        try:
            tx = cli.call("getrawtransaction", utxo["txid"], True)
            header = cli.block_header(tx["blockhash"]) if tx.get("blockhash") else None
        except RpcError as exc:
            row["status"] = "spent_or_unknown"
            row["note"] = f"getrawtransaction: {exc}"
            return row
        if header:
            created = int(header["height"])
            row["created_height"] = created
            if created == utxo["height"] and created <= stamp.height:
                row["status"] = "spent_after_snapshot"
                row["verified"] = True
                row["note"] = "existed at the snapshot block and has been spent since (that it was unspent at the snapshot cannot be shown without a spend index)"
            else:
                row["status"] = "created_after_snapshot"
                row["contradiction"] = True
                row["problem"] = "the creating transaction was confirmed after the snapshot block"
            return row
    row["status"] = "spent_or_unknown"
    row["note"] = "not in the UTXO set now; --txindex on a node with -txindex can confirm it existed at the snapshot block"
    return row


def verify_proofs(document: dict, cli: BitcoinCli | None, *, engines=None, txindex: bool = False, scan: bool = False) -> dict:
    """Verify a proofs document; ``cli=None`` verifies only what needs no node."""
    engines = list(engines or available_engines())
    message = bytes.fromhex(document["message_hex"]) if document.get("message_hex") else document["message"].encode("utf-8")
    stamp = parse_stamp(message)
    report: dict = {"tool": TOOL, "verified_utc": _now(), "engines": engines, "proofs": [], "stamp": None, "node": None}

    if cli is not None:
        chain = cli.chain()
        tip_height, tip_hash = cli.tip()
        report["node"] = {"chain": chain, "tip_height": tip_height, "tip_hash": tip_hash}
        if document.get("chain") and document["chain"] != chain:
            raise AuditError(f"proofs are for chain {document['chain']!r}, node is on {chain!r}")
    if stamp is None:
        report["stamp"] = {"ok": False, "error": "message carries no block stamp"}
    elif cli is None:
        report["stamp"] = {"stamp": stamp.to_dict(), "ok": None, "note": "not checked (offline)"}
    else:
        report["stamp"] = check_stamp(cli, stamp)

    claimed = unspent = 0
    all_proofs_ok = True
    contradictions = 0
    verified_count = total_count = 0
    for proof in document["proofs"]:
        address = proof["address"]
        verdict = verify_message(address, proof["signature"], message, engines=engines)
        row = {"address": address, "branch": proof.get("branch"), "index": proof.get("index"), "bip322": verdict.to_dict(), "utxos": [], "claimed_sat": proof["total_sat"]}
        row["bip322"].pop("message_utf8", None)
        row["bip322"].pop("message_hex", None)
        all_proofs_ok &= verdict.ok
        claimed += proof["total_sat"]
        if cli is not None and stamp is not None:
            for utxo in proof["utxos"]:
                checked = _check_utxo(cli, tip_height, stamp, address, utxo, txindex=txindex)
                row["utxos"].append(checked)
                total_count += 1
                verified_count += int(checked["verified"])
                contradictions += int(checked["contradiction"])
                if checked["status"] == "unspent" and checked["verified"]:
                    unspent += checked["node_amount_sat"]
        else:
            row["utxos"] = [{**u, "status": "not checked (offline)"} for u in proof["utxos"]]
        row["unspent_now_sat"] = sum(u.get("node_amount_sat", 0) for u in row["utxos"] if u.get("status") == "unspent" and u.get("verified"))
        report["proofs"].append(row)

    if cli is not None and scan:
        report["current_holdings"] = _scan_now(cli, document)

    stamp_ok = bool(report["stamp"] and report["stamp"].get("ok"))
    online = cli is not None
    report["totals"] = {"claimed_sat": claimed, "verified_unspent_sat": unspent if online else None}
    report["summary"] = {
        "proofs_valid": all_proofs_ok,
        "stamp_ok": stamp_ok if online else None,
        "utxos_verified_at_snapshot": f"{verified_count}/{total_count}" if online else None,
        "contradictions": contradictions if online else None,
        "all_utxos_still_unspent": (unspent == claimed) if online else None,
    }
    # the proof of control stands when the signatures and the stamp check out and the node contradicts
    # nothing; outputs spent since the snapshot are reported (and confirmed with --txindex), not failures
    report["ok"] = all_proofs_ok and (stamp_ok if online else True) and contradictions == 0
    return report


def _scan_now(cli: BitcoinCli, document: dict) -> dict:
    descriptors = [{"desc": f"addr({p['address']})"} for p in document["proofs"]]
    result = cli.call("scantxoutset", "start", descriptors)
    by_address: dict[str, int] = {}
    for u in result.get("unspents", []):
        address = u.get("desc", "")
        address = address[5:].split(")")[0] if address.startswith("addr(") else address
        by_address[address] = by_address.get(address, 0) + to_sat(u["amount"])
    return {"height": int(result["height"]), "bestblock": result["bestblock"], "by_address_sat": by_address, "total_sat": sum(by_address.values())}


def format_report(report: dict) -> str:
    lines = []
    node = report.get("node")
    lines.append(f"{report['tool']}  verified {report['verified_utc']}  engines: {', '.join(report['engines'])}")
    if node:
        lines.append(f"node: chain {node['chain']}, tip {node['tip_height']} {node['tip_hash'][:16]}...")
    st = report.get("stamp") or {}
    if st.get("stamp"):
        s = st["stamp"]
        status = "ok" if st.get("ok") else ("not checked" if st.get("ok") is None else f"FAILED ({st.get('error') or 'mismatch'})")
        lines.append(f"stamp: block {s['height']} {s['hash'][:16]}... {s['time']}  ->  {status}" + (f", {st['confirmations']} confirmations" if st.get("confirmations") else ""))
    else:
        lines.append("stamp: none")
    lines.append("")
    for p in report["proofs"]:
        v = p["bip322"]
        lines.append(f"{p['address']}  (branch {p['branch']}, index {p['index']})  bip322: {v['state'].upper()}")
        for u in p["utxos"]:
            mark = "ok" if u.get("verified") else ("!!" if u.get("contradiction") else "--")
            lines.append(f"    [{mark}] {u['txid'][:16]}...:{u['vout']}  {u['amount_sat']:>12} sat  {u['status']}" + (f"  ({u['problem']})" if u.get("problem") else ""))
        lines.append(f"    claimed {p['claimed_sat']} sat" + (f", unspent now {p['unspent_now_sat']} sat" if node else ""))
    lines.append("")
    t = report["totals"]
    lines.append(f"totals: claimed {t['claimed_sat']} sat" + (f", verified unspent now {t['verified_unspent_sat']} sat" if node else ""))
    if report.get("current_holdings"):
        h = report["current_holdings"]
        lines.append(f"current holdings at height {h['height']}: {h['total_sat']} sat across {len(h['by_address_sat'])} address(es)")
    s = report["summary"]
    lines.append(f"proofs valid: {s['proofs_valid']}; stamp ok: {s['stamp_ok']}; outputs verified at snapshot: {s['utxos_verified_at_snapshot']}; contradictions: {s['contradictions']}; all still unspent: {s['all_utxos_still_unspent']}")
    lines.append("RESULT: " + ("OK" if report["ok"] else "FAILED"))
    return "\n".join(lines)


def load_proofs(path: Path) -> dict:
    path = path / "proofs.json" if path.is_dir() else path
    return json.loads(path.read_text())
