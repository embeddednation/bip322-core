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
from .rpc import BitcoinCli, RpcError, btc, to_sat
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
    """Every parseable PSBT in ``to_sign/`` and ``signed/`` (and the bundle root), grouped by to_sign txid."""
    groups: dict[str, list[BIP322PSBT]] = {}
    for folder in (directory, directory / "to_sign", directory / "signed"):
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


def finalize_bundle(directory: Path, *, lenient: bool = False, engines=None, cli: BitcoinCli | None = None) -> dict:
    """Combine and finalize the signed PSBTs of every address; return the proofs document.

    The document is what the auditor gets: the message, the stamp, and per
    address the proof and the outputs.  Nothing about the wallet behind the
    addresses goes in (no descriptor, no derivation paths, no node wallet
    name): the proofs stand per address, and the xpubs would let the auditor
    derive every address of the wallet.  With ``cli`` (the node wallet the
    coins came from) the document also records which listed outputs have been
    spent since the snapshot and by what, so that a verifier can show they
    were unspent at the snapshot; re-running finalize refreshes that.
    """
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
        public = {k: v for k, v in entry.items() if k not in ("branch", "index")}
        proofs.append({**public, "signature": signature, "variant": signature[:3]})
    if missing:
        raise AuditError("cannot finalize every address:\n  " + "\n  ".join(missing))
    document = {k: v for k, v in snapshot.items() if k not in ("addresses", "wallet", "node_wallet", "source")}
    document.update(
        {
            "tool": TOOL,
            "finalized_utc": _now(),
            "message_hex": message.hex(),
            "policy": (snapshot.get("wallet") or {}).get("policy"),
            "proofs": proofs,
        }
    )
    if cli is not None:
        spends = collect_spends(cli, snapshot)
        document["spends"] = spends["spends"]
        document["spends_utc"] = spends["collected_utc"]
    else:
        document["spends"] = None
        document["spends_utc"] = None
    return document


# --------------------------------------------------------------------------- #
# spends: what the owner's wallet knows about outputs spent after the snapshot
# --------------------------------------------------------------------------- #


def collect_spends(cli: BitcoinCli, snapshot: dict) -> dict:
    """For every snapshot output spent since the stamp block, the spending transaction and its block.

    Uses the node wallet's own history (``listsinceblock`` from the stamp block),
    so it runs on the owner's side; the auditor then needs no address index:
    a spend confirmed *after* the stamp block proves the output was unspent at
    the stamp.
    """
    stamp = Stamp.from_dict(snapshot["stamp"])
    entries = snapshot.get("proofs") or snapshot.get("addresses") or []
    wanted = {(u["txid"], int(u["vout"])) for p in entries for u in p["utxos"]}
    since = cli.call("listsinceblock", stamp.hash)
    spends: dict[str, dict] = {}
    seen: set[str] = set()
    for entry in since.get("transactions", []):
        txid = entry["txid"]
        if txid in seen or int(entry.get("confirmations", 0)) <= 0:
            continue
        seen.add(txid)
        tx = cli.call("gettransaction", txid, True, True)
        for vin in tx.get("decoded", {}).get("vin", []):
            key = (vin.get("txid"), int(vin.get("vout", -1)))
            if key in wanted:
                spends[f"{key[0]}:{key[1]}"] = {"spent_by": txid, "blockhash": tx["blockhash"], "height": int(tx["blockheight"])}
    return {"tool": TOOL, "collected_utc": _now(), "stamp": stamp.to_dict(), "spends": spends}


# --------------------------------------------------------------------------- #
# verify
# --------------------------------------------------------------------------- #


def _creating_tx(cli: BitcoinCli, utxo: dict, *, txindex: bool):
    """The transaction that created the output: by recorded block hash (no index needed) or via -txindex."""
    if utxo.get("blockhash"):
        return cli.call("getrawtransaction", utxo["txid"], True, utxo["blockhash"]), cli.block_header(utxo["blockhash"])
    if txindex:
        tx = cli.call("getrawtransaction", utxo["txid"], True)
        return tx, (cli.block_header(tx["blockhash"]) if tx.get("blockhash") else None)
    return None, None


def _check_utxo(
    cli: BitcoinCli, tip_height: int, stamp: Stamp, address: str, utxo: dict, *, txindex: bool, spends: dict | None = None
) -> dict:
    """One listed output against the node.

    ``verified``: the node confirms it existed at the snapshot block with the claimed
    amount and address.  ``contradiction``: the node shows something that disagrees
    with the claim.  Neither: the output is gone and this node cannot say more.
    For a spent output, ``unspent_at_snapshot`` becomes True when the spending
    transaction (recorded in the document by finalize) is confirmed after the stamp block.
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
        matches = (
            row["node_amount_sat"] == utxo["amount_sat"]
            and row["node_address"] == address
            and created == utxo["height"]
            and created <= stamp.height
        )
        row["verified"] = matches
        row["contradiction"] = not matches
        if not matches:
            row["problem"] = "amount, address or creation height differs from the snapshot"
        return row
    try:
        tx, header = _creating_tx(cli, utxo, txindex=txindex)
    except RpcError as exc:
        row["status"] = "spent_or_unknown"
        row["note"] = f"cannot fetch the creating transaction: {exc}"
        return row
    if tx is None or header is None:
        row["status"] = "spent_or_unknown"
        row["note"] = "not in the UTXO set now; the snapshot carries no block hash for it and this node has no -txindex"
        return row
    created = int(header["height"])
    row["created_height"] = created
    outputs = tx.get("vout", [])
    out = outputs[utxo["vout"]] if utxo["vout"] < len(outputs) else None
    matches = (
        out is not None
        and to_sat(out["value"]) == utxo["amount_sat"]
        and out.get("scriptPubKey", {}).get("address") == address
        and created == utxo["height"]
        and created <= stamp.height
    )
    if not matches:
        row["status"] = "created_after_snapshot" if created > stamp.height else "mismatch"
        row["contradiction"] = True
        row["problem"] = "the creating transaction does not match the snapshot (amount, address or block)"
        return row
    row["status"] = "spent_after_snapshot"
    row["verified"] = True
    spend = (spends or {}).get(f"{utxo['txid']}:{utxo['vout']}")
    if not spend:
        row["note"] = (
            "existed at the snapshot block and has been spent since; re-run bip322-audit finalize on the owner's node to record the spend and show it was unspent at the snapshot"
        )
        return row
    try:
        spending = cli.call("getrawtransaction", spend["spent_by"], True, spend["blockhash"])
        spend_header = cli.block_header(spend["blockhash"])
    except RpcError as exc:
        row["note"] = f"the document names the spend {spend['spent_by'][:16]}... but the node cannot fetch it: {exc}"
        return row
    spends_it = any(v.get("txid") == utxo["txid"] and int(v.get("vout", -1)) == utxo["vout"] for v in spending.get("vin", []))
    spend_height = int(spend_header["height"])
    if spends_it and int(spend_header.get("confirmations", 0)) > 0 and spend_height > stamp.height:
        row["unspent_at_snapshot"] = True
        row["spent_by"] = spend["spent_by"]
        row["spent_height"] = spend_height
        row["note"] = f"spent at height {spend_height}, after the snapshot block {stamp.height}: it was unspent at the snapshot"
    elif spends_it:
        row["contradiction"] = True
        row["verified"] = False
        row["problem"] = f"spent at height {spend_height}, at or before the snapshot block {stamp.height}"
    else:
        row["note"] = "the document names a spending transaction that does not spend this output"
    return row


def verify_proofs(document: dict, cli: BitcoinCli | None, *, engines=None, txindex: bool = False) -> dict:
    """Verify a proofs document; ``cli=None`` verifies only what needs no node."""
    spends = document.get("spends") or {}
    engines = list(engines or available_engines())
    message = bytes.fromhex(document["message_hex"]) if document.get("message_hex") else document["message"].encode("utf-8")
    if document.get("message_hex") and document.get("message") is not None and message != document["message"].encode("utf-8"):
        raise AuditError("proofs.json is inconsistent: 'message' and 'message_hex' differ")
    stamp = parse_stamp(message)
    report: dict = {
        "tool": TOOL,
        "verified_utc": _now(),
        "engines": engines,
        "proofs": [],
        "stamp": None,
        "node": None,
        "document_problems": [],
    }
    if stamp is not None and document.get("stamp") and Stamp.from_dict(document["stamp"]) != stamp:
        report["document_problems"].append("the stamp recorded in proofs.json differs from the stamp inside the signed message")
    report["spends_recorded_utc"] = document.get("spends_utc")

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
        row = {
            "address": address,
            "bip322": verdict.to_dict(),
            "utxos": [],
            "claimed_sat": proof["total_sat"],
        }
        row["bip322"].pop("message_utf8", None)
        row["bip322"].pop("message_hex", None)
        all_proofs_ok &= verdict.ok
        claimed += proof["total_sat"]
        if cli is not None and stamp is not None:
            for utxo in proof["utxos"]:
                checked = _check_utxo(cli, tip_height, stamp, address, utxo, txindex=txindex, spends=spends)
                row["utxos"].append(checked)
                total_count += 1
                verified_count += int(checked["verified"])
                contradictions += int(checked["contradiction"])
                if checked["status"] == "unspent" and checked["verified"]:
                    unspent += checked["node_amount_sat"]
        else:
            row["utxos"] = [{**u, "status": "not checked (offline)"} for u in proof["utxos"]]
        row["unspent_now_sat"] = sum(
            u.get("node_amount_sat", 0) for u in row["utxos"] if u.get("status") == "unspent" and u.get("verified")
        )
        report["proofs"].append(row)

    unspent_at_snapshot = sum(
        1
        for p in report["proofs"]
        for u in p["utxos"]
        if u.get("status") == "unspent" and u.get("verified") or u.get("unspent_at_snapshot")
    )

    stamp_ok = bool(report["stamp"] and report["stamp"].get("ok"))
    online = cli is not None
    report["totals"] = {
        "claimed_sat": claimed,
        "claimed_btc": btc(claimed),
        "verified_unspent_sat": unspent if online else None,
        "verified_unspent_btc": btc(unspent) if online else None,
    }
    report["summary"] = {
        "proofs_valid": all_proofs_ok,
        "stamp_ok": stamp_ok if online else None,
        "utxos_verified_at_snapshot": f"{verified_count}/{total_count}" if online else None,
        "contradictions": contradictions if online else None,
        "all_utxos_still_unspent": (unspent == claimed) if online else None,
        "utxos_shown_unspent_at_snapshot": f"{unspent_at_snapshot}/{total_count}" if online else None,
    }
    # the proof of control stands when the signatures and the stamp check out, the document is consistent with
    # itself, and the node contradicts nothing; outputs spent since the snapshot are reported, not failures
    report["summary"]["document_consistent"] = not report["document_problems"]
    report["ok"] = all_proofs_ok and (stamp_ok if online else True) and contradictions == 0 and not report["document_problems"]
    return report


def _summary_rows(report: dict) -> list[tuple[str, str]]:
    """The checklist at the end of the text report: one row per thing verify checks."""
    s = report["summary"]
    proofs = report["proofs"]
    utxos = [u for p in proofs for u in p["utxos"]]
    online = report.get("node") is not None
    rows = [("signatures", f"{sum(1 for p in proofs if p['bip322']['state'] == 'valid')}/{len(proofs)} valid")]
    st = report.get("stamp") or {}
    if not online:
        rows.append(("stamp block", "not checked (no node)"))
    elif s["stamp_ok"]:
        rows.append(("stamp block", f"ok, {st.get('confirmations', '?')} confirmations"))
    else:
        rows.append(("stamp block", f"FAILED ({st.get('error') or 'mismatch'})"))
    problems = report.get("document_problems", [])
    rows.append(("document", "consistent" if not problems else f"{len(problems)} problem(s), listed above"))
    if online:
        rows.append(
            (
                "outputs at snapshot",
                f"{s['utxos_verified_at_snapshot']} existed, {s['utxos_shown_unspent_at_snapshot']} shown unspent, "
                f"{s['contradictions']} contradiction" + ("" if s["contradictions"] == 1 else "s"),
            )
        )
        still = sum(1 for u in utxos if u.get("status") == "unspent" and u.get("verified"))
        spent = sum(1 for u in utxos if str(u.get("status", "")).startswith("spent"))
        rows.append(("outputs now", f"{still}/{len(utxos)} still unspent" + (f", {spent} spent since the snapshot" if spent else "")))
    else:
        rows.append(("outputs", "not checked (no node)"))
    return rows


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
        lines.append(
            f"stamp: block {s['height']} {s['hash'][:16]}... {s['time']}  ->  {status}"
            + (f", {st['confirmations']} confirmations" if st.get("confirmations") else "")
        )
    else:
        lines.append("stamp: none")
    lines.append("")
    for p in report["proofs"]:
        v = p["bip322"]
        lines.append(f"{p['address']}  bip322: {v['state'].upper()}")
        for u in p["utxos"]:
            mark = "ok" if u.get("verified") else ("!!" if u.get("contradiction") else "--")
            detail = (
                f"  ({u['problem']})"
                if u.get("problem")
                else (f"  (spent at {u['spent_height']}, unspent at snapshot)" if u.get("unspent_at_snapshot") else "")
            )
            lines.append(f"    [{mark}] {u['txid'][:16]}...:{u['vout']}  {btc(u['amount_sat']):>14} BTC  {u['status']}{detail}")
        lines.append(f"    claimed {btc(p['claimed_sat'])} BTC" + (f", unspent now {btc(p['unspent_now_sat'])} BTC" if node else ""))
    lines.append("")
    t = report["totals"]
    lines.append(
        f"totals: claimed {btc(t['claimed_sat'])} BTC" + (f", verified unspent now {btc(t['verified_unspent_sat'])} BTC" if node else "")
    )
    for problem in report.get("document_problems", []):
        lines.append(f"!! document: {problem}")
    lines.append("")
    lines.append("summary")
    for label, value in _summary_rows(report):
        lines.append(f"  {label:<20} {value}")
    lines.append("RESULT: " + ("OK" if report["ok"] else "FAILED"))
    return "\n".join(lines)


def load_proofs(path: Path) -> dict:
    path = path / "proofs.json" if path.is_dir() else path
    return json.loads(path.read_text())
