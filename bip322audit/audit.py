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
from bip322.wallet import Wallet, WalletError

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


def finalize_bundle(directory: Path, *, lenient: bool = False, engines=None, with_descriptor: bool = False) -> dict:
    """Combine and finalize the signed PSBTs of every address; return the proofs document.

    The wallet descriptor (xpubs) is left out unless ``with_descriptor`` is set:
    it would let the auditor derive every address of the wallet, which the
    proofs do not require.
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
        proofs.append({**entry, "signature": signature, "variant": signature[:3]})
    if missing:
        raise AuditError("cannot finalize every address:\n  " + "\n  ".join(missing))
    document = dict(snapshot)
    document.update({"tool": TOOL, "finalized_utc": _now(), "message_hex": message.hex(), "proofs": proofs})
    document.pop("addresses", None)
    if not with_descriptor:
        document["wallet"] = {k: v for k, v in (snapshot.get("wallet") or {}).items() if k != "descriptor"}
        document["wallet"]["descriptor_shared"] = False
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


def load_spends(path: Path) -> dict:
    return json.loads(path.read_text()).get("spends", {})


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
    transaction (from spends.json) is confirmed after the stamp block.
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
            "existed at the snapshot block and has been spent since; add spends.json (bip322-audit spends) to show it was unspent at the snapshot"
        )
        return row
    try:
        spending = cli.call("getrawtransaction", spend["spent_by"], True, spend["blockhash"])
        spend_header = cli.block_header(spend["blockhash"])
    except RpcError as exc:
        row["note"] = f"spends.json names {spend['spent_by'][:16]}... but the node cannot fetch it: {exc}"
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
        row["note"] = "spends.json names a transaction that does not spend this output"
    return row


def verify_proofs(
    document: dict, cli: BitcoinCli | None, *, engines=None, txindex: bool = False, scan: bool = False, spends: dict | None = None
) -> dict:
    """Verify a proofs document; ``cli=None`` verifies only what needs no node.

    ``spends`` (from spends.json) lets spent outputs be shown unspent at the snapshot.
    """
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
    wallet = _document_wallet(document, report)
    report["wallet_descriptor_shared"] = wallet is not None

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
            "branch": proof.get("branch"),
            "index": proof.get("index"),
            "bip322": verdict.to_dict(),
            "utxos": [],
            "claimed_sat": proof["total_sat"],
        }
        row["bip322"].pop("message_utf8", None)
        row["bip322"].pop("message_hex", None)
        row["address_in_wallet"] = _address_in_wallet(wallet, proof)
        if row["address_in_wallet"] is False:
            report["document_problems"].append(
                f"{address} is not branch {proof.get('branch')} index {proof.get('index')} of the declared wallet descriptor"
            )
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

    if cli is not None and scan:
        report["current_holdings"] = _scan_now(cli, document, wallet)
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
    # itself and its wallet, and the node contradicts nothing; outputs spent since the snapshot are reported
    # (and confirmed with --txindex), not failures
    report["summary"]["document_consistent"] = not report["document_problems"]
    report["ok"] = all_proofs_ok and (stamp_ok if online else True) and contradictions == 0 and not report["document_problems"]
    return report


def _document_wallet(document: dict, report: dict) -> Wallet | None:
    """The wallet declared in proofs.json, on the document's chain; None when it cannot be built."""
    descriptor = (document.get("wallet") or {}).get("descriptor")
    if not descriptor:
        return None
    network = {"main": "main", "test": "test", "regtest": "regtest", "signet": "signet"}.get(document.get("chain") or "")
    try:
        return Wallet.from_descriptor(descriptor, network=network)
    except WalletError as exc:
        report["document_problems"].append(f"declared wallet descriptor is unusable: {exc}")
        return None


def _address_in_wallet(wallet: Wallet | None, proof: dict) -> bool | None:
    """Does the proof's address sit at the stated branch/index of the declared wallet?"""
    if wallet is None or proof.get("index") is None:
        return None
    try:
        derived = wallet.derive(int(proof["index"]), int(proof.get("branch") or 0))
    except WalletError:
        return False
    return derived.address == proof["address"] or _same_script(wallet, derived.script_pubkey, proof["address"])


def _same_script(wallet: Wallet, script_pubkey: bytes, address: str) -> bool:
    from embit.script import address_to_scriptpubkey

    try:
        return address_to_scriptpubkey(address).data == script_pubkey
    except Exception:  # noqa: BLE001
        return False


def _scan_now(cli: BitcoinCli, document: dict, wallet: Wallet | None, scan_range: int = 1000) -> dict:
    """What the wallet holds *now*: every funded address of the declared descriptor, proven or not.

    This is the completeness check an auditor wants: coins of the wallet that no
    proof covers show up as ``unproven``.  Falls back to the proven addresses
    only when the document declares no usable wallet.
    """
    if wallet is not None:
        descriptors = [{"desc": d, "range": [0, scan_range]} for d in wallet.core_descriptors()]
    else:
        descriptors = [{"desc": f"addr({p['address']})"} for p in document["proofs"]]
    result = cli.call("scantxoutset", "start", descriptors)
    if not result or not result.get("success"):
        raise AuditError("scantxoutset did not succeed (another scan running?)")
    from embit.networks import NETWORKS
    from embit.script import Script

    by_address: dict[str, int] = {}
    for u in result.get("unspents", []):
        try:
            address = Script(bytes.fromhex(u["scriptPubKey"])).address(NETWORKS[wallet.network if wallet else "main"])
        except Exception:  # noqa: BLE001
            continue
        by_address[address] = by_address.get(address, 0) + to_sat(u["amount"])
    proven = {p["address"] for p in document["proofs"]}
    unproven = {a: v for a, v in by_address.items() if a not in proven}
    return {
        "height": int(result["height"]),
        "bestblock": result["bestblock"],
        "scanned": "wallet descriptor" if wallet is not None else "proven addresses only",
        "by_address_sat": by_address,
        "total_sat": sum(by_address.values()),
        "unproven": unproven,
        "unproven_sat": sum(unproven.values()),
    }


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
        lines.append(f"{p['address']}  (branch {p['branch']}, index {p['index']})  bip322: {v['state'].upper()}")
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
    if report.get("current_holdings"):
        h = report["current_holdings"]
        lines.append(
            f"current holdings at height {h['height']} ({h['scanned']}): {btc(h['total_sat'])} BTC across {len(h['by_address_sat'])} address(es)"
        )
        if h.get("unproven"):
            lines.append(f"  !! {btc(h['unproven_sat'])} BTC at {len(h['unproven'])} funded address(es) not covered by any proof:")
            for a, v in h["unproven"].items():
                lines.append(f"     {a}  {btc(v)} BTC")
    for problem in report.get("document_problems", []):
        lines.append(f"!! document: {problem}")
    if report.get("wallet_descriptor_shared") is False:
        lines.append(
            "note: the wallet descriptor is not shared; address membership not checked and --scan covers the proven addresses only"
        )
    s = report["summary"]
    lines.append(
        f"proofs valid: {s['proofs_valid']}; stamp ok: {s['stamp_ok']}; document consistent: {s['document_consistent']}; "
        f"outputs existed at snapshot: {s['utxos_verified_at_snapshot']}; shown unspent at snapshot: {s['utxos_shown_unspent_at_snapshot']}; "
        f"contradictions: {s['contradictions']}; all still unspent: {s['all_utxos_still_unspent']}"
    )
    lines.append("RESULT: " + ("OK" if report["ok"] else "FAILED"))
    return "\n".join(lines)


def load_proofs(path: Path) -> dict:
    path = path / "proofs.json" if path.is_dir() else path
    return json.loads(path.read_text())
