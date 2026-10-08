"""Signer health: does every cosigner's signature verify, and does every threshold-sized combination make a valid proof?

Built on the finalizer and the verifier; kept apart from both so that the
verifier module holds the verifier only.
"""

from __future__ import annotations

import copy
import hashlib
import itertools
from collections.abc import Sequence
from math import comb

from embit.hashes import hash160
from embit.networks import NETWORKS
from embit.script import Script

from .core import describe_witness, disassemble
from .psbt import BIP322PSBT, FinalizeError, finalize_psbt, inspect_psbt, signature_from_psbt, signer_report
from .verify import verify_message

__all__ = ["check_signers"]


def check_signers(psbt: BIP322PSBT, *, engines: Sequence[str] = ("btclib",), network: str = "main") -> dict:
    """Exercise every cosigner and every threshold-sized combination of them.

    From one PSBT carrying all partial signatures: verify each signature on its
    own, then for every combination of ``threshold`` signers finalize a copy
    with only those signatures and verify the resulting proof.  ``ok`` means
    every known signer has a valid signature and every combination verifies.
    """
    info = inspect_psbt(psbt, network=network)
    report: dict = {
        "is_bip322": info.is_bip322,
        "problems": info.problems,
        "address": info.address,
        "message_utf8": (info.message or b"").decode("utf-8", errors="replace"),
        "threshold": info.threshold,
        "script": _script_chain(psbt, network),
        "signers": signer_report(psbt, 0),
        "combinations": [],
    }
    valid_signers = [s for s in report["signers"] if s["signature"] == "valid"]
    threshold = info.threshold or 1
    # a broken signature is what this check is for; only structural problems stop the combinations
    structural = [p for p in info.problems if "partial signature" not in p]
    report["structural_problems"] = structural
    if not structural and info.message is not None and info.address:
        for combo in itertools.combinations(valid_signers, threshold):
            selectors = [s["pubkey"] for s in combo]  # full keys: two cosigners may share a master fingerprint
            row = {"signers": [s["fingerprint"] or s["pubkey"][:16] for s in combo], "state": "invalid", "reason": "", "signature": None}
            try:
                trial = copy.deepcopy(psbt)
                finalize_psbt(trial, signers=selectors)
                signature = signature_from_psbt(trial)
                verdict = verify_message(info.address, signature, info.message, engines=engines)
                witness = describe_witness(trial.inputs[0].final_scriptwitness.items)
                row.update(
                    {
                        "state": verdict.state.value,
                        "reason": verdict.reason,
                        "signature": signature,
                        "witness": [{k: v for k, v in w.items() if k in ("index", "role", "sighash", "bytes")} for w in witness],
                    }
                )
            except FinalizeError as exc:
                row["reason"] = str(exc)
            report["combinations"].append(row)
    expected = _n_choose_k(len(report["signers"]), threshold) if report["signers"] else 0
    report["summary"] = {
        "signers_valid": f"{len(valid_signers)}/{len(report['signers'])}",
        "combinations_valid": f"{sum(c['state'] == 'valid' for c in report['combinations'])}/{expected}",
    }
    script_ok = report["script"] is None or report["script"].get("matches_input", True)
    report["ok"] = bool(
        not structural
        and script_ok
        and report["signers"]
        and len(valid_signers) == len(report["signers"])
        and expected > 0
        and all(c["state"] == "valid" for c in report["combinations"])
        and len(report["combinations"]) == expected
    )
    return report


def _script_chain(psbt: BIP322PSBT, network: str) -> dict | None:
    """The script behind input 0 and how it maps back to the scriptPubKey and address."""
    inp = psbt.inputs[0]
    spk = inp.script_pubkey.data if inp.script_pubkey is not None else None
    if spk is None:
        return None
    if inp.witness_script is not None:
        script = inp.witness_script.data
        digest = hashlib.sha256(script).digest()
        derived_spk = b"\x00\x20" + digest
        chain = {"type": "p2wsh", "witness_script_hex": script.hex(), "asm": disassemble(script), "sha256": digest.hex()}
    elif Script(spk).script_type() == "p2wpkh":
        keys = list(inp.bip32_derivations) or list(inp.partial_sigs)
        if not keys:
            return {"type": "p2wpkh", "note": "no public key in the PSBT to rebuild the scriptPubKey from"}
        pub = keys[0].sec()
        derived_spk = b"\x00\x14" + hash160(pub)
        chain = {"type": "p2wpkh", "pubkey": pub.hex(), "hash160": hash160(pub).hex()}
    else:
        return {"type": Script(spk).script_type() or "unknown", "note": "not a script this tool rebuilds"}
    chain.update(
        {
            "scriptPubKey": derived_spk.hex(),
            "address": Script(derived_spk).address(NETWORKS[network]),
            "matches_input": derived_spk == spk,
        }
    )
    return chain


def _n_choose_k(n: int, k: int) -> int:
    return comb(n, k) if 0 <= k <= n else 0
