"""What the commands print: results as JSON-ready dicts and as text.

No argument parsing and no I/O here, so that other programs and documents can
produce exactly the output of ``verifymessage``, ``validateaddress``,
``decodesignature`` and ``checksigners``.
"""

from __future__ import annotations

import hashlib
import json

from embit.descriptor.checksum import add_checksum
from embit.networks import NETWORKS
from embit.script import Script

from .core import (
    PREFIX_FULL,
    PREFIX_POF,
    PREFIX_SIMPLE,
    SignatureFormatError,
    decode_signature,
    describe_witness,
    is_native_segwit,
    parse_transaction,
    parse_witness,
)
from .psbt import input_finalized, parse_psbt
from .verify import is_script_hex, script_pubkey_from_address
from .wallet import DerivedAddress, Wallet

__all__ = [
    "address_info",
    "decode_signature_report",
    "describe_address",
    "format_address_text",
    "format_decode_text",
    "format_signers_text",
    "format_verify_text",
]


def address_info(wallet: Wallet, derived: DerivedAddress) -> dict:
    """What ``getaddressinfo`` prints for an address of the wallet: its script, keys, key paths and descriptors."""
    concrete = wallet.descriptor.derive(derived.index, branch_index=derived.branch if wallet.num_branches > 1 else None)
    info = {
        "address": derived.address,
        "scriptPubKey": derived.script_pubkey.hex(),
        "ismine": True,
        "iswitness": True,
        "witness_version": 0,
        "witness_program": derived.script_pubkey[2:].hex(),
    }
    if derived.witness_script is not None:
        info.update(
            {
                "script": "multisig",
                "hex": derived.witness_script.hex(),
                "sigsrequired": derived.threshold,
                "pubkeys": [pk.hex() for pk in derived.pubkeys],
            }
        )
    else:
        info["pubkey"] = derived.pubkeys[0].hex()
    info.update(
        {
            # same order as the witness script, so the lists line up
            "hdkeypaths": {pk.hex(): derived.derivation_paths()[pk.hex()] for pk in derived.pubkeys},
            "branch": derived.branch,
            "index": derived.index,
            "desc": add_checksum(concrete.to_string()),
            "wallet_desc": wallet.to_descriptor(),
        }
    )
    return info


def format_verify_text(verdict: dict) -> str:
    """The text ``verifymessage`` prints for a verdict: the state, one line per engine, then the tool.

    ``verdict`` is ``VerifyResult.to_dict()`` (or that dict read back from
    JSON).  Only ``state`` is required; ``reason``, ``engines`` (each with
    ``engine``, ``ok``, ``error``, ``version``, ``bindings``), ``tool`` and
    ``spec`` are used when present.  Returns the lines joined by newlines,
    without a final newline.

    Public so that documents quoting the command can show its exact output;
    the last line names the tool and the specification version, so that the
    quoted output says by what it was produced.
    """
    state = str(verdict["state"]).upper()
    reason = verdict.get("reason") or ""
    runs = verdict.get("engines") or []
    if state == "VALID":
        first = state if reason == "valid" else f"{state} ({reason})"
    elif state == "INVALID" and runs:
        first = state  # the engine lines below say why
    else:
        first = f"{state}: {reason}"
    lines = [first]
    for run in runs:
        version = run.get("version") or "?"
        engine = run.get("engine", "")
        if engine == "btclib-required":
            label = f"btclib {version}, consensus + BIP-322 required rules"
        elif engine == "kernel":
            label = f"Bitcoin Core kernel {version} ({run.get('bindings') or 'py-bitcoinkernel ?'}), consensus rules"
        elif engine == "btclib-upgradeable":
            label = f"btclib {version}, + upgradeable rules"
        else:
            label = engine
        lines.append(f"  [{label}] {'ok' if run.get('ok') else 'FAIL: ' + str(run.get('error'))}")
    if verdict.get("tool"):
        lines.append(f"  {verdict['tool']}" + (f", {verdict['spec']}" if verdict.get("spec") else ""))
    return "\n".join(lines)


def format_signers_text(report: dict) -> str:
    """The text ``checksigners`` prints for ``signers.check_signers``'s report: the script chain, every signer, every combination."""
    lines = [f"address   {report['address']}", f"message   {report['message_utf8']!r}", f"threshold {report['threshold']}", ""]
    lines += _script_chain_lines(report.get("script") or {})
    for s in report["signers"]:
        lines.append(f"  signer {s['fingerprint'] or '?'}  {s['path'] or ''}  {s['pubkey'][:16]}...  {s['signature']}")
    lines.append("")
    for c in report["combinations"]:
        used = ", ".join(f"#{w['index']} {w['role'].split(' (')[0]}" for w in c.get("witness", []) if "signature" in w["role"])
        lines.append(
            f"  {'+'.join(c['signers']):<28} {c['state'].upper():<12} {c['reason'] if c['state'] != 'valid' else ('witness: ' + used)}".rstrip()
        )
    for p in report["problems"]:
        lines.append(f"  problem: {p}")
    summary = report["summary"]
    lines.append("")
    lines.append(f"signers valid: {summary['signers_valid']}; combinations valid: {summary['combinations_valid']}")
    lines.append("RESULT: " + ("OK" if report["ok"] else "FAILED"))
    return "\n".join(lines)


def _script_chain_lines(sc: dict) -> list[str]:
    """How the script (or key) behind the input hashes to the scriptPubKey and the address."""
    lines = []
    if sc.get("asm"):
        lines.append(f"  script    {sc['asm']}")
        lines.append(f"  sha256    {sc['sha256']}")
    elif sc.get("pubkey"):
        lines.append(f"  pubkey    {sc['pubkey']}  hash160 {sc['hash160']}")
    if sc.get("scriptPubKey"):
        lines.append(f"  scriptPubKey {sc['scriptPubKey']}")
        lines.append(f"  address   {sc['address']}  ({'matches the input' if sc['matches_input'] else 'DOES NOT MATCH the input'})")
        lines.append("")
    return lines


def describe_address(address: str, network: str = "main") -> dict:
    """An address opened into the scriptPubKey it encodes, and what kind of lock that is.

    This is the whole relation between an address and the coins: an address is
    a scriptPubKey, checksummed and encoded; an output is locked to a
    scriptPubKey; a BIP-322 proof is made for a scriptPubKey.  Given the hex
    of a scriptPubKey instead, the address is the one that encodes it on
    ``network``.
    """
    spk = script_pubkey_from_address(address)
    kind = Script(spk).script_type()
    if is_script_hex(address):
        try:
            shown = Script(spk).address(NETWORKS[network])
        except Exception as exc:  # noqa: BLE001 - embit raises ValueError for a script without an address form
            raise SignatureFormatError(f"scriptPubKey {spk.hex()} has no address form") from exc
    else:
        shown = address.strip()
    out = {"address": shown, "scriptPubKey": spk.hex(), "bytes": len(spk), "type": kind}
    if is_native_segwit(spk):
        version = 0 if spk[0] == 0 else spk[0] - 0x50
        program = spk[2:]
        out.update({"witness_version": version, "witness_program": program.hex()})
        if version == 0 and len(program) == 32:
            out["type"], out["program_is"] = "p2wsh", "the sha256 of the witness script"
        elif version == 0 and len(program) == 20:
            out["type"], out["program_is"] = "p2wpkh", "the hash160 of the public key"
        elif version == 1 and len(program) == 32:
            out["type"], out["program_is"] = "p2tr", "the taproot output key"
    return out


def format_address_text(info: dict) -> str:
    """The text ``validateaddress`` prints: the address, the scriptPubKey it is, and what that script is.

    ``info`` is the dict ``verify.describe_address`` returns.  ``address``,
    ``scriptPubKey``, ``type`` and ``bytes`` are required (KeyError otherwise);
    ``witness_version`` with ``witness_program``, and ``program_is``, are used
    when present.  Returns three lines joined by newlines, without a final newline.
    """
    names = {"p2wsh": "P2WSH", "p2wpkh": "P2WPKH", "p2tr": "P2TR (taproot)", "p2pkh": "P2PKH (legacy)", "p2sh": "P2SH (legacy)"}
    lines = [f"address       {info['address']}", f"scriptPubKey  {info['scriptPubKey']}"]
    kind = names.get(info["type"], info["type"])
    if "witness_version" in info:
        detail = f"{info['bytes']} bytes: witness v{info['witness_version']}, {len(info['witness_program']) // 2}-byte program"
        if info.get("program_is"):
            detail += f" = {info['program_is']}"
        lines.append(f"type          {kind}, {detail}")
    else:
        lines.append(f"type          {kind}, {info['bytes']} bytes")
    return "\n".join(lines)


def decode_signature_report(text: str, network_name: str = "main") -> dict:
    """A proof string opened into its parts (what ``decodesignature`` prints as JSON).

    Every witness script comes with its sha256, the P2WSH scriptPubKey that
    hash makes, and that scriptPubKey's address; every public key with its
    hash160, the P2WPKH scriptPubKey and address.  That is the derivation from
    the keys in the proof to the script the coins are locked to.
    """
    decoded = decode_signature(text)
    out: dict = {"variant": decoded.variant, "prefixed": decoded.prefixed, "payload_bytes": len(decoded.payload)}
    network = NETWORKS[network_name]

    def with_address(items) -> list[dict]:
        return _with_addresses(describe_witness(items), network)

    if decoded.variant == PREFIX_SIMPLE:
        out["witness"] = with_address(parse_witness(decoded.payload))
        out["note"] = (
            "the simple variant is the witness stack of to_sign input 0; to_sign itself is implied (version 0, locktime 0, sequence 0)"
        )
    elif decoded.variant == PREFIX_FULL:
        tx = parse_transaction(decoded.payload)
        out["to_sign"] = {
            "txid": tx.txid().hex(),
            "version": tx.version,
            "locktime": tx.locktime,
            "inputs": [
                {
                    "txid": vin.txid.hex(),
                    "vout": vin.vout,
                    "sequence": vin.sequence,
                    "scriptSig": vin.script_sig.data.hex(),
                    "witness": with_address(vin.witness.items),
                }
                for vin in tx.vin
            ],
            "outputs": [{"value": o.value, "scriptPubKey": o.script_pubkey.data.hex()} for o in tx.vout],
        }
    elif decoded.variant == PREFIX_POF:
        psbt = parse_psbt(decoded.payload)
        tx = psbt.tx
        out["psbt"] = {
            "inputs": [
                {
                    "txid": inp.txid.hex(),
                    "vout": inp.vout,
                    "finalized": input_finalized(inp),
                    "witness": with_address(inp.final_scriptwitness.items) if inp.final_scriptwitness else [],
                }
                for inp in psbt.inputs
            ],
            "outputs": [{"value": o.value, "scriptPubKey": o.script_pubkey.data.hex()} for o in tx.vout],
            "message_utf8": psbt.message.decode("utf-8", errors="replace") if psbt.message else None,
        }
    else:
        out["note"] = "65-byte payload: a legacy BIP-137 signature (recoverable ECDSA), P2PKH only"
        out["hex"] = decoded.payload.hex()
    return out


def _with_addresses(elements: list[dict], network: dict) -> list[dict]:
    """Add to each witness script and public key the scriptPubKey it hashes to and that scriptPubKey's address."""
    for e in elements:
        if "p2wsh_scriptPubKey" in e:
            e["p2wsh_address"] = Script(bytes.fromhex(e["p2wsh_scriptPubKey"])).address(network)
        elif e.get("role") == "compressed public key":
            digest = hashlib.new("ripemd160", hashlib.sha256(bytes.fromhex(e["hex"])).digest()).digest()
            e["hash160"] = digest.hex()
            e["p2wpkh_scriptPubKey"] = (b"\x00\x14" + digest).hex()
            e["p2wpkh_address"] = Script(bytes.fromhex(e["p2wpkh_scriptPubKey"])).address(network)
    return elements


def format_decode_text(out: dict) -> str:
    """The text ``decodesignature --text`` prints: each witness item with what it is, and for a script or key the lock it names."""

    def items(elements: list[dict]) -> list[str]:
        return [line for e in elements for line in _witness_item_lines(e)]

    if out["variant"] == PREFIX_SIMPLE:
        return "\n".join([f"smp: the witness stack of to_sign input 0, {len(out['witness'])} items", *items(out["witness"])])
    if out["variant"] == PREFIX_FULL:
        lines = [f"ful: to_sign {out['to_sign']['txid']}, version {out['to_sign']['version']}, {len(out['to_sign']['inputs'])} input(s)"]
        for i, vin in enumerate(out["to_sign"]["inputs"]):
            lines.append(f"input {i}: {vin['txid']}:{vin['vout']}")
            lines.extend("  " + line for line in items(vin["witness"]))
        return "\n".join(lines)
    return json.dumps(out, indent=2)


def _witness_item_lines(e: dict) -> list[str]:
    """One witness item: what it is, its content, and for a script or key the lock it names."""
    head = f"[{e['index']}] {e['role']}"
    if "sighash" in e:
        head += f", sighash {e['sighash']}" + (" (ALL)" if e["sighash"] == 1 else "")
    if e.get("bytes"):
        head += f", {e['bytes']} bytes"
    lines = [head]
    if e.get("asm"):
        lines.append(f"    {e['asm']}")
    elif e.get("hex"):
        lines.append(f"    {e['hex']}")
    if "sha256" in e:
        lines.append(f"    sha256        {e['sha256']}")
        lines.append(f"    scriptPubKey  {e['p2wsh_scriptPubKey']}  (P2WSH: OP_0 <sha256 of the witness script>)")
        if e.get("p2wsh_address"):
            lines.append(f"    address       {e['p2wsh_address']}  (the scriptPubKey, bech32 encoded)")
    if "hash160" in e:
        lines.append(f"    hash160       {e['hash160']}")
        lines.append(f"    scriptPubKey  {e['p2wpkh_scriptPubKey']}  (P2WPKH: OP_0 <hash160 of the key>)")
        lines.append(f"    address       {e['p2wpkh_address']}  (the scriptPubKey, bech32 encoded)")
    return lines
