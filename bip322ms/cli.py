"""Command line interface for bip322ms."""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

from embit.networks import NETWORKS

from . import __doc__ as _pkgdoc  # noqa: F401
from .coldcard import lint_message_for_coldcard
from .core import BIP322Error, build_to_spend
from .engines import available_engines, engine_labels, engine_versions
from .psbt import (
    BIP322PSBT,
    FinalizeError,
    choose_variant,
    combine_psbts,
    create_psbt,
    extract_tx,
    finalize_psbt,
    inspect_psbt,
    parse_psbt,
    sign_psbt,
    signature_from_psbt,
)
from .verify import State, verify_message
from .wallet import MultisigWallet, WalletError, cosigner_from_text, wallet_from_cosigners, wallet_from_file


class CLIError(Exception):
    pass


def _read_message(args) -> bytes:
    if getattr(args, "message_file", None):
        return Path(args.message_file).read_bytes()
    if getattr(args, "message", None) is None:
        raise CLIError("provide --message or --message-file")
    return args.message.encode("utf-8")


def _network(args) -> str | None:
    return getattr(args, "network", None) or getattr(args, "global_network", None)


def _load_wallet(args) -> MultisigWallet:
    """Wallet options may be given before or after the subcommand."""
    descriptor = getattr(args, "descriptor", None) or getattr(args, "global_descriptor", None)
    wallet = getattr(args, "wallet", None) or getattr(args, "global_wallet", None)
    if descriptor:
        return MultisigWallet.from_descriptor(descriptor, network=_network(args) or "main")
    if wallet:
        return wallet_from_file(wallet, network=_network(args))
    raise CLIError("provide --wallet FILE (a wsh(sortedmulti(...)) descriptor) or --descriptor")


def _read_psbt(path: str) -> BIP322PSBT:
    data = Path(path).read_bytes() if path != "-" else sys.stdin.buffer.read()
    return parse_psbt(data)


def _write_psbt(psbt: BIP322PSBT, path: str | None, binary: bool = False) -> None:
    if path is None or path == "-":
        print(psbt.to_string())
        return
    out = Path(path)
    if binary or out.suffix.lower() == ".psbt" and binary:
        out.write_bytes(psbt.serialize())
    else:
        out.write_text(psbt.to_string() + "\n")


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #


def cmd_wallet(args) -> int:
    wallet = _load_wallet(args)
    print(json.dumps(wallet.describe(), indent=2))
    return 0


def cmd_deriveaddresses(args) -> int:
    """Like Bitcoin Core's deriveaddresses: addresses for an explicit index range."""
    wallet = _load_wallet(args)
    if args.index is not None:
        start = end = args.index
    else:
        start, end = args.range
    if start < 0 or end < start:
        raise CLIError("range must be START END with 0 <= START <= END")
    branch = 1 if args.change else 0
    rows = [wallet.derive(i, branch) for i in range(start, end + 1)]
    if args.json:
        print(json.dumps([{"branch": d.branch, "index": d.index, "address": d.address} for d in rows], indent=2))
    else:
        for d in rows:
            print(d.address)
    return 0


def _address_info(wallet: MultisigWallet, derived) -> dict:
    from embit.descriptor.checksum import add_checksum

    concrete = wallet.descriptor.derive(derived.index, branch_index=derived.branch if wallet.num_branches > 1 else None)
    return {
        "address": derived.address,
        "scriptPubKey": derived.script_pubkey.hex(),
        "ismine": True,
        "iswitness": True,
        "witness_version": 0,
        "witness_program": derived.script_pubkey[2:].hex(),
        "script": "multisig",
        "hex": derived.witness_script.hex(),
        "sigsrequired": derived.threshold,
        "pubkeys": [pk.hex() for pk in derived.pubkeys],
        # same order as the witness script, so the two lists line up
        "hdkeypaths": {pk.hex(): derived.derivation_paths()[pk.hex()] for pk in derived.pubkeys},
        "branch": derived.branch,
        "index": derived.index,
        "desc": add_checksum(concrete.to_string()),
        "wallet_desc": wallet.to_descriptor(),
    }


def cmd_getaddressinfo(args) -> int:
    """Like Bitcoin Core's getaddressinfo: is this address ours, and how is it built?"""
    wallet = _load_wallet(args)
    derived = wallet.find_address(args.address, max_index=args.max_index)
    if derived is None:
        print(json.dumps({"address": args.address, "ismine": False,
                          "reason": f"not found in the first {args.max_index + 1} receive/change indexes"}, indent=2))
        return 1
    print(json.dumps(_address_info(wallet, derived), indent=2))
    return 0


def cmd_create(args) -> int:
    wallet = _load_wallet(args)
    message = _read_message(args)
    if args.address:
        derived = wallet.find_address(args.address, max_index=args.max_index)
        if derived is None:
            raise CLIError(f"address {args.address} not found in the first {args.max_index} indexes of the wallet")
    else:
        derived = wallet.derive(args.index, 1 if args.change else 0)
    psbt = create_psbt(
        derived,
        message,
        xpubs=None if args.no_xpubs else wallet.global_xpubs(),
        utxo_mode=args.utxo,
        psbt_version=2 if args.psbt_v2 else None,
    )
    lint = lint_message_for_coldcard(message)
    summary = {
        "address": derived.address,
        "branch": derived.branch,
        "index": derived.index,
        "policy": f"{derived.threshold} of {len(derived.pubkeys)}",
        "message_utf8": message.decode("utf-8", errors="replace"),
        "message_bytes": len(message),
        "to_spend_txid": build_to_spend(message, derived.script_pubkey).txid().hex(),
        "to_sign_txid": psbt.tx.txid().hex(),
        "coldcard_lint": lint or "ok",
        "derivations": derived.derivation_paths(),
    }
    _write_psbt(psbt, args.output, binary=args.binary)
    print(json.dumps(summary, indent=2), file=sys.stderr)
    if lint and args.strict_coldcard:
        raise CLIError("message would be refused by a Coldcard: " + "; ".join(lint))
    return 0


def cmd_inspect(args) -> int:
    psbt = _read_psbt(args.psbt)
    info = inspect_psbt(psbt, network=_network(args) or "main")
    out = {
        "is_bip322": info.is_bip322,
        "problems": info.problems,
        "message_utf8": info.message.decode("utf-8", errors="replace") if info.message is not None else None,
        "address": info.address,
        "script_pubkey": info.script_pubkey.hex() if info.script_pubkey else None,
        "to_spend_txid": info.to_spend_txid,
        "to_sign_txid": info.to_sign_txid,
        "tx_version": info.tx_version,
        "locktime": info.locktime,
        "sequence": info.sequence,
        "inputs": info.num_inputs,
        "threshold": info.threshold,
        "pubkeys": info.pubkeys,
        "partial_sigs": info.partial_sigs,
        "finalized": info.finalized,
    }
    print(json.dumps(out, indent=2))
    return 0 if info.is_bip322 else 1


def cmd_sign(args) -> int:
    psbt = _read_psbt(args.psbt)
    info = inspect_psbt(psbt, network=_network(args) or "main")
    if not info.is_bip322 and not args.force:
        raise CLIError("refusing to sign: not a well-formed BIP-322 PSBT: " + "; ".join(info.problems))
    total = 0
    for key in args.key:
        total += sign_psbt(psbt, _read_signer_key(key))
    if total == 0:
        raise CLIError("no signatures added (key does not match any input derivation)")
    _write_psbt(psbt, args.output, binary=args.binary)
    print(f"added {total} signature(s)", file=sys.stderr)
    return 0


def _read_signer_key(text: str) -> str:
    """``-k`` accepts a key string, a bip322ms keygen JSON file, or a file holding the key."""
    if not Path(text).is_file():
        return text
    content = Path(text).read_text(encoding="utf-8").strip()
    if content.startswith("{"):
        data = json.loads(content)
        if not data.get("xprv_expression"):
            raise CLIError(f"{text}: JSON has no xprv_expression (public-only cosigner file?)")
        return data["xprv_expression"]
    return content


def cmd_makewallet(args) -> int:
    cosigners = [cosigner_from_text(k) for k in args.keys]
    fps = [c.fingerprint_hex for c in cosigners]
    if len(set(fps)) != len(fps):
        raise CLIError("duplicate cosigner fingerprints: " + ", ".join(fps))
    network = _network(args) or "main"
    name = args.name or f"bip322ms-{args.threshold}of{len(cosigners)}"
    wallet = wallet_from_cosigners(args.threshold, cosigners, network=network, name=name)
    text = wallet.to_descriptor() + "\n"
    if args.output and args.output != "-":
        Path(args.output).write_text(text)
    else:
        sys.stdout.write(text)
    info = wallet.describe()
    info["first_address"] = wallet.derive(0).address
    print(json.dumps({k: info[k] for k in ("name", "network", "policy", "script", "first_address")}, indent=2), file=sys.stderr)
    return 0


def cmd_combine(args) -> int:
    psbts = [_read_psbt(p) for p in args.psbts]
    combined = combine_psbts(psbts)
    _write_psbt(combined, args.output, binary=args.binary)
    info = inspect_psbt(combined, network=_network(args) or "main")
    print(f"combined {len(psbts)} PSBT(s); input 0 now has {len(info.partial_sigs)} partial signature(s)", file=sys.stderr)
    return 0


def cmd_finalize(args) -> int:
    """BIP-174 input finalizer: check each partial signature, assemble the witness, encode.

    Verification of the resulting proof is verifymessage's job, not this command's.
    """
    psbt = _read_psbt(args.psbt)
    info = inspect_psbt(psbt, network=_network(args) or "main")
    if not info.is_bip322:
        raise CLIError("not a well-formed BIP-322 PSBT: " + "; ".join(info.problems))
    if not info.finalized:
        finalize_psbt(psbt, strict=not args.lenient)
    signature = signature_from_psbt(psbt, args.variant)
    if args.output_psbt:
        _write_psbt(psbt, args.output_psbt, binary=args.binary)
    if args.signature_file:
        Path(args.signature_file).write_text(signature + "\n")
    out = {
        "address": info.address,
        "message_utf8": info.message.decode("utf-8", errors="replace"),
        "variant": signature[:3],
        "signature": signature,
        "to_sign_hex": extract_tx(psbt).serialize().hex(),
    }
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print(signature)
    return 0


def cmd_verify(args) -> int:
    address = args.address or args.pos_address
    if not address:
        raise CLIError("provide an address (positional or --address)")
    if args.pos_message is not None and args.message is None and not args.message_file:
        args.message = args.pos_message
    message = _read_message(args)
    signature = args.signature or args.pos_signature
    if args.signature_file:
        signature = Path(args.signature_file).read_text().strip()
    if signature is None:
        raise CLIError("provide a signature (positional, --signature or --signature-file)")
    engines = args.engines.split(",") if args.engines else available_engines()
    result = verify_message(
        address,
        signature,
        message,
        engines=engines,
        allow_unprefixed=not args.require_prefix,
        allow_legacy=not args.no_legacy,
    )
    if args.json:
        out = result.to_dict()
        out["engine_versions"] = engine_versions()
        print(json.dumps(out, indent=2))
    else:
        state = result.state.value.upper()
        if result.state is State.VALID:
            print(state if result.reason == "valid" else f"{state} ({result.reason})")
        elif result.state is State.INVALID and result.engines:
            print(state)  # the engine lines below say why
        else:
            print(f"{state}: {result.reason}")
        names = engine_labels()
        labels = {
            "btclib-required": f"{names['btclib']}, consensus + BIP-322 required rules",
            "kernel": f"{names.get('kernel', 'Bitcoin Core kernel')}, consensus rules",
            "btclib-upgradeable": f"{names['btclib']}, + upgradeable rules",
        }
        for run in result.engines:
            print(f"  [{labels.get(run.engine, run.engine)}] {'ok' if run.ok else 'FAIL: ' + str(run.error)}")
    return 0 if result.ok else 1


def cmd_lint(args) -> int:
    message = _read_message(args)
    problems = lint_message_for_coldcard(message)
    if problems:
        print("Coldcard would refuse this message:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("ok: message is acceptable to a Coldcard")
    return 0


def cmd_keygen(args) -> int:
    """Generate a cosigner key set for tests and walkthroughs (never for real funds)."""
    import hashlib
    import os

    from embit.bip32 import HDKey

    from .wallet import path_from_str, path_to_str

    if args.seed is not None:
        seed = hashlib.sha512(("bip322ms-keygen:" + args.seed).encode("utf-8")).digest()
    else:
        seed = os.urandom(64)
    net = NETWORKS[_network(args) or "main"]
    master = HDKey.from_seed(seed, version=net["xprv"])
    origin = path_to_str(path_from_str(args.origin), prefix="")[1:]
    account = master.derive("m/" + origin)
    fp = master.my_fingerprint.hex()
    xprv = account.to_base58(net["xprv"])
    xpub = account.to_public().to_base58(net["xpub"])
    out = {
        "label": args.label,
        "warning": "test keys only; anyone with the seed text can derive them",
        "fingerprint": fp,
        "origin": "m/" + origin,
        "xpub_expression": f"[{fp}/{origin}]{xpub}/<0;1>/*",
        "xprv_expression": f"[{fp}/{origin}]{xprv}/<0;1>/*",
    }
    print(json.dumps(out, indent=2))
    return 0


def cmd_engines(args) -> int:  # noqa: ARG001
    print(json.dumps({"engines": available_engines(), "versions": engine_versions()}, indent=2))
    return 0


# --------------------------------------------------------------------------- #
# argument parsing
# --------------------------------------------------------------------------- #


def _add_wallet_args(p: argparse.ArgumentParser) -> None:
    g = p.add_mutually_exclusive_group()
    g.add_argument("--wallet", "-w", help="file holding the wallet's wsh(sortedmulti(...)) descriptor")
    g.add_argument("--descriptor", "-d", help="wsh(sortedmulti(...)) descriptor text")
    p.add_argument("--network", choices=sorted(NETWORKS), default=None, help="address network (default: main)")


def _add_message_args(p: argparse.ArgumentParser) -> None:
    g = p.add_mutually_exclusive_group()
    g.add_argument("--message", "-m", help="message text (UTF-8)")
    g.add_argument("--message-file", help="file whose exact bytes are the message")


def _add_output_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--output", "-o", help="output PSBT file (base64; default stdout)")
    p.add_argument("--binary", action="store_true", help="write the PSBT in binary instead of base64")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bip322ms", description="BIP-322 message signing for P2WSH multisig quorums")
    # wallet options are accepted here (before the subcommand) as well as after it
    parser.add_argument("--wallet", "-w", dest="global_wallet", metavar="FILE", help="file holding the wallet's wsh(sortedmulti(...)) descriptor")
    parser.add_argument("--descriptor", "-d", dest="global_descriptor", metavar="DESC", help="wsh(sortedmulti(...)) descriptor text")
    parser.add_argument("--network", dest="global_network", choices=sorted(NETWORKS), default=None, help="address network (default: main)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("wallet", help="show wallet policy, cosigners and descriptor")
    _add_wallet_args(p)
    p.set_defaults(func=cmd_wallet)

    p = sub.add_parser("deriveaddresses", help="addresses for an index range (like Bitcoin Core's deriveaddresses)")
    _add_wallet_args(p)
    g = p.add_mutually_exclusive_group()
    g.add_argument("--range", nargs=2, type=int, metavar=("START", "END"), default=[0, 0], help="inclusive index range (default 0 0)")
    g.add_argument("--index", type=int, help="a single index")
    p.add_argument("--change", action="store_true", help="change branch instead of receive")
    p.add_argument("--json", action="store_true", help="objects with branch/index instead of bare addresses")
    p.set_defaults(func=cmd_deriveaddresses)

    p = sub.add_parser("getaddressinfo", help="look an address up in the wallet (like Bitcoin Core's getaddressinfo)")
    _add_wallet_args(p)
    p.add_argument("address")
    p.add_argument("--max-index", type=int, default=500, help="how far to search each branch")
    p.set_defaults(func=cmd_getaddressinfo)

    p = sub.add_parser("makewallet", help="write a checksummed wsh(sortedmulti(...)) descriptor from cosigner keys")
    p.add_argument("keys", nargs="+", help="cosigners: keygen JSON files or [fp/path]xpub expressions")
    p.add_argument("--threshold", "-t", type=int, required=True, help="signatures required (the k in k-of-n)")
    p.add_argument("--name", help="wallet name (default bip322ms-<k>of<n>)")
    p.add_argument("--network", choices=sorted(NETWORKS), default=None)
    p.add_argument("--output", "-o", help="output file (default stdout)")
    p.set_defaults(func=cmd_makewallet)

    p = sub.add_parser("createpsbt", help="create the BIP-322 to_sign PSBT for a message and a wallet address")
    _add_wallet_args(p)
    _add_message_args(p)
    p.add_argument("--address", "-a", help="the wallet address to sign for (searched in the wallet)")
    p.add_argument("--index", type=int, default=0, help="derivation index (when no --address)")
    p.add_argument("--change", action="store_true", help="use the change branch (when no --address)")
    p.add_argument("--max-index", type=int, default=500, help="how far to search for --address")
    p.add_argument("--utxo", choices=["witness", "non_witness", "both"], default="witness", help="which UTXO field(s) to include for input 0")
    p.add_argument("--no-xpubs", action="store_true", help="omit PSBT_GLOBAL_XPUB entries")
    p.add_argument("--psbt-v2", action="store_true", help="emit a BIP-370 (v2) PSBT")
    p.add_argument("--strict-coldcard", action="store_true", help="fail if the message would be refused by a Coldcard")
    _add_output_args(p)
    p.set_defaults(func=cmd_create)

    p = sub.add_parser("analyzepsbt", help="report whether a PSBT is a BIP-322 PSBT, its state and what is missing")
    p.add_argument("psbt", help="PSBT file (base64 or binary) or - for stdin")
    p.add_argument("--network", choices=sorted(NETWORKS), default=None)
    p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("signpsbt", help="add signatures with software keys (tests / non-hardware cosigners)")
    p.add_argument("psbt")
    p.add_argument("--key", "-k", action="append", required=True, help="xprv, [fp/path]xprv expression or WIF (repeatable)")
    p.add_argument("--network", choices=sorted(NETWORKS), default=None)
    p.add_argument("--force", action="store_true", help="sign even if the PSBT fails the BIP-322 checks")
    _add_output_args(p)
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("combinepsbt", help="merge partially signed PSBTs from the cosigners")
    p.add_argument("psbts", nargs="+")
    p.add_argument("--network", choices=sorted(NETWORKS), default=None)
    _add_output_args(p)
    p.set_defaults(func=cmd_combine)

    p = sub.add_parser("finalizepsbt", help="finalize a signed PSBT into the BIP-322 signature string")
    p.add_argument("psbt")
    p.add_argument("--variant", choices=["auto", "smp", "ful", "pof"], default="auto")
    p.add_argument("--network", choices=sorted(NETWORKS), default=None)
    p.add_argument("--lenient", action="store_true", help="skip invalid partial signatures instead of failing")
    p.add_argument("--output-psbt", help="also write the finalized PSBT")
    p.add_argument("--signature-file", help="write the signature to this file")
    p.add_argument("--binary", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_finalize)

    p = sub.add_parser("verifymessage", help="verify a BIP-322 signature")
    p.add_argument("pos_address", nargs="?", metavar="address", help="Core-style positional form: address signature message")
    p.add_argument("pos_signature", nargs="?", metavar="signature")
    p.add_argument("pos_message", nargs="?", metavar="message")
    p.add_argument("--address", "-a")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--signature", "-s")
    g.add_argument("--signature-file")
    _add_message_args(p)
    p.add_argument("--engines", default=None, help="comma separated script engines to run (default: all installed, see `engines`)")
    p.add_argument("--require-prefix", action="store_true", help="reject signatures without smp/ful/pof prefix")
    p.add_argument("--no-legacy", action="store_true", help="reject legacy BIP-137 signatures")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("lint-message", help="check a message against Coldcard's display rules")
    _add_message_args(p)
    p.set_defaults(func=cmd_lint)

    p = sub.add_parser("keygen", help="generate a dummy cosigner (fingerprint, xpub/xprv key expressions) for tests")
    p.add_argument("--label", default="cosigner")
    p.add_argument("--seed", help="derive deterministically from this text (omit for random)")
    p.add_argument("--origin", default="48h/0h/0h/2h", help="BIP32 origin path (default: BIP-48 P2WSH multisig account 0)")
    p.add_argument("--network", choices=sorted(NETWORKS), default=None)
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("engines", help="list available script engines")
    p.set_defaults(func=cmd_engines)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (CLIError, BIP322Error, WalletError, FinalizeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
