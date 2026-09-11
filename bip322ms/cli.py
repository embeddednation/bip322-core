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
from .engines import available_engines
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
from .verify import verify_message
from .wallet import MultisigWallet, WalletError, wallet_from_file


class CLIError(Exception):
    pass


def _read_message(args) -> bytes:
    if getattr(args, "message_file", None):
        return Path(args.message_file).read_bytes()
    if getattr(args, "message", None) is None:
        raise CLIError("provide --message or --message-file")
    return args.message.encode("utf-8")


def _load_wallet(args) -> MultisigWallet:
    if getattr(args, "descriptor", None):
        return MultisigWallet.from_descriptor(args.descriptor, network=args.network or "main")
    if getattr(args, "wallet", None):
        return wallet_from_file(args.wallet, network=args.network)
    raise CLIError("provide --wallet FILE (descriptor or Coldcard export) or --descriptor")


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
    info = wallet.describe()
    if args.addresses:
        info["addresses"] = [
            {"branch": b, "index": i, "address": wallet.derive(i, b).address}
            for b in range(max(wallet.num_branches, 1))
            for i in range(args.addresses)
        ]
    print(json.dumps(info, indent=2))
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
    info = inspect_psbt(psbt, network=args.network or "main")
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
    info = inspect_psbt(psbt, network=args.network or "main")
    if not info.is_bip322 and not args.force:
        raise CLIError("refusing to sign: not a well-formed BIP-322 PSBT: " + "; ".join(info.problems))
    total = 0
    for key in args.key:
        total += sign_psbt(psbt, key)
    if total == 0:
        raise CLIError("no signatures added (key does not match any input derivation)")
    _write_psbt(psbt, args.output, binary=args.binary)
    print(f"added {total} signature(s)", file=sys.stderr)
    return 0


def cmd_combine(args) -> int:
    psbts = [_read_psbt(p) for p in args.psbts]
    combined = combine_psbts(psbts)
    _write_psbt(combined, args.output, binary=args.binary)
    info = inspect_psbt(combined, network=args.network or "main")
    print(f"combined {len(psbts)} PSBT(s); input 0 now has {len(info.partial_sigs)} partial signature(s)", file=sys.stderr)
    return 0


def cmd_finalize(args) -> int:
    psbt = _read_psbt(args.psbt)
    info = inspect_psbt(psbt, network=args.network or "main")
    if not info.is_bip322:
        raise CLIError("not a well-formed BIP-322 PSBT: " + "; ".join(info.problems))
    message = info.message
    address = info.address
    if not info.finalized:
        finalize_psbt(psbt, strict=not args.lenient)
    signature = signature_from_psbt(psbt, args.variant)
    result = verify_message(address, signature, message, engines=args.engines.split(","))
    if not result.ok and not args.no_verify:
        raise CLIError(f"finalized proof failed self-verification ({result.state.value}): {result.reason}")
    if args.output_psbt:
        _write_psbt(psbt, args.output_psbt, binary=args.binary)
    out = {
        "address": address,
        "message_utf8": message.decode("utf-8", errors="replace"),
        "variant": signature[:3],
        "signature": signature,
        "to_sign_hex": extract_tx(psbt).serialize().hex(),
        "self_verification": result.to_dict(),
    }
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print(signature)
        print(json.dumps({k: v for k, v in out.items() if k != "signature"}, indent=2), file=sys.stderr)
    if args.signature_file:
        Path(args.signature_file).write_text(signature + "\n")
    return 0


def cmd_verify(args) -> int:
    message = _read_message(args)
    signature = args.signature
    if args.signature_file:
        signature = Path(args.signature_file).read_text().strip()
    if signature is None:
        raise CLIError("provide --signature or --signature-file")
    result = verify_message(
        args.address,
        signature,
        message,
        engines=args.engines.split(","),
        allow_unprefixed=not args.require_prefix,
        allow_legacy=not args.no_legacy,
    )
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(f"{result.state.value.upper()}: {result.reason}")
        for run in result.engines:
            print(f"  [{run.engine}] {'ok' if run.ok else 'FAIL: ' + str(run.error)}")
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
    net = NETWORKS[args.network or "main"]
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
        "coldcard_line": f"{fp.upper()}: {xpub}",
    }
    print(json.dumps(out, indent=2))
    return 0


def cmd_engines(args) -> int:  # noqa: ARG001
    print(json.dumps({"engines": available_engines()}))
    return 0


# --------------------------------------------------------------------------- #
# argument parsing
# --------------------------------------------------------------------------- #


def _add_wallet_args(p: argparse.ArgumentParser) -> None:
    g = p.add_mutually_exclusive_group()
    g.add_argument("--wallet", "-w", help="wallet file: an output descriptor or a Coldcard multisig export")
    g.add_argument("--descriptor", "-d", help="wsh(sortedmulti(...)) descriptor text")
    p.add_argument("--network", choices=sorted(NETWORKS), default=None, help="address network (default: main, or inferred from a Coldcard file)")


def _add_message_args(p: argparse.ArgumentParser) -> None:
    g = p.add_mutually_exclusive_group()
    g.add_argument("--message", "-m", help="message text (UTF-8)")
    g.add_argument("--message-file", help="file whose exact bytes are the message")


def _add_output_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--output", "-o", help="output PSBT file (base64; default stdout)")
    p.add_argument("--binary", action="store_true", help="write the PSBT in binary instead of base64")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bip322ms", description="BIP-322 message signing for P2WSH multisig quorums")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("wallet", help="show wallet policy, descriptor and addresses")
    _add_wallet_args(p)
    p.add_argument("--addresses", type=int, default=0, help="also list the first N receive/change addresses")
    p.set_defaults(func=cmd_wallet)

    p = sub.add_parser("create", help="create the BIP-322 PSBT for a message and a wallet address")
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

    p = sub.add_parser("inspect", help="check whether a PSBT is a BIP-322 PSBT and show its state")
    p.add_argument("psbt", help="PSBT file (base64 or binary) or - for stdin")
    p.add_argument("--network", choices=sorted(NETWORKS), default=None)
    p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("sign", help="add signatures with software keys (tests / non-hardware cosigners)")
    p.add_argument("psbt")
    p.add_argument("--key", "-k", action="append", required=True, help="xprv, [fp/path]xprv expression or WIF (repeatable)")
    p.add_argument("--network", choices=sorted(NETWORKS), default=None)
    p.add_argument("--force", action="store_true", help="sign even if the PSBT fails the BIP-322 checks")
    _add_output_args(p)
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("combine", help="merge partially signed PSBTs from the cosigners")
    p.add_argument("psbts", nargs="+")
    p.add_argument("--network", choices=sorted(NETWORKS), default=None)
    _add_output_args(p)
    p.set_defaults(func=cmd_combine)

    p = sub.add_parser("finalize", help="finalize a signed PSBT and print the BIP-322 signature")
    p.add_argument("psbt")
    p.add_argument("--variant", choices=["auto", "smp", "ful", "pof"], default="auto")
    p.add_argument("--network", choices=sorted(NETWORKS), default=None)
    p.add_argument("--engines", default="btclib", help="comma separated engines for self-verification (btclib,kernel)")
    p.add_argument("--lenient", action="store_true", help="skip invalid partial signatures instead of failing")
    p.add_argument("--no-verify", action="store_true", help="print the signature even if self-verification fails")
    p.add_argument("--output-psbt", help="also write the finalized PSBT")
    p.add_argument("--signature-file", help="write the signature to this file")
    p.add_argument("--binary", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_finalize)

    p = sub.add_parser("verify", help="verify a BIP-322 signature")
    p.add_argument("--address", "-a", required=True)
    g = p.add_mutually_exclusive_group()
    g.add_argument("--signature", "-s")
    g.add_argument("--signature-file")
    _add_message_args(p)
    p.add_argument("--engines", default="btclib", help="comma separated engines (btclib,kernel)")
    p.add_argument("--require-prefix", action="store_true", help="reject signatures without smp/ful/pof prefix")
    p.add_argument("--no-legacy", action="store_true", help="reject legacy BIP-137 signatures")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("lint-message", help="check a message against Coldcard's display rules")
    _add_message_args(p)
    p.set_defaults(func=cmd_lint)

    p = sub.add_parser("keygen", help="generate a dummy cosigner (fingerprint, xpub/xprv expressions, Coldcard line) for tests")
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
