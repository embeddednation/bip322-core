"""Command line interface for bip322: the commands and the entry point.

The pieces live in their own modules and are re-exported here, where other
packages import them from: ``cli_common`` (errors, I/O, shared options),
``cli_help`` (help and extensions), ``cli_parser`` (the argument parser) and
``report`` (what the commands print).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ._version import __version__
from .cli_common import CLIError, emit, network_of, read_psbt, run_cli, write_psbt
from .cli_help import add_help_command, dispatch_extension, extension_path, format_command_help, format_help_listing, list_extensions
from .cli_parser import DASH_NOTE, MESSAGE_HELP, make_parser
from .core import build_to_spend
from .engines import available_engines, check_engines, engine_versions
from .msglint import lint_message
from .psbt import combine_psbts, create_psbt, extract_tx, finalize_psbt, inspect_psbt, signature_from_psbt
from .report import (
    address_info,
    decode_signature_report,
    describe_address,
    format_address_text,
    format_decode_text,
    format_signers_text,
    format_verify_text,
)
from .signers import check_signers
from .verify import State, script_pubkey_from_address, verify_message
from .wallet import Wallet, wallet_from_file

__all__ = [
    "DASH_NOTE",
    "EXIT_BY_STATE",
    "MESSAGE_HELP",
    "CLIError",
    "add_help_command",
    "build_parser",
    "cmd_analyzepsbt",
    "cmd_checksigners",
    "cmd_combinepsbt",
    "cmd_createpsbt",
    "cmd_decodesignature",
    "cmd_deriveaddresses",
    "cmd_engines",
    "cmd_finalizepsbt",
    "cmd_getaddressinfo",
    "cmd_lint_message",
    "cmd_validateaddress",
    "cmd_verifymessage",
    "cmd_wallet",
    "decode_signature_report",
    "dispatch_extension",
    "emit",
    "extension_path",
    "format_address_text",
    "format_command_help",
    "format_decode_text",
    "format_help_listing",
    "format_verify_text",
    "list_extensions",
    "main",
]


def _message_bytes(args, text: str | None) -> bytes:
    """The message: ``--message-file``'s exact bytes, otherwise the UTF-8 encoding of ``text``."""
    if getattr(args, "message_file", None):
        data = Path(args.message_file).read_bytes()
        if data.endswith(b"\n"):  # editors and echo add one; it is signed like any other byte
            print(f"note: {args.message_file} ends with a newline; the message is all {len(data)} bytes, newline included", file=sys.stderr)
        return data
    return (text or "").encode("utf-8")


def _load_wallet(args) -> Wallet:
    """Wallet options may be given before or after the subcommand."""
    descriptor = getattr(args, "descriptor", None) or getattr(args, "global_descriptor", None)
    wallet = getattr(args, "wallet", None) or getattr(args, "global_wallet", None)
    if descriptor:
        return Wallet.from_descriptor(descriptor, network=network_of(args))
    if wallet:
        return wallet_from_file(wallet, network=network_of(args))
    raise CLIError("provide --wallet FILE (a wsh(sortedmulti(...)) descriptor) or --descriptor")


def _engines(args) -> list[str]:
    """The engines asked for, checked before any work so that a typo is an error and never part of a verdict."""
    engines = [e.strip() for e in args.engines.split(",") if e.strip()] if args.engines else available_engines()
    check_engines(engines)
    return engines


def cmd_wallet(args) -> int:
    wallet = _load_wallet(args)
    print(json.dumps(wallet.describe(), indent=2))
    return 0


def cmd_deriveaddresses(args) -> int:
    """Like Bitcoin Core's deriveaddresses: addresses for an explicit index range."""
    wallet = _load_wallet(args)
    if len(args.indexes) == 0:
        start = end = 0
    elif len(args.indexes) == 1:
        start = end = args.indexes[0]
    elif len(args.indexes) == 2:
        start, end = args.indexes
    else:
        raise CLIError("give INDEX, or START END")
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


def cmd_getaddressinfo(args) -> int:
    """Like Bitcoin Core's getaddressinfo: is this address ours, and how is it built?"""
    wallet = _load_wallet(args)
    derived = wallet.find_address(args.address, max_index=args.max_index)
    if derived is None:
        print(
            json.dumps(
                {"address": args.address, "ismine": False, "reason": f"not found in the first {args.max_index + 1} receive/change indexes"},
                indent=2,
            )
        )
        return 1
    print(json.dumps(address_info(wallet, derived), indent=2))
    return 0


def cmd_createpsbt(args) -> int:
    wallet = _load_wallet(args)
    message = _message_bytes(args, getattr(args, "message", None))
    derived = wallet.find_address(args.address, max_index=args.max_index)
    if derived is None:
        raise CLIError(f"address {args.address} not found in the first {args.max_index + 1} receive/change indexes of the wallet")
    lint = lint_message(message)
    if lint and args.strict_message:
        raise CLIError("a hardware signer may refuse this message: " + "; ".join(lint))
    psbt = create_psbt(
        derived,
        message,
        xpubs=None if args.no_xpubs else wallet.global_xpubs(),
        utxo_mode=args.utxo,
        psbt_version=2 if args.psbt_v2 else None,
    )
    summary = {
        "address": derived.address,
        "branch": derived.branch,
        "index": derived.index,
        "policy": f"{derived.threshold} of {len(derived.pubkeys)}" if derived.witness_script is not None else "single key (p2wpkh)",
        "message_utf8": message.decode("utf-8", errors="replace"),
        "message_bytes": len(message),
        "to_spend_txid": build_to_spend(message, derived.script_pubkey).txid().hex(),
        "to_sign_txid": psbt.tx.txid().hex(),
        "message_lint": lint or "ok",
        "derivations": derived.derivation_paths(),
    }
    write_psbt(psbt, args.output, binary=args.binary)
    print(json.dumps(summary, indent=2), file=sys.stderr)
    return 0


def cmd_analyzepsbt(args) -> int:
    psbt = read_psbt(args.psbt)
    info = inspect_psbt(psbt, network=network_of(args) or "main")
    out = {
        "tool": f"bip322-core {__version__}",
        "is_bip322": info.is_bip322,
        "problems": info.problems,
        "warnings": info.warnings,
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
        "signers": info.signers,
        "finalized": info.finalized,
    }
    print(json.dumps(out, indent=2))
    return 0 if info.is_bip322 else 1


def cmd_combinepsbt(args) -> int:
    psbts = [read_psbt(p) for p in args.psbts]
    combined = combine_psbts(psbts)
    write_psbt(combined, args.output, binary=args.binary)
    info = inspect_psbt(combined, network=network_of(args) or "main")
    print(f"combined {len(psbts)} PSBT(s); input 0 now has {len(info.partial_sigs)} partial signature(s)", file=sys.stderr)
    return 0


def cmd_finalizepsbt(args) -> int:
    """BIP-174 input finalizer: check each partial signature, assemble the witness, encode.

    Verification of the resulting proof is verifymessage's job, not this command's.
    """
    if args.binary and not args.output_psbt:
        raise CLIError("--binary applies to --output-psbt FILE; the signature itself is text")
    psbt = read_psbt(args.psbt)
    info = inspect_psbt(psbt, network=network_of(args) or "main")
    if not info.is_bip322:
        raise CLIError("not a well-formed BIP-322 PSBT: " + "; ".join(info.problems))
    if not info.finalized:
        finalize_psbt(psbt, strict=not args.lenient, signers=args.signers.split(",") if args.signers else None)
    elif args.signers:
        raise CLIError("the PSBT is already finalized; --signers cannot select signatures any more")
    signature = signature_from_psbt(psbt, args.variant)
    if args.output_psbt:
        write_psbt(psbt, args.output_psbt, binary=args.binary)
    out = {
        "address": info.address,
        "message_utf8": info.message.decode("utf-8", errors="replace"),
        "variant": signature[:3],
        "signature": signature,
        "to_sign_hex": extract_tx(psbt).serialize().hex(),
    }
    emit(json.dumps(out, indent=2) if args.json else signature, args.output)
    return 0


#: verifymessage exit codes: 0 valid, 1 invalid, 3 inconclusive (2 = usage/IO error)
EXIT_BY_STATE = {State.VALID: 0, State.INVALID: 1, State.INCONCLUSIVE: 3}


def cmd_verifymessage(args) -> int:
    address = args.address
    engines = _engines(args)
    # an address that is none is a usage error (exit 2), not a verdict on the proof (exit 1)
    script_pubkey_from_address(address)
    message = _message_bytes(args, getattr(args, "message", None))
    if args.signature_file:
        try:
            signature = Path(args.signature_file).read_text(encoding="utf-8").strip()
        except UnicodeDecodeError as exc:
            raise CLIError(f"{args.signature_file}: not a text file (a signature is base64 text)") from exc
    else:
        signature = args.signature
    result = verify_message(
        address,
        signature,
        message,
        engines=engines,
        allow_unprefixed=not args.require_prefix,
        allow_legacy=not args.no_legacy,
    )
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(format_verify_text(result.to_dict()))
    return EXIT_BY_STATE[result.state]


def cmd_checksigners(args) -> int:
    engines = _engines(args)
    psbts = [read_psbt(p) for p in args.psbts]
    psbt = combine_psbts(psbts) if len(psbts) > 1 else psbts[0]
    report = check_signers(psbt, engines=engines, network=network_of(args) or "main")
    emit(json.dumps(report, indent=2) if args.json else format_signers_text(report), args.output)
    return 0 if report["ok"] else 1


def cmd_validateaddress(args) -> int:
    """Like Bitcoin Core's validateaddress, without a node: the scriptPubKey an address encodes."""
    info = describe_address(args.address, network_of(args) or "main")
    emit(json.dumps(info, indent=2) if args.json else format_address_text(info), args.output)
    return 0


def cmd_decodesignature(args) -> int:
    """Open a proof string into its parts, like Core's decoderawtransaction."""
    text = sys.stdin.read() if args.signature == "-" else args.signature
    out = decode_signature_report(text, network_of(args) or "main")
    emit(format_decode_text(out) if args.text else json.dumps(out, indent=2), args.output)
    return 0


def cmd_lint_message(args) -> int:
    message = _message_bytes(args, getattr(args, "message", None))
    problems = lint_message(message)
    if problems:
        print("a hardware signer may refuse this message:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("ok: message fits the display rules of hardware signers")
    return 0


def cmd_engines(args) -> int:  # noqa: ARG001
    print(json.dumps({"engines": available_engines(), "versions": engine_versions()}, indent=2))
    return 0


def build_parser(argv: list[str] | None = None) -> argparse.ArgumentParser:
    """The parser for ``argv``: a value given by ``--signature-file``/``--message-file`` is not expected as a positional."""
    # the functions are looked up here, at call time, so that replacing one on this module takes effect
    commands = {
        "wallet": cmd_wallet,
        "deriveaddresses": cmd_deriveaddresses,
        "getaddressinfo": cmd_getaddressinfo,
        "createpsbt": cmd_createpsbt,
        "analyzepsbt": cmd_analyzepsbt,
        "combinepsbt": cmd_combinepsbt,
        "finalizepsbt": cmd_finalizepsbt,
        "checksigners": cmd_checksigners,
        "verifymessage": cmd_verifymessage,
        "validateaddress": cmd_validateaddress,
        "decodesignature": cmd_decodesignature,
        "lint-message": cmd_lint_message,
        "engines": cmd_engines,
    }
    return make_parser(argv, commands)


def _run(argv: list[str]) -> int:
    parser = build_parser(argv)
    known = set(_subcommands(parser))
    dispatch_extension("bip322", argv, known)
    if argv and not argv[0].startswith("-") and argv[0] not in known:
        print(f"bip322: '{argv[0]}' is not a bip322 command. See 'bip322 help'.", file=sys.stderr)
        return 2
    args = parser.parse_args(argv)
    return args.func(args)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    return run_cli(lambda: _run(argv))


def _subcommands(parser: argparse.ArgumentParser) -> list[str]:
    for action in parser._actions:  # noqa: SLF001
        if isinstance(action, argparse._SubParsersAction):  # noqa: SLF001
            return list(action.choices)
    return []


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
