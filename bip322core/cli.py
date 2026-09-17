"""Command line interface for bip322."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

from embit.networks import NETWORKS

from ._version import SPEC, __version__
from .coldcard import lint_message_for_coldcard
from .core import (
    PREFIX_FULL,
    PREFIX_POF,
    PREFIX_SIMPLE,
    BIP322Error,
    build_to_spend,
    decode_signature,
    describe_witness,
    parse_transaction,
    parse_witness,
)
from .engines import available_engines, engine_versions
from .psbt import (
    BIP322PSBT,
    combine_psbts,
    create_psbt,
    extract_tx,
    finalize_psbt,
    inspect_psbt,
    parse_psbt,
    signature_from_psbt,
)
from .verify import State, check_signers, verify_message
from .wallet import Wallet, wallet_from_file


class CLIError(Exception):
    pass


def _positional_values(args, slots: list[tuple[str, str | None]]) -> dict[str, str]:
    """Map the trailing positional values onto ``slots`` = [(name, file_flag_attr)].

    A slot whose file flag was given (e.g. ``--message-file``) is not expected
    on the command line, so ``verifymessage ADDR MSG --signature-file F`` works.
    """
    expected = [name for name, file_attr in slots if not (file_attr and getattr(args, file_attr, None))]
    values = list(getattr(args, "values", []) or [])
    if len(values) != len(expected):
        want = " ".join(n.upper() for n in expected) or "no further values"
        raise CLIError(
            f"expected {want} after the address, got {len(values)} value(s)"
            if "address" in vars(args)
            else f"expected {want}, got {len(values)} value(s)"
        )
    return dict(zip(expected, values, strict=True))


def _message_bytes(args, text: str | None) -> bytes:
    """The message: ``--message-file``'s exact bytes, otherwise the UTF-8 encoding of ``text``."""
    if getattr(args, "message_file", None):
        return Path(args.message_file).read_bytes()
    return (text or "").encode("utf-8")


def _network(args) -> str | None:
    return getattr(args, "network", None) or getattr(args, "global_network", None)


def _load_wallet(args) -> Wallet:
    """Wallet options may be given before or after the subcommand."""
    descriptor = getattr(args, "descriptor", None) or getattr(args, "global_descriptor", None)
    wallet = getattr(args, "wallet", None) or getattr(args, "global_wallet", None)
    if descriptor:
        return Wallet.from_descriptor(descriptor, network=_network(args))
    if wallet:
        return wallet_from_file(wallet, network=_network(args))
    raise CLIError("provide --wallet FILE (a wsh(sortedmulti(...)) descriptor) or --descriptor")


def _read_psbt(path: str) -> BIP322PSBT:
    data = Path(path).read_bytes() if path != "-" else sys.stdin.buffer.read()
    return parse_psbt(data)


def emit(text: str, path: str | None) -> None:
    """The command's artifact: to stdout, or to ``path`` (``-`` = stdout) with nothing on stdout."""
    if path is None or path == "-":
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
    else:
        Path(path).write_text(text if text.endswith("\n") else text + "\n")


def _write_psbt(psbt: BIP322PSBT, path: str | None, binary: bool = False) -> None:
    if path is None or path == "-":
        print(psbt.to_string())
        return
    out = Path(path)
    if binary:
        out.write_bytes(psbt.serialize())
    else:
        out.write_text(psbt.to_string() + "\n")


# --------------------------------------------------------------------------- #
# Core-style help: `help` lists commands by group, `help CMD` shows one command
# --------------------------------------------------------------------------- #


def _positional_signature(parser: argparse.ArgumentParser) -> str:
    """``"address" "message"`` style signature built from the parser's positionals."""
    parts = []
    for action in parser._actions:  # noqa: SLF001 - argparse keeps this stable in practice
        if action.option_strings or action.dest == "help":
            continue
        meta = action.metavar or action.dest
        names = meta.split() if isinstance(meta, str) else [str(meta)]
        rendered = " ".join("|" if n == "|" else f'"{n.lower()}"' for n in names)
        if action.nargs in ("*", "?"):
            rendered = f"( {rendered} )"
        elif action.nargs == "+":
            rendered = f"{rendered}..."
        parts.append(rendered)
    return " ".join(parts)


def _options(parser: argparse.ArgumentParser) -> list[tuple[str, str]]:
    rows = []
    for action in parser._actions:  # noqa: SLF001
        if not action.option_strings or action.dest == "help" or action.help == argparse.SUPPRESS:
            continue
        flags = ", ".join(action.option_strings)
        if action.nargs != 0 and action.metavar:
            flags += " " + (action.metavar if isinstance(action.metavar, str) else " ".join(action.metavar))
        elif action.nargs != 0 and action.dest:
            flags += " " + action.dest.upper()
        help_text = action.help or ""
        if "%(" in help_text:  # argparse's own placeholders, e.g. %(default)s
            help_text = help_text % {**vars(action), "prog": parser.prog}
        rows.append((flags, help_text))
    return rows


def format_help_listing(prog: str, subparsers: argparse._SubParsersAction, groups: dict[str, list[str]]) -> str:  # noqa: SLF001
    lines = []
    for title, names in groups.items():
        lines.append(f"== {title} ==")
        for name in names:
            p = subparsers.choices[name]
            sig = _positional_signature(p)
            lines.append(f"{name} {sig}".rstrip())
        lines.append("")
    lines.append(f'Use "{prog} help <command>" for the arguments, options and examples of one command.')
    return "\n".join(lines)


def format_command_help(prog: str, name: str, parser: argparse.ArgumentParser) -> str:
    lines = [f"{name} {_positional_signature(parser)}".rstrip(), ""]
    if parser.description:
        lines += [parser.description, ""]
    positionals = [a for a in parser._actions if not a.option_strings and a.dest != "help"]  # noqa: SLF001
    if positionals:
        lines.append("Arguments:")
        n = 1
        for a in positionals:
            meta = a.metavar or a.dest
            for part in meta.split() if isinstance(meta, str) else [str(meta)]:
                if part == "|":
                    continue
                required = "required" if a.nargs not in ("*", "?") else "optional"
                lines.append(f"{n}. {part.lower():<12} ({required}) {a.help or ''}".rstrip())
                n += 1
        lines.append("")
    options = _options(parser)
    if options:
        lines.append("Options:")
        width = min(max(len(f) for f, _ in options), 28)
        for flags, help_text in options:
            lines.append(f"  {flags:<{width}}  {help_text}".rstrip())
        lines.append("")
    examples = parser.get_default("examples") or []
    if examples:
        lines.append("Examples:")
        lines += [f"> {prog} {e}" for e in examples]
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# --------------------------------------------------------------------------- #
# extensions: ``bip322 NAME ...`` runs ``bip322-NAME ...`` (git style)
# --------------------------------------------------------------------------- #


def extension_path(prog: str, name: str) -> str | None:
    """The executable behind ``prog NAME``: ``prog-NAME`` next to this program, else on PATH."""
    if not name or not name.replace("-", "").replace("_", "").isalnum() or name.startswith("-"):
        return None
    candidate = Path(sys.argv[0]).resolve().parent / f"{prog}-{name}"
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    return shutil.which(f"{prog}-{name}")


def list_extensions(prog: str) -> list[str]:
    """Names of the ``prog-*`` executables reachable as ``prog NAME``."""
    dirs = [str(Path(sys.argv[0]).resolve().parent)] + (os.environ.get("PATH") or "").split(os.pathsep)
    found: dict[str, None] = {}
    for d in dirs:
        try:
            for entry in sorted(os.listdir(d)):
                if entry.startswith(f"{prog}-") and os.access(os.path.join(d, entry), os.X_OK):
                    found.setdefault(entry[len(prog) + 1 :], None)
        except OSError:
            continue
    return list(found)


def dispatch_extension(prog: str, argv: list[str], known: set[str]) -> None:
    """Replace this process with ``prog-NAME`` when ``argv`` starts with a name that is not a built-in command.

    Nothing comes back: the extension owns the process from here on, so the
    core never reads another program's output.
    """
    if not argv or argv[0].startswith("-") or argv[0] in known:
        return
    path = extension_path(prog, argv[0])
    if path:
        os.execv(path, [path, *argv[1:]])


def add_help_command(prog: str, sub: argparse._SubParsersAction, groups: dict[str, list[str]]) -> None:  # noqa: SLF001
    """Register ``help [command]`` on ``sub`` (call after every other command is added)."""
    p = sub.add_parser("help", help="list commands, or show one command's syntax, options and examples")
    p.add_argument("name", nargs="?", metavar="COMMAND")

    def cmd_help(args) -> int:
        if not args.name:
            print(format_help_listing(prog, sub, groups))
            extensions = [e for e in list_extensions(prog) if e not in sub.choices]
            if extensions:
                print(f"\nExtensions ({prog} NAME ...): " + ", ".join(extensions) + f'. Use "{prog} NAME help".')
            return 0
        if args.name not in sub.choices and extension_path(prog, args.name):
            os.execv(extension_path(prog, args.name), [extension_path(prog, args.name), "help"])
        if args.name not in sub.choices:
            raise CLIError(f"unknown command {args.name!r}; try '{prog} help'")
        sys.stdout.write(format_command_help(prog, args.name, sub.choices[args.name]))
        return 0

    p.set_defaults(func=cmd_help)


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


def _address_info(wallet: Wallet, derived) -> dict:
    from embit.descriptor.checksum import add_checksum

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
    print(json.dumps(_address_info(wallet, derived), indent=2))
    return 0


def cmd_create(args) -> int:
    wallet = _load_wallet(args)
    message = _message_bytes(args, _positional_values(args, [("message", "message_file")]).get("message"))
    derived = wallet.find_address(args.address, max_index=args.max_index)
    if derived is None:
        raise CLIError(f"address {args.address} not found in the first {args.max_index + 1} receive/change indexes of the wallet")
    lint = lint_message_for_coldcard(message)
    if lint and args.strict_coldcard:
        raise CLIError("message would be refused by a Coldcard: " + "; ".join(lint))
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
        "coldcard_lint": lint or "ok",
        "derivations": derived.derivation_paths(),
    }
    _write_psbt(psbt, args.output, binary=args.binary)
    print(json.dumps(summary, indent=2), file=sys.stderr)
    return 0


def cmd_inspect(args) -> int:
    psbt = _read_psbt(args.psbt)
    info = inspect_psbt(psbt, network=_network(args) or "main")
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
        finalize_psbt(psbt, strict=not args.lenient, signers=args.signers.split(",") if args.signers else None)
    elif args.signers:
        raise CLIError("the PSBT is already finalized; --signers cannot select signatures any more")
    signature = signature_from_psbt(psbt, args.variant)
    if args.output_psbt:
        _write_psbt(psbt, args.output_psbt, binary=args.binary)
    out = {
        "address": info.address,
        "message_utf8": info.message.decode("utf-8", errors="replace"),
        "variant": signature[:3],
        "signature": signature,
        "to_sign_hex": extract_tx(psbt).serialize().hex(),
    }
    emit(json.dumps(out, indent=2) if args.json else signature, args.output)
    return 0


def cmd_verify(args) -> int:
    address = args.address
    values = _positional_values(args, [("signature", "signature_file"), ("message", "message_file")])
    message = _message_bytes(args, values.get("message"))
    signature = Path(args.signature_file).read_text().strip() if args.signature_file else values["signature"]
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
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(format_verify_text(result.to_dict()))
    return EXIT_BY_STATE[result.state]


def format_verify_text(verdict: dict) -> str:
    """The text ``verifymessage`` prints for a verdict (``VerifyResult.to_dict()``): the state, then one line per engine.

    Public so that documents quoting the command can show its exact output.
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
    return "\n".join(lines)


#: verifymessage exit codes: 0 valid, 1 invalid, 3 inconclusive (2 = usage/IO error)
EXIT_BY_STATE = {State.VALID: 0, State.INVALID: 1, State.INCONCLUSIVE: 3}


def cmd_checksigners(args) -> int:
    psbts = [_read_psbt(p) for p in args.psbts]
    psbt = combine_psbts(psbts) if len(psbts) > 1 else psbts[0]
    engines = args.engines.split(",") if args.engines else available_engines()
    report = check_signers(psbt, engines=engines, network=_network(args) or "main")
    if args.json:
        emit(json.dumps(report, indent=2), args.output)
    else:
        lines = [f"address   {report['address']}", f"message   {report['message_utf8']!r}", f"threshold {report['threshold']}", ""]
        sc = report.get("script") or {}
        if sc.get("asm"):
            lines.append(f"  script    {sc['asm']}")
            lines.append(f"  sha256    {sc['sha256']}")
        elif sc.get("pubkey"):
            lines.append(f"  pubkey    {sc['pubkey']}  hash160 {sc['hash160']}")
        if sc.get("scriptPubKey"):
            lines.append(f"  scriptPubKey {sc['scriptPubKey']}")
            lines.append(f"  address   {sc['address']}  ({'matches the input' if sc['matches_input'] else 'DOES NOT MATCH the input'})")
            lines.append("")
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
        emit("\n".join(lines), args.output)
    return 0 if report["ok"] else 1


def cmd_decodesignature(args) -> int:
    """Open a proof string into its parts, like Core's decoderawtransaction."""
    text = sys.stdin.read() if args.signature == "-" else args.signature
    out = decode_signature_report(text, _network(args) or "main")
    emit(format_decode_text(out) if args.text else json.dumps(out, indent=2), args.output)
    return 0


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

    def with_address(elements: list[dict]) -> list[dict]:
        from embit.script import Script

        for e in elements:
            if "p2wsh_scriptPubKey" in e:
                e["p2wsh_address"] = Script(bytes.fromhex(e["p2wsh_scriptPubKey"])).address(network)
            elif e.get("role") == "compressed public key":
                digest = hashlib.new("ripemd160", hashlib.sha256(bytes.fromhex(e["hex"])).digest()).digest()
                e["hash160"] = digest.hex()
                e["p2wpkh_scriptPubKey"] = (b"\x00\x14" + digest).hex()
                e["p2wpkh_address"] = Script(bytes.fromhex(e["p2wpkh_scriptPubKey"])).address(network)
        return elements

    if decoded.variant == PREFIX_SIMPLE:
        out["witness"] = with_address(describe_witness(parse_witness(decoded.payload)))
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
                    "witness": with_address(describe_witness(vin.witness.items)),
                }
                for vin in tx.vin
            ],
            "outputs": [{"value": o.value, "scriptPubKey": o.script_pubkey.data.hex()} for o in tx.vout],
        }
    elif decoded.variant == PREFIX_POF:
        psbt = parse_psbt(decoded.payload)
        tx = psbt.tx
        out["psbt"] = {  # noqa: F841 - built below
            "inputs": [
                {
                    "txid": inp.txid.hex(),
                    "vout": inp.vout,
                    "finalized": bool(inp.final_scriptwitness) or bool(inp.final_scriptsig),
                    "witness": with_address(describe_witness(inp.final_scriptwitness.items)) if inp.final_scriptwitness else [],
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


def format_decode_text(out: dict) -> str:
    """The text ``decodesignature --text`` prints: each witness item with what it is, and for a script or key the lock it names."""

    def items(elements: list[dict]) -> list[str]:
        lines = []
        for e in elements:
            head = f"[{e['index']}] {e['role']}"
            if "sighash" in e:
                head += f", sighash {e['sighash']}" + (" (ALL)" if e["sighash"] == 1 else "")
            if e.get("bytes"):
                head += f", {e['bytes']} bytes"
            lines.append(head)
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

    if out["variant"] == PREFIX_SIMPLE:
        return "\n".join([f"smp: the witness stack of to_sign input 0, {len(out['witness'])} items", *items(out["witness"])])
    if out["variant"] == PREFIX_FULL:
        lines = [f"ful: to_sign {out['to_sign']['txid']}, version {out['to_sign']['version']}, {len(out['to_sign']['inputs'])} input(s)"]
        for i, vin in enumerate(out["to_sign"]["inputs"]):
            lines.append(f"input {i}: {vin['txid']}:{vin['vout']}")
            lines.extend("  " + line for line in items(vin["witness"]))
        return "\n".join(lines)
    return json.dumps(out, indent=2)


def cmd_lint(args) -> int:
    message = _message_bytes(args, _positional_values(args, [("message", "message_file")]).get("message"))
    problems = lint_message_for_coldcard(message)
    if problems:
        print("Coldcard would refuse this message:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("ok: message is acceptable to a Coldcard")
    return 0


def cmd_engines(args) -> int:  # noqa: ARG001
    print(json.dumps({"engines": available_engines(), "versions": engine_versions()}, indent=2))
    return 0


# --------------------------------------------------------------------------- #
# argument parsing
# --------------------------------------------------------------------------- #


def _add_wallet_args(p: argparse.ArgumentParser) -> None:
    g = p.add_mutually_exclusive_group()
    g.add_argument("--wallet", "-w", help="file holding the wallet descriptor: wsh(sortedmulti(...)) or wpkh(...)")
    g.add_argument("--descriptor", "-d", help="descriptor text: wsh(sortedmulti(...)) or wpkh(...)")
    p.add_argument("--network", choices=sorted(NETWORKS), default=None, help="address network (default: main)")


def _add_message_file(p: argparse.ArgumentParser) -> None:
    p.add_argument("--message-file", metavar="FILE", help="take the message's exact bytes from FILE instead of the MESSAGE argument")


def _add_output_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--output", "-o", help="write the PSBT here instead of stdout (base64)")
    p.add_argument("--binary", action="store_true", help="write the PSBT in binary instead of base64")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bip322",
        description=f"BIP-322 message signing: build, finalize and verify proofs ({SPEC}; private-key tooling lives in bip322-dev)",
    )
    parser.add_argument("--version", action="version", version=f"bip322-core {__version__} ({SPEC})")
    # wallet options are accepted here (before the subcommand) as well as after it
    parser.add_argument(
        "--wallet",
        "-w",
        dest="global_wallet",
        metavar="FILE",
        help="file holding the wallet descriptor: wsh(sortedmulti(...)) or wpkh(...)",
    )
    parser.add_argument(
        "--descriptor", "-d", dest="global_descriptor", metavar="DESC", help="descriptor text: wsh(sortedmulti(...)) or wpkh(...)"
    )
    parser.add_argument("--network", dest="global_network", choices=sorted(NETWORKS), default=None, help="address network (default: main)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser(
        "wallet",
        help="show wallet policy, cosigners and descriptor",
        description="Show the wallet's policy, cosigners (fingerprint, origin, xpub) and checksummed descriptor.",
    )
    _add_wallet_args(p)
    p.set_defaults(func=cmd_wallet, examples=["-w wallet.desc wallet"])

    p = sub.add_parser("deriveaddresses", help="addresses for an index or an index range (like Bitcoin Core's deriveaddresses)")
    _add_wallet_args(p)
    p.add_argument("indexes", nargs="*", type=int, metavar="INDEX | START END", help="a single index, or an inclusive range; default 0")
    p.add_argument("--change", action="store_true", help="change branch instead of receive")
    p.add_argument("--json", action="store_true", help="objects with branch/index instead of bare addresses")
    p.description = "Derive the wallet's addresses for one index or an inclusive index range, one per line."
    p.set_defaults(
        func=cmd_deriveaddresses,
        examples=["-w wallet.desc deriveaddresses 0 5", "-w wallet.desc deriveaddresses 3 --change", "-w wallet.desc deriveaddresses"],
    )

    p = sub.add_parser("getaddressinfo", help="look an address up in the wallet (like Bitcoin Core's getaddressinfo)")
    _add_wallet_args(p)
    p.add_argument("address", help="the address to look up")
    p.add_argument("--max-index", type=int, default=500, help="how far to search each branch")
    p.description = (
        "Report whether the address belongs to the wallet and how it is built: script, public keys, key paths, branch/index, descriptor."
    )
    p.set_defaults(func=cmd_getaddressinfo, examples=["-w wallet.desc getaddressinfo bc1q..."])

    p = sub.add_parser("createpsbt", help="create the BIP-322 to_sign PSBT for a wallet address and a message")
    _add_wallet_args(p)
    p.add_argument("address", help="the wallet address to sign for (searched in the wallet)")
    p.add_argument("values", nargs="*", metavar="MESSAGE", help="the message text (UTF-8)")
    _add_message_file(p)
    p.add_argument("--max-index", type=int, default=500, help="how far to search the wallet for ADDRESS")
    p.add_argument(
        "--utxo", choices=["witness", "non_witness", "both"], default="witness", help="which UTXO field(s) to include for input 0"
    )
    p.add_argument("--no-xpubs", action="store_true", help="omit PSBT_GLOBAL_XPUB entries")
    p.add_argument("--psbt-v2", action="store_true", help="emit a BIP-370 (v2) PSBT")
    p.add_argument("--strict-coldcard", action="store_true", help="fail if the message would be refused by a Coldcard")
    _add_output_args(p)
    p.description = (
        "Build the BIP-322 to_sign PSBT for the address and message: version 0, one input spending to_spend:0 with "
        "sequence 0, one zero-value OP_RETURN output, witness_utxo, witness script, key paths, sighash ALL, global xpubs "
        "and the message in global field 0x09. A summary goes to stderr."
    )
    p.set_defaults(
        func=cmd_create,
        examples=[
            '-w wallet.desc createpsbt bc1q... "proof of control 2026-09-14" --strict-coldcard -o proof.psbt',
            "-w wallet.desc createpsbt bc1q... --message-file msg.txt > proof.psbt",
        ],
    )

    p = sub.add_parser("analyzepsbt", help="report whether a PSBT is a BIP-322 PSBT, its state and what is missing")
    p.add_argument("psbt", help="PSBT file (base64 or binary) or - for stdin")
    p.add_argument("--network", choices=sorted(NETWORKS), default=None, help="address network for the report (default: main)")
    p.description = (
        "Apply the BIP-322 PSBT-signer checks (message field, to_spend txid, OP_RETURN output, version) and report the state: "
        "address, every cosigner with whether its signature is present and verifies, finalized or not, problems and warnings. "
        "Exit 1 if it is not a BIP-322 PSBT."
    )
    p.set_defaults(func=cmd_inspect, examples=["analyzepsbt proof.psbt", "analyzepsbt - < proof.psbt"])

    p = sub.add_parser("combinepsbt", help="merge partially signed PSBTs from the cosigners")
    p.add_argument("psbts", nargs="+", metavar="PSBT", help="PSBT files signed by different cosigners")
    p.add_argument("--network", choices=sorted(NETWORKS), default=None, help="address network for the summary (default: main)")
    _add_output_args(p)
    p.description = "Merge PSBTs that different cosigners signed from the same original; refuses PSBTs whose shared fields disagree."
    p.set_defaults(func=cmd_combine, examples=["combinepsbt proof-A.psbt proof-B.psbt -o proof-AB.psbt"])

    p = sub.add_parser("finalizepsbt", help="finalize a signed PSBT into the BIP-322 signature string")
    p.add_argument("psbt", help="signed PSBT file (base64 or binary) or - for stdin")
    p.add_argument(
        "--variant",
        choices=["auto", "smp", "ful", "pof"],
        default="auto",
        help="encoding to emit (default auto: smp when the BIP allows it, else ful)",
    )
    p.add_argument("--network", choices=sorted(NETWORKS), default=None, help="address network for the report (default: main)")
    p.add_argument("--lenient", action="store_true", help="skip invalid partial signatures instead of failing")
    p.add_argument(
        "--signers",
        metavar="FP[,FP...]",
        help="use only these cosigners' signatures (master fingerprints or pubkey prefixes), e.g. to prove a specific pair works",
    )
    p.add_argument("--output", "-o", help="write the signature (or the --json report) here instead of stdout")
    p.add_argument(
        "--json",
        action="store_true",
        help="emit a JSON report (address, message, variant, signature, to_sign hex) instead of the bare signature",
    )
    p.add_argument("--output-psbt", help="also write the finalized PSBT (for the pof variant or for the record)")
    p.add_argument("--binary", action="store_true", help="write --output-psbt in binary instead of base64")
    p.description = (
        "BIP-174 finalizer: check every partial signature (strict DER, low-S, SIGHASH_ALL, verifies against the sighash), "
        "build the witness, and print the encoded proof (smp when the BIP allows it, ful otherwise). Does not verify the proof."
    )
    p.set_defaults(
        func=cmd_finalize,
        examples=[
            "finalizepsbt proof-AB.psbt -o proof.sig",
            "finalizepsbt proof-ABC.psbt --signers ea34d476,7d5dc65a",
            "finalizepsbt proof-AB.psbt --variant ful --json",
        ],
    )

    p = sub.add_parser("checksigners", help="the whole picture of a signed PSBT: script chain, every cosigner, every threshold combination")
    p.add_argument("psbts", nargs="+", metavar="PSBT", help="the signed PSBT, or the separate files each device produced (combined here)")
    p.add_argument("--network", choices=sorted(NETWORKS), default=None, help="address network for the report (default: main)")
    p.add_argument("--engines", default=None, help="comma separated bip322 engines (default: all installed)")
    p.add_argument("--json", action="store_true", help="JSON report including every combination's proof")
    p.add_argument("--output", "-o", help="write the report here instead of stdout")
    p.description = (
        "Device health check and explanation in one: rebuild the script behind the input and show how it hashes back to "
        "the scriptPubKey and address; verify each cosigner's signature on its own; then finalize and verify one proof per "
        "threshold-sized combination of cosigners (all three pairs of a 2-of-3), showing the witness each one assembled. "
        "Exit 0 when the script matches, every signer is valid and every combination verifies."
    )
    p.set_defaults(
        func=cmd_checksigners,
        examples=[
            "checksigners proof-ccA.psbt proof-ccB.psbt proof-ccC.psbt",
            "checksigners combined.psbt --json -o signers-2026-09-15.json",
        ],
    )

    p = sub.add_parser("verifymessage", help="verify a BIP-322 signature (same argument order as Bitcoin Core's RPC)")
    p.add_argument("address")
    p.add_argument("values", nargs="*", metavar="SIGNATURE MESSAGE", help="the signature string and the message text")
    p.add_argument("--signature-file", metavar="FILE", help="read the signature from FILE instead of the SIGNATURE argument")
    _add_message_file(p)
    p.add_argument("--engines", default=None, help="comma separated script engines to run (default: all installed, see `engines`)")
    p.add_argument("--require-prefix", action="store_true", help="reject signatures without smp/ful/pof prefix")
    p.add_argument("--no-legacy", action="store_true", help="reject legacy BIP-137 signatures")
    p.add_argument("--json", action="store_true", help="self-contained JSON report instead of text")
    p.description = (
        "Verify a BIP-322 proof (smp, ful, pof or legacy) for the address and message with every installed script engine. "
        "Exit codes: 0 valid, 1 invalid, 3 inconclusive, 2 error."
    )
    p.set_defaults(
        func=cmd_verify,
        examples=[
            'verifymessage bc1q... smp... "proof of control 2026-09-14"',
            'verifymessage bc1q... "proof of control 2026-09-14" --signature-file proof.sig --json',
        ],
    )
    p.epilog = "exit codes: 0 valid, 1 invalid, 3 inconclusive, 2 error"

    p = sub.add_parser("decodesignature", help="open a proof string into its parts (witness stack, to_sign or PSBT)")
    p.add_argument("signature", help="an smp/ful/pof proof string, or - to read it from stdin")
    p.add_argument(
        "--network", choices=sorted(NETWORKS), default=None, help="network for the address a witness script commits to (default: main)"
    )
    p.add_argument(
        "--text",
        action="store_true",
        help="print text instead of JSON: each witness item, and the scriptPubKey and address a witness script or key names",
    )
    p.add_argument("--output", "-o", help="write the output here instead of stdout")
    p.description = (
        "Decode a BIP-322 signature: for smp the witness stack (each element labelled: dummy, signatures with their "
        "sighash byte, the witness script disassembled), for ful the whole to_sign transaction, for pof the finalized PSBT. "
        "Nothing is verified; use verifymessage for that."
    )
    p.set_defaults(func=cmd_decodesignature, examples=["decodesignature smp...", "decodesignature - < proof.sig"])

    p = sub.add_parser("lint-message", help="check a message against Coldcard's display rules")
    p.add_argument("values", nargs="*", metavar="MESSAGE")
    _add_message_file(p)
    p.description = (
        "Check a message against Coldcard's display rules (2-330 printable ASCII, no leading/trailing space, no run of three spaces)."
    )
    p.set_defaults(func=cmd_lint, examples=['lint-message "proof of control 2026-09-14"'])

    p = sub.add_parser("engines", help="list available script engines", description="List the installed script engines and their versions.")
    p.set_defaults(func=cmd_engines, examples=["engines"])

    add_help_command(
        "bip322",
        sub,
        {
            "Wallet": ["wallet", "deriveaddresses", "getaddressinfo"],
            "PSBT": ["createpsbt", "analyzepsbt", "combinepsbt", "finalizepsbt"],
            "Verification": ["verifymessage", "checksigners"],
            "Util": ["decodesignature", "lint-message", "engines", "help"],
        },
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    dispatch_extension("bip322", argv, set(_subcommands(parser)))
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (CLIError, BIP322Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc.strerror or exc}: {exc.filename}" if getattr(exc, "filename", None) else f"error: {exc}", file=sys.stderr)
        return 2


def _subcommands(parser: argparse.ArgumentParser) -> list[str]:
    for action in parser._actions:  # noqa: SLF001
        if isinstance(action, argparse._SubParsersAction):  # noqa: SLF001
            return list(action.choices)
    return []


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
