"""``bip322-dev``: the commands that handle private keys (keygen, makewallet, signpsbt)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..cli_common import CLIError, add_option, add_psbt_output_options, emit, network_of, read_psbt, run_cli, write_psbt
from ..cli_help import add_help_command
from ..psbt import inspect_psbt
from .keys import cosigner_from_text, generate_cosigner, wallet_from_cosigners
from .signing import sign_psbt


def _read_signer_key(text: str) -> str:
    """A KEY argument: a key string, a keygen JSON file, or a file holding the key."""
    if not Path(text).is_file():
        return text
    try:
        content = Path(text).read_text(encoding="utf-8").strip()
        data = json.loads(content) if content.startswith("{") else None
    except ValueError as exc:  # binary file or broken JSON
        raise CLIError(f"{text}: not a key file (expected keygen JSON or a key expression)") from exc
    if data is not None:
        if not data.get("xprv_expression"):
            raise CLIError(f"{text}: JSON has no xprv_expression (public-only cosigner file?)")
        return data["xprv_expression"]
    return content


def cmd_keygen(args) -> int:
    cosigner = generate_cosigner(args.label, args.seed, args.origin, args.network or "regtest")
    if args.seed is not None:
        print("note: keys derived from --seed are public to anyone who knows the seed text; demo and test use only", file=sys.stderr)
    emit(json.dumps(cosigner, indent=2), args.output, mode=0o600)  # the file holds an xprv
    return 0


def cmd_makewallet(args) -> int:
    cosigners = [cosigner_from_text(k) for k in args.keys]
    fps = [c.fingerprint_hex for c in cosigners]
    if len(set(fps)) != len(fps):
        raise CLIError("duplicate cosigner fingerprints: " + ", ".join(fps))
    network = args.network or "regtest"
    if args.wpkh:
        name = args.name or "bip322-wpkh"
    else:
        if args.threshold is None:
            raise CLIError("--threshold is required for a multisig wallet (or use --wpkh with one key)")
        name = args.name or f"bip322-{args.threshold}of{len(cosigners)}"
    wallet = wallet_from_cosigners(args.threshold, cosigners, network=network, name=name, wpkh=args.wpkh)
    emit(wallet.to_descriptor(), args.output)
    info = wallet.describe()
    info["first_address"] = wallet.derive(0).address
    print(json.dumps({k: info[k] for k in ("name", "network", "policy", "script", "first_address")}, indent=2), file=sys.stderr)
    return 0


def cmd_signpsbt(args) -> int:
    psbt = read_psbt(args.psbt)
    info = inspect_psbt(psbt, network=network_of(args) or "main")
    if not info.is_bip322 and not args.force:
        raise CLIError("refusing to sign: not a well-formed BIP-322 PSBT: " + "; ".join(info.problems))
    total = 0
    for key in args.keys:
        total += sign_psbt(psbt, _read_signer_key(key))
    if total == 0:
        raise CLIError("no signatures added (key does not match any input derivation)")
    write_psbt(psbt, args.output, binary=args.binary)
    print(f"added {total} signature(s)", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bip322-dev", description="bip322 scaffolding that handles private keys: dummy cosigners, wallet assembly, software signing"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="generate a dummy cosigner (fingerprint, xpub/xprv key expressions) for tests")
    p.add_argument("--label", default="cosigner")
    p.add_argument("--seed", help="derive deterministically from this text (omit for random); refused with --network main")
    p.add_argument("--origin", default="48h/0h/0h/2h", help="BIP32 origin path (default: BIP-48 P2WSH multisig account 0)")
    add_option(p, "network", "key and address encoding (default: regtest)")
    add_option(p, "output", "write the JSON here instead of stdout (mode 0600)")
    p.description = (
        "Generate a dummy cosigner for tests and demos: fingerprint, origin, xpub and xprv key expressions. Never for real funds."
    )
    p.set_defaults(func=cmd_keygen, examples=['keygen --label A --seed "demo cosigner A" -o cosigner-A.json', "keygen --origin 84h/0h/0h"])

    p = sub.add_parser("makewallet", help="write a checksummed wsh(sortedmulti(...)) or wpkh(...) descriptor from keys")
    p.add_argument("keys", nargs="+", help="cosigners: keygen JSON files or [fp/path]xpub expressions")
    p.add_argument("--threshold", "-t", type=int, help="signatures required (the k in k-of-n); multisig only")
    p.add_argument("--wpkh", action="store_true", help="single-key P2WPKH wallet (exactly one key, no threshold)")
    p.add_argument("--name", help="wallet name (default bip322-<k>of<n>)")
    add_option(p, "network", "key and address encoding (default: regtest)")
    add_option(p, "output", "write the descriptor here instead of stdout")
    p.description = "Assemble a checksummed wsh(sortedmulti(k,...)) or wpkh(...) descriptor from cosigner keys."
    p.set_defaults(
        func=cmd_makewallet,
        examples=["makewallet -t 2 cosigner-A.json cosigner-B.json cosigner-C.json -o wallet.desc", "makewallet --wpkh key.json"],
    )

    p = sub.add_parser("signpsbt", help="add signatures with software keys (like Bitcoin Core's signrawtransactionwithkey: PSBT then keys)")
    p.add_argument("psbt", help="BIP-322 PSBT file (base64 or binary) or - for stdin")
    p.add_argument("keys", nargs="+", metavar="KEY", help="xprv, [fp/path]xprv expression, WIF, or a keygen JSON file")
    add_option(p, "network", "address network for the report (default: main)")
    p.add_argument("--force", action="store_true", help="sign even if the PSBT fails the BIP-322 checks")
    add_psbt_output_options(p)
    p.description = (
        "Add partial signatures to a BIP-322 PSBT with software keys; refuses PSBTs that fail the BIP-322 checks unless --force. "
        "A key on the command line is visible in the process list and the shell history: test keys only."
    )
    p.set_defaults(
        func=cmd_signpsbt,
        examples=[
            "signpsbt proof.psbt cosigner-A.json -o proof-A.psbt",
            "signpsbt proof-A.psbt '[fp/48h/0h/0h/2h]xprv.../<0;1>/*' > proof-AB.psbt",
        ],
    )

    add_help_command("bip322-dev", sub, {"Keys and signing": ["keygen", "makewallet", "signpsbt", "help"]})
    return parser


def _run(argv: list[str] | None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


def main(argv: list[str] | None = None) -> int:
    return run_cli(lambda: _run(argv))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
