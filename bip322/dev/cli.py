"""``bip322-dev``: the commands that handle private keys (keygen, makewallet, signpsbt)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from embit.networks import NETWORKS

from ..cli import CLIError, _add_output_args, _emit, _network, _read_psbt, _write_psbt
from ..core import BIP322Error
from ..psbt import inspect_psbt
from ..wallet import WalletError
from .keys import cosigner_from_text, generate_cosigner, wallet_from_cosigners
from .signing import sign_psbt


def _read_signer_key(text: str) -> str:
    """``-k`` accepts a key string, a keygen JSON file, or a file holding the key."""
    if not Path(text).is_file():
        return text
    content = Path(text).read_text(encoding="utf-8").strip()
    if content.startswith("{"):
        data = json.loads(content)
        if not data.get("xprv_expression"):
            raise CLIError(f"{text}: JSON has no xprv_expression (public-only cosigner file?)")
        return data["xprv_expression"]
    return content


def cmd_keygen(args) -> int:
    _emit(json.dumps(generate_cosigner(args.label, args.seed, args.origin, args.network or "main"), indent=2), args.output)
    return 0


def cmd_makewallet(args) -> int:
    cosigners = [cosigner_from_text(k) for k in args.keys]
    fps = [c.fingerprint_hex for c in cosigners]
    if len(set(fps)) != len(fps):
        raise CLIError("duplicate cosigner fingerprints: " + ", ".join(fps))
    network = args.network or "main"
    if args.wpkh:
        name = args.name or "bip322-wpkh"
    else:
        if args.threshold is None:
            raise CLIError("--threshold is required for a multisig wallet (or use --wpkh with one key)")
        name = args.name or f"bip322-{args.threshold}of{len(cosigners)}"
    wallet = wallet_from_cosigners(args.threshold, cosigners, network=network, name=name, wpkh=args.wpkh)
    _emit(wallet.to_descriptor(), args.output)
    info = wallet.describe()
    info["first_address"] = wallet.derive(0).address
    print(json.dumps({k: info[k] for k in ("name", "network", "policy", "script", "first_address")}, indent=2), file=sys.stderr)
    return 0


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bip322-dev", description="bip322 scaffolding that handles private keys: dummy cosigners, wallet assembly, software signing")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="generate a dummy cosigner (fingerprint, xpub/xprv key expressions) for tests")
    p.add_argument("--label", default="cosigner")
    p.add_argument("--seed", help="derive deterministically from this text (omit for random)")
    p.add_argument("--origin", default="48h/0h/0h/2h", help="BIP32 origin path (default: BIP-48 P2WSH multisig account 0)")
    p.add_argument("--network", choices=sorted(NETWORKS), default=None)
    p.add_argument("--output", "-o", help="write the JSON here instead of stdout")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("makewallet", help="write a checksummed wsh(sortedmulti(...)) or wpkh(...) descriptor from keys")
    p.add_argument("keys", nargs="+", help="cosigners: keygen JSON files or [fp/path]xpub expressions")
    p.add_argument("--threshold", "-t", type=int, help="signatures required (the k in k-of-n); multisig only")
    p.add_argument("--wpkh", action="store_true", help="single-key P2WPKH wallet (exactly one key, no threshold)")
    p.add_argument("--name", help="wallet name (default bip322-<k>of<n>)")
    p.add_argument("--network", choices=sorted(NETWORKS), default=None)
    p.add_argument("--output", "-o", help="write the descriptor here instead of stdout")
    p.set_defaults(func=cmd_makewallet)

    p = sub.add_parser("signpsbt", help="add signatures with software keys (tests / non-hardware cosigners)")
    p.add_argument("psbt")
    p.add_argument("--key", "-k", action="append", required=True, help="xprv, [fp/path]xprv expression, WIF, or a keygen JSON file (repeatable)")
    p.add_argument("--network", choices=sorted(NETWORKS), default=None)
    p.add_argument("--force", action="store_true", help="sign even if the PSBT fails the BIP-322 checks")
    _add_output_args(p)
    p.set_defaults(func=cmd_sign)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (CLIError, BIP322Error, WalletError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
