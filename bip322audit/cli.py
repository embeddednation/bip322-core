"""``bip322-audit``: snapshot, finalize, verify (and stamp, help)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from bip322._version import SPEC
from bip322.cli import CLIError, _emit, add_help_command
from bip322.core import BIP322Error
from bip322.wallet import Wallet, wallet_from_file

from . import TOOL
from .audit import AuditError, finalize_bundle, format_report, load_proofs, verify_proofs
from .rpc import BitcoinCli, RpcError, btc
from .snapshot import DEFAULT_DEPTH, check_wallet_against_node, take_snapshot, wallet_from_node, write_bundle
from .stamp import fetch_stamp

DEFAULT_TEMPLATE = "Proof of control {date}"


def _opt(args, name: str):
    """A node option given after the subcommand wins over the same option given before it."""
    return getattr(args, f"{name}_sub", None) or getattr(args, name, None)


def _cli(args) -> BitcoinCli:
    cli = BitcoinCli(_opt(args, "cli") or "bitcoin-cli")
    wallet = _opt(args, "wallet")
    if wallet:
        cli.argv.append(f"-rpcwallet={wallet}")
    return cli


def _add_node_args(p: argparse.ArgumentParser, wallet: bool = True) -> None:
    p.add_argument("--cli", dest="cli_sub", metavar="CMD", help="how to reach the node (may also be given before the command)")
    if wallet:
        p.add_argument("--wallet", "-w", dest="wallet_sub", metavar="NAME", help="the node wallet (may also be given before the command)")


def _wallet(args, cli: BitcoinCli) -> Wallet:
    """The wallet: from --descriptor (file or text, cross-checked against the node) or from the node wallet itself."""
    chain = cli.chain()
    network = {"main": "main", "test": "test", "regtest": "regtest", "signet": "signet"}.get(chain, chain)
    if getattr(args, "descriptor", None):
        text = args.descriptor
        wallet = wallet_from_file(text, network=network) if Path(text).is_file() else Wallet.from_descriptor(text, network=network)
        check_wallet_against_node(cli, wallet)
        return wallet
    return wallet_from_node(cli, chain)


def cmd_stamp(args) -> int:
    print(fetch_stamp(_cli(args), args.depth).line())
    return 0


def cmd_snapshot(args) -> int:
    cli = _cli(args)
    wallet = _wallet(args, cli)
    snapshot, psbts = take_snapshot(
        cli, wallet, args.text, depth=args.depth, source=args.source,
        coldcard_strict=not args.allow_non_coldcard, max_index=args.max_index, utxo_mode=args.utxo,
        progress=lambda line: print(line, file=sys.stderr),
    )
    directory = Path(args.output) if args.output else Path(f"snapshot-{snapshot.stamp.time[:10]}-{snapshot.stamp.height}")
    if directory.exists() and any(directory.iterdir()) and not args.force:
        raise CLIError(f"{directory} exists and is not empty (use --force to add to it)")
    write_bundle(directory, snapshot, psbts)
    print(json.dumps({"directory": str(directory), "stamp": snapshot.stamp.to_dict(), "source": snapshot.source, "policy": snapshot.policy,
                      "addresses": len(snapshot.addresses), "utxos": sum(len(a["utxos"]) for a in snapshot.addresses),
                      "total_sat": snapshot.total_sat, "total_btc": btc(snapshot.total_sat), "message": snapshot.message,
                      "psbts": {a["file"]: f"{a['address']} ({btc(a['total_sat'])} BTC)" for a in snapshot.addresses}}, indent=2), file=sys.stderr)
    print(str(directory))
    return 0


def cmd_finalize(args) -> int:
    directory = Path(args.directory)
    document = finalize_bundle(directory, lenient=args.lenient)
    out = Path(args.output) if args.output else directory / "proofs.json"
    out.write_text(json.dumps(document, indent=2) + "\n")
    total = sum(p["total_sat"] for p in document["proofs"])
    print(json.dumps({"proofs": len(document["proofs"]), "total_sat": total, "total_btc": btc(total), "written": str(out)}, indent=2), file=sys.stderr)
    print(str(out))
    return 0


def cmd_verify(args) -> int:
    document = load_proofs(Path(args.proofs))
    cli = None if args.offline else _cli(args)
    engines = args.engines.split(",") if args.engines else None
    report = verify_proofs(document, cli, engines=engines, txindex=args.txindex, scan=args.scan)
    if args.report:
        Path(args.report).write_text(json.dumps(report, indent=2, default=str) + "\n")
    _emit(json.dumps(report, indent=2, default=str) if args.json else format_report(report), args.output)
    return 0 if report["ok"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bip322-audit", description=f"Proof of control of a wallet's coins at a point in time: BIP-322 proofs plus on-chain checks through bitcoin-cli ({SPEC}).")
    parser.add_argument("--version", action="version", version=f"{TOOL} ({SPEC})")
    parser.add_argument("--cli", default=None, metavar="CMD", help='how to reach the node, e.g. "bitcoin-cli -signet" or "bitcoin-cli -rpcconnect=10.0.0.5" (default: bitcoin-cli)')
    parser.add_argument("--wallet", "-w", default=None, metavar="NAME", help="the node wallet (bitcoin-cli -rpcwallet=NAME); required when several are loaded. Its descriptor is read from the node. May also follow the command.")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("stamp", help="print the block stamp line for a message", description="Print `block: HEIGHT HASH TIME` for the block DEPTH blocks behind the node's tip.")
    p.add_argument("--depth", type=int, default=DEFAULT_DEPTH, help=f"blocks behind the tip (default {DEFAULT_DEPTH})")
    _add_node_args(p, wallet=False)
    p.set_defaults(func=cmd_stamp, examples=["stamp", "--cli 'bitcoin-cli -signet' stamp --depth 3"])
    p.description += " No wallet is needed."

    p = sub.add_parser("snapshot", help="stamp, funded addresses, message and one PSBT per address into a directory",
                       description=("Take the snapshot: read the wallet descriptor from the node wallet (or --descriptor), choose the stamp block "
                                    "(tip - DEPTH), find the wallet's coins confirmed at that block "
                                    "(listunspent on the node wallet, or a scantxoutset of the descriptor), compose the message from the template "
                                    "plus the stamp line, and write snapshot.json, message.txt and to_sign-NN.psbt per funded address (the address of each is in snapshot.json). "
                                    "Sign the PSBTs on the cosigners' devices and put the results in <dir>/signed/."))
    _add_node_args(p)
    p.add_argument("--descriptor", "-d", metavar="FILE|DESC", help="use this descriptor (a file or the text) instead of the node wallet's own; it must be one of the wallet's descriptors")
    p.add_argument("--text", default=DEFAULT_TEMPLATE, help="message template; {date} {time} {height} {hash} are filled from the stamp block (default: '%(default)s')")
    p.add_argument("--depth", type=int, default=DEFAULT_DEPTH, help=f"stamp/snapshot block is this many blocks behind the tip (default {DEFAULT_DEPTH})")
    p.add_argument("--source", choices=["auto", "listunspent", "scantxoutset"], default="auto", help="where to find the coins (auto: the node's wallet via listunspent when one is loaded, else a scantxoutset of the descriptor)")
    p.add_argument("--max-index", type=int, default=1000, help="derivation range to consider per branch")
    p.add_argument("--utxo", choices=["witness", "both"], default="witness", help="UTXO fields to embed in the PSBTs")
    p.add_argument("--allow-non-coldcard", action="store_true", help="do not insist on Coldcard's message rules")
    p.add_argument("--output", "-o", metavar="DIR", help="bundle directory (default snapshot-<date>-<height>)")
    p.add_argument("--force", action="store_true", help="write into a non-empty directory")
    p.set_defaults(func=cmd_snapshot, examples=["-w treasury snapshot --text 'Annual audit {date}'",
                                                "--cli 'bitcoin-cli -signet' -w watch snapshot",
                                                "snapshot -d wallet.desc --source scantxoutset -o audit-2026"])

    p = sub.add_parser("finalize", help="combine and finalize the signed PSBTs of a bundle into proofs.json",
                       description="Read every PSBT in <dir> and <dir>/signed/, group them by address, combine, finalize, self-verify, and write proofs.json.")
    p.add_argument("directory", metavar="DIR", help="the snapshot bundle directory")
    p.add_argument("--lenient", action="store_true", help="skip invalid partial signatures instead of failing")
    p.add_argument("--output", "-o", metavar="FILE", help="proofs file (default DIR/proofs.json)")
    p.set_defaults(func=cmd_finalize, examples=["finalize snapshot-2026-09-14-912345"])

    p = sub.add_parser("verify", help="auditor side: verify proofs.json against the node and report",
                       description=("Verify every BIP-322 signature, check the stamp block with getblockheader, check every listed output with "
                                    "gettxout (amount, address, creation height), and print a report. Exit 0 when the signatures, the stamp and the "
                                    "outputs' existence at the snapshot all check out; coins spent since are reported, not failures."))
    p.add_argument("proofs", metavar="PROOFS", help="proofs.json or the bundle directory")
    _add_node_args(p, wallet=False)
    p.add_argument("--offline", action="store_true", help="verify the signatures only (no node)")
    p.add_argument("--txindex", action="store_true", help="use getrawtransaction (node with -txindex) to explain outputs no longer in the UTXO set")
    p.add_argument("--scan", action="store_true", help="also scantxoutset the proven addresses for their holdings now")
    p.add_argument("--engines", default=None, help="comma separated bip322 engines (default: all installed)")
    p.add_argument("--json", action="store_true", help="print the JSON report instead of the summary")
    p.add_argument("--report", metavar="FILE", help="also write the JSON report here")
    p.add_argument("--output", "-o", metavar="FILE", help="write the printed output here instead of stdout")
    p.set_defaults(func=cmd_verify, examples=["verify snapshot-2026-09-14-912345", "verify proofs.json --json --report audit-report.json", "verify proofs.json --offline"])

    add_help_command("bip322-audit", sub, {"Workflow": ["stamp", "snapshot", "finalize", "verify", "help"]})
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (CLIError, BIP322Error, RpcError, AuditError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc.strerror or exc}: {exc.filename}" if getattr(exc, "filename", None) else f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
