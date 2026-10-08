"""The argument parser of ``bip322``: every command, its arguments, options, description and examples."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping

from ._version import SPEC, __version__
from .cli_common import add_option, add_psbt_output_options
from .cli_help import add_help_command

__all__ = ["DASH_NOTE", "MESSAGE_HELP", "make_parser"]

#: command name -> the function that runs it (takes the parsed arguments, returns the exit code)
Commands = Mapping[str, Callable[[argparse.Namespace], int]]


def _has_flag(argv: list[str], flag: str) -> bool:
    """Was ``flag`` given (before any ``--``)?  Its value then does not come as a positional argument."""
    head = argv[: argv.index("--")] if "--" in argv else argv
    return any(a == flag or a.startswith(flag + "=") for a in head)


def _add_wallet_args(p: argparse.ArgumentParser) -> None:
    g = p.add_mutually_exclusive_group()
    g.add_argument("--wallet", "-w", help="file holding the wallet descriptor: wsh(sortedmulti(...)) or wpkh(...)")
    g.add_argument("--descriptor", "-d", help="descriptor text: wsh(sortedmulti(...)) or wpkh(...)")
    add_option(p, "network", "address network (default: from the key versions, xpub = main, tpub = test)")


def _add_message_file(p: argparse.ArgumentParser) -> None:
    p.add_argument("--message-file", metavar="FILE", help="take the message's exact bytes from FILE instead of the MESSAGE argument")


MESSAGE_HELP = "the message text (UTF-8); after -- when it starts with a dash"
DASH_NOTE = (
    "Options may stand before, between or after the arguments. A message that starts with a dash goes after --, "
    "or comes from --message-file; this command has no -h, use `help`."
)


def _free_text_usage(p: argparse.ArgumentParser, arguments: str) -> None:
    """A usage line that says where a dash-leading message goes: that is what a usage error here is mostly about."""
    p.usage = f"{p.prog} [options] {arguments}\n       a MESSAGE that starts with a dash goes after --; `bip322 help {p.prog.split()[-1]}` shows the options"


def make_parser(argv: list[str] | None, commands: Commands) -> argparse.ArgumentParser:
    """The parser for ``argv``: a value given by ``--signature-file``/``--message-file`` is not expected as a positional.

    ``commands`` gives the function behind every command name.

    The commands that take free text (a message) have no ``-h``: a message
    that reads ``-h`` must never turn a verdict command into "help, exit 0".
    """
    argv = list(argv or [])
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
    add_option(parser, "network", "address network (default: from the key versions, xpub = main, tpub = test)", dest="global_network")
    sub = parser.add_subparsers(dest="command", required=True)
    _wallet_commands(sub, commands)
    _psbt_commands(sub, argv, commands)
    _verification_commands(sub, argv, commands)
    _util_commands(sub, argv, commands)
    add_help_command(
        "bip322",
        sub,
        {
            "Wallet": ["wallet", "deriveaddresses", "getaddressinfo"],
            "PSBT": ["createpsbt", "analyzepsbt", "combinepsbt", "finalizepsbt"],
            "Verification": ["verifymessage", "checksigners"],
            "Util": ["validateaddress", "decodesignature", "lint-message", "engines", "help"],
        },
    )
    return parser


def _wallet_commands(sub, commands: Commands) -> None:
    p = sub.add_parser(
        "wallet",
        help="show wallet policy, cosigners and descriptor",
        description="Show the wallet's policy, cosigners (fingerprint, origin, xpub) and checksummed descriptor.",
    )
    _add_wallet_args(p)
    p.set_defaults(func=commands["wallet"], examples=["-w wallet.desc wallet"])

    p = sub.add_parser("deriveaddresses", help="addresses for an index or an index range (like Bitcoin Core's deriveaddresses)")
    _add_wallet_args(p)
    p.add_argument("indexes", nargs="*", type=int, metavar="INDEX | START END", help="a single index, or an inclusive range; default 0")
    p.add_argument("--change", action="store_true", help="change branch instead of receive")
    add_option(p, "json", "objects with branch/index instead of bare addresses")
    p.description = "Derive the wallet's addresses for one index or an inclusive index range, one per line."
    p.set_defaults(
        func=commands["deriveaddresses"],
        examples=["-w wallet.desc deriveaddresses 0 5", "-w wallet.desc deriveaddresses 3 --change", "-w wallet.desc deriveaddresses"],
    )

    p = sub.add_parser("getaddressinfo", help="look an address up in the wallet (like Bitcoin Core's getaddressinfo)")
    _add_wallet_args(p)
    p.add_argument("address", help="the address to look up")
    add_option(p, "max-index", "how far to search each branch")
    p.description = (
        "Report whether the address belongs to the wallet and how it is built: script, public keys, key paths, branch/index, descriptor."
    )
    p.set_defaults(func=commands["getaddressinfo"], examples=["-w wallet.desc getaddressinfo bc1q..."])


def _psbt_commands(sub, argv: list[str], commands: Commands) -> None:
    p = sub.add_parser("createpsbt", add_help=False, help="create the BIP-322 to_sign PSBT for a wallet address and a message")
    _add_wallet_args(p)
    p.add_argument("address", help="the wallet address to sign for (searched in the wallet)")
    if not _has_flag(argv, "--message-file"):
        p.add_argument("message", metavar="MESSAGE", help=MESSAGE_HELP)
    _add_message_file(p)
    _free_text_usage(p, "ADDRESS MESSAGE")
    add_option(p, "max-index", "how far to search the wallet for ADDRESS")
    p.add_argument(
        "--utxo", choices=["witness", "non_witness", "both"], default="witness", help="which UTXO field(s) to include for input 0"
    )
    p.add_argument("--no-xpubs", action="store_true", help="omit PSBT_GLOBAL_XPUB entries")
    p.add_argument("--psbt-v2", action="store_true", help="emit a BIP-370 (v2) PSBT")
    p.add_argument(
        "--strict-message", action="store_true", help="fail if a hardware signer may refuse to display the message (see lint-message)"
    )
    add_psbt_output_options(p)
    p.description = (
        "Build the BIP-322 to_sign PSBT for the address and message: version 0, one input spending to_spend:0 with "
        "sequence 0, one zero-value OP_RETURN output, witness_utxo, witness script, key paths, sighash ALL, global xpubs "
        "and the message in global field 0x09. A summary goes to stderr. " + DASH_NOTE
    )
    p.set_defaults(
        func=commands["createpsbt"],
        examples=[
            '-w wallet.desc createpsbt bc1q... "proof of control 2026-09-14" --strict-message -o proof.psbt',
            "-w wallet.desc createpsbt bc1q... --message-file msg.txt > proof.psbt",
        ],
    )

    p = sub.add_parser("analyzepsbt", help="report whether a PSBT is a BIP-322 PSBT, its state and what is missing")
    p.add_argument("psbt", help="PSBT file (base64 or binary) or - for stdin")
    add_option(p, "network", "address network for the report (default: main)")
    p.description = (
        "Apply the BIP-322 PSBT-signer checks (message field, to_spend txid, OP_RETURN output, version) and report the state: "
        "address, every cosigner with whether its signature is present and verifies, finalized or not, problems and warnings. "
        "Exit 1 if it is not a BIP-322 PSBT."
    )
    p.set_defaults(func=commands["analyzepsbt"], examples=["analyzepsbt proof.psbt", "analyzepsbt - < proof.psbt"])

    p = sub.add_parser("combinepsbt", help="merge partially signed PSBTs from the cosigners")
    p.add_argument("psbts", nargs="+", metavar="PSBT", help="PSBT files signed by different cosigners")
    add_option(p, "network", "address network for the summary (default: main)")
    add_psbt_output_options(p)
    p.description = "Merge PSBTs that different cosigners signed from the same original; refuses PSBTs whose shared fields disagree."
    p.set_defaults(func=commands["combinepsbt"], examples=["combinepsbt proof-A.psbt proof-B.psbt -o proof-AB.psbt"])

    p = sub.add_parser("finalizepsbt", help="finalize a signed PSBT into the BIP-322 signature string")
    p.add_argument("psbt", help="signed PSBT file (base64 or binary) or - for stdin")
    p.add_argument(
        "--variant",
        choices=["auto", "smp", "ful", "pof"],
        default="auto",
        help="encoding to emit (default auto: smp when the BIP allows it, else ful)",
    )
    add_option(p, "network", "address network for the report (default: main)")
    p.add_argument("--lenient", action="store_true", help="skip invalid partial signatures instead of failing")
    p.add_argument(
        "--signers",
        metavar="FP[,FP...]",
        help="use only these cosigners' signatures (master fingerprints or pubkey prefixes), e.g. to prove a specific pair works",
    )
    add_option(p, "output", "write the signature (or the --json report) here instead of stdout")
    add_option(p, "json", "emit a JSON report (address, message, variant, signature, to_sign hex) instead of the bare signature")
    p.add_argument("--output-psbt", help="also write the finalized PSBT (for the pof variant or for the record)")
    p.add_argument("--binary", action="store_true", help="write --output-psbt in binary instead of base64")
    p.description = (
        "BIP-174 finalizer: check every partial signature (strict DER, low-S, SIGHASH_ALL, verifies against the sighash), "
        "build the witness, and print the encoded proof (smp when the BIP allows it, ful otherwise). Does not verify the proof."
    )
    p.set_defaults(
        func=commands["finalizepsbt"],
        examples=[
            "finalizepsbt proof-AB.psbt -o proof.sig",
            "finalizepsbt proof-ABC.psbt --signers ea34d476,7d5dc65a",
            "finalizepsbt proof-AB.psbt --variant ful --json",
        ],
    )


def _verification_commands(sub, argv: list[str], commands: Commands) -> None:
    p = sub.add_parser("checksigners", help="the whole picture of a signed PSBT: script chain, every cosigner, every threshold combination")
    p.add_argument("psbts", nargs="+", metavar="PSBT", help="the signed PSBT, or the separate files each device produced (combined here)")
    add_option(p, "network", "address network for the report (default: main)")
    add_option(p, "engines", "comma separated bip322 engines (default: all installed)")
    add_option(p, "json", "JSON report including every combination's proof")
    add_option(p, "output", "write the report here instead of stdout")
    p.description = (
        "Device health check and explanation in one: rebuild the script behind the input and show how it hashes back to "
        "the scriptPubKey and address; verify each cosigner's signature on its own; then finalize and verify one proof per "
        "threshold-sized combination of cosigners (all three pairs of a 2-of-3), showing the witness each one assembled. "
        "Exit 0 when the script matches, every signer is valid and every combination verifies."
    )
    p.set_defaults(
        func=commands["checksigners"],
        examples=[
            "checksigners proof-A.psbt proof-B.psbt proof-C.psbt",
            "checksigners combined.psbt --json -o signers-2026-09-15.json",
        ],
    )

    p = sub.add_parser("verifymessage", add_help=False, help="verify a BIP-322 signature (same argument order as Bitcoin Core's RPC)")
    p.add_argument(
        "address", metavar="ADDRESS|SCRIPTPUBKEY", help="the address, or the scriptPubKey it encodes as hex: BIP-322 proves a scriptPubKey"
    )
    if not _has_flag(argv, "--signature-file"):
        p.add_argument("signature", metavar="SIGNATURE", help="the signature string: smp/ful/pof and base64")
    if not _has_flag(argv, "--message-file"):
        p.add_argument("message", metavar="MESSAGE", help=MESSAGE_HELP)
    p.add_argument("--signature-file", metavar="FILE", help="read the signature from FILE instead of the SIGNATURE argument")
    _free_text_usage(p, "ADDRESS|SCRIPTPUBKEY SIGNATURE MESSAGE")
    _add_message_file(p)
    add_option(p, "engines", "comma separated script engines to run (default: all installed, see `engines`)")
    p.add_argument("--require-prefix", action="store_true", help="reject signatures without smp/ful/pof prefix")
    p.add_argument("--no-legacy", action="store_true", help="reject legacy BIP-137 signatures")
    add_option(p, "json", "self-contained JSON report instead of text")
    p.description = (
        "Verify a BIP-322 proof (smp, ful, pof or legacy) for the address and message with every installed script engine. "
        "Exit codes: 0 valid, 1 invalid, 3 inconclusive, 2 error (including an address that cannot be decoded). " + DASH_NOTE
    )
    p.set_defaults(
        func=commands["verifymessage"],
        examples=[
            'verifymessage bc1q... smp... "proof of control 2026-09-14"',
            'verifymessage bc1q... "proof of control 2026-09-14" --signature-file proof.sig --json',
        ],
    )
    p.epilog = "exit codes: 0 valid, 1 invalid, 3 inconclusive, 2 error"


def _util_commands(sub, argv: list[str], commands: Commands) -> None:
    p = sub.add_parser("validateaddress", help="the scriptPubKey an address encodes, and what kind of script it is (no node, no wallet)")
    p.add_argument(
        "address",
        metavar="ADDRESS|SCRIPTPUBKEY",
        help="an address, or a scriptPubKey as hex (then --network chooses the address encoding shown)",
    )
    add_option(p, "network", "address encoding for a scriptPubKey given as hex (default: main)")
    add_option(p, "json", "print JSON instead of text")
    add_option(p, "output", "write the output here instead of stdout")
    p.description = (
        "Decode an address into the scriptPubKey it stands for: the script an output is locked to and a BIP-322 proof is made for. "
        "Like Bitcoin Core's validateaddress, for any network's encoding, without a node."
    )
    p.set_defaults(func=commands["validateaddress"], examples=["validateaddress bc1q..."])

    p = sub.add_parser("decodesignature", help="open a proof string into its parts (witness stack, to_sign or PSBT)")
    p.add_argument("signature", help="an smp/ful/pof proof string, or - to read it from stdin")
    add_option(p, "network", "network for the address a witness script commits to (default: main)")
    p.add_argument(
        "--text",
        action="store_true",
        help="print text instead of JSON: each witness item, and the scriptPubKey and address a witness script or key names",
    )
    add_option(p, "output", "write the output here instead of stdout")
    p.description = (
        "Decode a BIP-322 signature: for smp the witness stack (each element labelled: dummy, signatures with their "
        "sighash byte, the witness script disassembled), for ful the whole to_sign transaction, for pof the finalized PSBT. "
        "Nothing is verified; use verifymessage for that."
    )
    p.set_defaults(func=commands["decodesignature"], examples=["decodesignature smp...", "decodesignature - < proof.sig"])

    p = sub.add_parser("lint-message", add_help=False, help="check a message against the display rules of hardware signers")
    if not _has_flag(argv, "--message-file"):
        p.add_argument("message", metavar="MESSAGE", help=MESSAGE_HELP)
    _add_message_file(p)
    _free_text_usage(p, "MESSAGE")
    p.description = (
        "Check a message against the display rules of hardware signers (2-330 printable ASCII, no leading/trailing space, newline or tab, no run of three spaces). Exit 1 when it does not fit. "
        + DASH_NOTE
    )
    p.set_defaults(func=commands["lint-message"], examples=['lint-message "proof of control 2026-09-14"'])

    p = sub.add_parser("engines", help="list available script engines", description="List the installed script engines and their versions.")
    p.set_defaults(func=commands["engines"], examples=["engines"])
