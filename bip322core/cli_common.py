"""What the command line programs share: the error type and its handler, PSBT and artifact I/O, the options many commands define."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from pathlib import Path

from embit.networks import NETWORKS

from .core import BIP322Error
from .psbt import BIP322PSBT, parse_psbt

__all__ = ["CLIError", "add_option", "add_psbt_output_options", "emit", "network_of", "read_psbt", "run_cli", "write_psbt"]


class CLIError(Exception):
    """A usage or input error: reported as one ``error: ...`` line on stderr, exit code 2."""


def run_cli(body: Callable[[], int]) -> int:
    """Run ``body`` (parse one command line and execute it) and return the exit code.

    Every exception becomes one ``error: ...`` line on stderr and exit code 2:
    never a traceback, and never exit 1, which means "invalid" on the commands
    that give a verdict.  argparse's own exits (usage errors, ``--help``) pass through.
    """
    try:
        return body()
    except (CLIError, BIP322Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc.strerror or exc}: {exc.filename}" if getattr(exc, "filename", None) else f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - last resort: 1 means "invalid", so nothing unexpected may exit with it
        print(f"error: unexpected {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


def network_of(args: argparse.Namespace) -> str | None:
    """``--network`` as given after the subcommand, else before it, else None (each command has its own default)."""
    return getattr(args, "network", None) or getattr(args, "global_network", None)


def read_psbt(path: str) -> BIP322PSBT:
    data = Path(path).read_bytes() if path != "-" else sys.stdin.buffer.read()
    return parse_psbt(data)


def emit(text: str, path: str | None, mode: int | None = None) -> None:
    """Write a command's artifact: to stdout, or to ``path`` with nothing on stdout.

    ``text`` gets a final newline if it has none.  ``path`` None or ``-`` means
    stdout; any other path is created or truncated.  ``mode`` sets the file's
    permission bits (0o600 for a file holding private keys), also on a file
    that already exists; it is ignored for stdout.  Raises OSError when the
    file cannot be written.
    """
    text = text if text.endswith("\n") else text + "\n"
    if path is None or path == "-":
        sys.stdout.write(text)
    elif mode is None:
        Path(path).write_text(text)
    else:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "w") as fh:
            os.fchmod(fd, mode)  # an existing file keeps its old bits otherwise
            fh.write(text)


def write_psbt(psbt: BIP322PSBT, path: str | None, binary: bool = False) -> None:
    if path is None or path == "-":
        if binary:
            raise CLIError("--binary needs a file to write to (-o FILE); stdout carries base64")
        print(psbt.to_string())
        return
    out = Path(path)
    if binary:
        out.write_bytes(psbt.serialize())
    else:
        out.write_text(psbt.to_string() + "\n")


# The options that many commands define.  Flags, type and default live here once;
# the help text is each command's own, because what the option means differs
# (where the output goes, what the network is used for).
_OPTIONS: dict[str, tuple[tuple[str, ...], dict]] = {
    "network": (("--network",), {"choices": sorted(NETWORKS), "default": None}),
    "output": (("--output", "-o"), {}),
    "json": (("--json",), {"action": "store_true"}),
    "engines": (("--engines",), {"default": None}),
    "max-index": (("--max-index",), {"type": int, "default": 500}),
}


def add_option(parser: argparse.ArgumentParser, name: str, help: str, **overrides) -> None:  # noqa: A002 - argparse's own word
    """Add one of the shared options (``network``, ``output``, ``json``, ``engines``, ``max-index``) with this command's help text."""
    flags, kwargs = _OPTIONS[name]
    parser.add_argument(*flags, help=help, **{**kwargs, **overrides})


def add_psbt_output_options(parser: argparse.ArgumentParser) -> None:
    """``-o`` and ``--binary`` of the commands whose artifact is a PSBT."""
    add_option(parser, "output", "write the PSBT here instead of stdout (base64)")
    parser.add_argument("--binary", action="store_true", help="write the PSBT in binary instead of base64")
