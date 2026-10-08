"""Core-style help (``help`` lists commands by group, ``help CMD`` shows one) and git-style extensions (``prog NAME`` runs ``prog-NAME``)."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .cli_common import CLIError

__all__ = ["add_help_command", "dispatch_extension", "extension_path", "format_command_help", "format_help_listing", "list_extensions"]


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


def _extension_dirs() -> list[str]:
    """Where extensions are looked up: next to this program, then PATH; never relative to the current directory."""
    dirs = []
    if os.sep in sys.argv[0]:  # not a path (python -c, an embedding program): resolve() would give the current directory
        dirs.append(str(Path(sys.argv[0]).resolve().parent))
    return dirs + [d for d in (os.environ.get("PATH") or "").split(os.pathsep) if os.path.isabs(d)]


def _extension_name_ok(name: str) -> bool:
    return bool(name) and not name.startswith("-") and name.replace("-", "").replace("_", "").isalnum()


def extension_path(prog: str, name: str) -> str | None:
    """The executable behind ``prog NAME``: ``prog-NAME`` next to this program, else on PATH."""
    if not _extension_name_ok(name):
        return None
    for d in _extension_dirs():
        candidate = os.path.join(d, f"{prog}-{name}")
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def list_extensions(prog: str) -> list[str]:
    """Names of the ``prog-*`` executables reachable as ``prog NAME`` (exactly those ``extension_path`` finds)."""
    found: dict[str, None] = {}
    for d in _extension_dirs():
        try:
            entries = sorted(os.listdir(d))
        except OSError:
            continue
        for entry in entries:
            name = entry[len(prog) + 1 :]
            if entry.startswith(f"{prog}-") and _extension_name_ok(name) and extension_path(prog, name):
                found.setdefault(name, None)
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
        _exec(path, [path, *argv[1:]])


def _exec(path: str, argv: list[str]) -> None:
    try:
        os.execv(path, argv)
    except OSError as exc:  # no shebang, missing interpreter
        raise CLIError(f"cannot run extension {path}: {exc.strerror or exc}") from exc


def add_help_command(prog: str, sub: argparse._SubParsersAction, groups: dict[str, list[str]]) -> None:  # noqa: SLF001
    """Register ``help [COMMAND]`` on ``sub``, the object ``parser.add_subparsers()`` returned.

    Call it after every other command is added.  ``prog`` is the program name
    shown in the output and the prefix of its extensions (``prog-NAME``).
    ``groups`` maps a heading to the command names listed under it, in order:
    a command that is in no group is not listed (``help NAME`` still shows
    it), and a name that is not a command of ``sub`` is a KeyError when the
    listing is printed.  ``help NAME`` prints the command's signature, its
    ``description``, arguments, options and the lines given to it with
    ``set_defaults(examples=[...])``, each shown after ``> prog``.  A NAME
    that is no command but an extension is handed to ``prog-NAME help``;
    anything else raises CLIError.
    """
    p = sub.add_parser("help", help="list commands, or show one command's syntax, options and examples")
    p.add_argument("name", nargs="?", metavar="COMMAND")

    def cmd_help(args) -> int:
        if not args.name:
            print(format_help_listing(prog, sub, groups))
            extensions = [e for e in list_extensions(prog) if e not in sub.choices]
            if extensions:
                print(f"\nExtensions ({prog} NAME ...): " + ", ".join(extensions) + f'. Use "{prog} NAME help".')
            return 0
        if args.name not in sub.choices:
            path = extension_path(prog, args.name)
            if path:
                _exec(path, [path, "help"])
            raise CLIError(f"unknown command {args.name!r}; try '{prog} help'")
        sys.stdout.write(format_command_help(prog, args.name, sub.choices[args.name]))
        return 0

    p.set_defaults(func=cmd_help)
