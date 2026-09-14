"""Coldcard-specific checks.

Coldcard (firmware 5.5.1 / 1.4.1Q and later) signs BIP-322 PSBTs as a
"PSBT signer".  Its message rules, taken from ``docs/proof-of-reserves-bip-322.md``
and ``shared/msgsign.py`` in the firmware repository, are stricter than the BIP:
"""

from __future__ import annotations

COLDCARD_MAX_MESSAGE = 330
COLDCARD_MIN_MESSAGE = 2


def lint_message_for_coldcard(message: bytes) -> list[str]:
    """Return a list of reasons a Coldcard would refuse to display/sign ``message``."""
    problems: list[str] = []
    try:
        text = bytes(message).decode("ascii")
    except UnicodeDecodeError:
        return ["message is not ASCII (Coldcard only displays ASCII)"]
    for ch in text:
        code = ord(ch)
        if ch in "\n\t":
            continue
        if code < 32 or code > 126:
            problems.append(f"non-printable character {ch!r}")
            break
    if len(text) < COLDCARD_MIN_MESSAGE:
        problems.append(f"message too short (min {COLDCARD_MIN_MESSAGE} characters)")
    if len(text) > COLDCARD_MAX_MESSAGE:
        problems.append(f"message too long (max {COLDCARD_MAX_MESSAGE} characters)")
    if "   " in text:
        problems.append("three or more consecutive spaces")
    if text[:1] == " ":
        problems.append("leading space")
    if text[-1:] == " ":
        problems.append("trailing space")
    return problems
