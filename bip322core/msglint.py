"""Message lint for hardware signers.

BIP-322 allows any byte string as the message.  A signing device has to show
the message to the person approving it, and devices are stricter than the
BIP: the profile below is one every BIP-322-capable device is expected to
display and sign: 2 to 330 printable ASCII characters, newline and tab
allowed, no leading or trailing space, newline or tab, no run of three spaces.  A message
inside it can be read on a small screen exactly as it will be signed.
"""

from __future__ import annotations

__all__ = [
    "MESSAGE_MAX",
    "MESSAGE_MIN",
    "lint_message",
]

MESSAGE_MAX = 330
MESSAGE_MIN = 2


def lint_message(message: bytes) -> list[str]:
    """Return the reasons a hardware signer may refuse to display or sign ``message``; empty when it fits the profile."""
    problems: list[str] = []
    try:
        text = bytes(message).decode("ascii")
    except UnicodeDecodeError:
        return ["message is not ASCII (signing devices display ASCII only)"]
    for ch in text:
        code = ord(ch)
        if ch in "\n\t":
            continue
        if code < 32 or code > 126:
            problems.append(f"non-printable character {ch!r}")
            break
    if len(text) < MESSAGE_MIN:
        problems.append(f"message too short (min {MESSAGE_MIN} characters)")
    if len(text) > MESSAGE_MAX:
        problems.append(f"message too long (max {MESSAGE_MAX} characters)")
    if "   " in text:
        problems.append("three or more consecutive spaces")
    if text[:1] == " ":
        problems.append("leading space")
    if text[-1:] == " ":
        problems.append("trailing space")
    # a file's final newline is signed like any other byte, and the typed message then no longer verifies
    if text[:1] in ("\n", "\t"):
        problems.append("leading newline or tab")
    if text[-1:] in ("\n", "\t"):
        problems.append("trailing newline or tab")
    return problems
