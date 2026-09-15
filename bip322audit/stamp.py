"""The block stamp: ``block: HEIGHT HASH ISO-8601-TIME`` as the last line of a message.

The hash makes the message impossible to have written before that block
existed (a *not before* bound); the height and the block's own header time
make it readable and checkable with one ``getblockheader`` call.  All three
come from the block, so the stamp is verifiable as a whole.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone

from .rpc import BitcoinCli

STAMP_RE = re.compile(r"^block: (\d+) ([0-9a-f]{64}) (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)$", re.M)
DEFAULT_DEPTH = 6


def iso_utc(unix_time: int) -> str:
    return datetime.fromtimestamp(int(unix_time), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class Stamp:
    height: int
    hash: str
    time: str  # ISO 8601 UTC of the block header time

    def line(self) -> str:
        return f"block: {self.height} {self.hash} {self.time}"

    def to_dict(self) -> dict:
        return {"height": self.height, "hash": self.hash, "time": self.time}

    @classmethod
    def from_dict(cls, d: dict) -> Stamp:
        return cls(int(d["height"]), str(d["hash"]), str(d["time"]))


def fetch_stamp(cli: BitcoinCli, depth: int = DEFAULT_DEPTH) -> Stamp:
    """The block ``depth`` blocks behind the tip (default 6: safe from reorgs, an hour of slack)."""
    if depth < 0:
        raise ValueError("depth must be >= 0")
    tip_height, _ = cli.tip()
    height = tip_height - depth
    if height < 0:
        raise ValueError(f"chain has only {tip_height + 1} blocks; depth {depth} is too large")
    block_hash = cli.block_hash(height)
    header = cli.block_header(block_hash)
    return Stamp(height=int(header["height"]), hash=block_hash, time=iso_utc(header["time"]))


def parse_stamp(message: bytes | str) -> Stamp | None:
    """The stamp on the message's last line, or None."""
    text = message.decode("utf-8", errors="replace") if isinstance(message, bytes) else message
    last = text.rstrip("\n").rsplit("\n", 1)[-1]
    match = STAMP_RE.match(last)
    if not match:
        return None
    return Stamp(int(match.group(1)), match.group(2), match.group(3))


def compose_message(template: str, stamp: Stamp) -> str:
    """``template`` with ``{date}``/``{time}``/``{height}``/``{hash}`` filled in, then the stamp line."""
    text = template.format(date=stamp.time[:10], time=stamp.time, height=stamp.height, hash=stamp.hash).rstrip()
    return f"{text}\n{stamp.line()}" if text else stamp.line()


def check_stamp(cli: BitcoinCli, stamp: Stamp) -> dict:
    """Compare the stamp with the node's view of that block."""
    result = {"stamp": stamp.to_dict(), "ok": False}
    try:
        header = cli.block_header(stamp.hash)
    except Exception as exc:  # noqa: BLE001 - unknown hash is the interesting outcome, not a crash
        result["error"] = f"block hash unknown to this node: {exc}"
        return result
    confirmations = int(header.get("confirmations", -1))
    result.update(
        {
            "node_height": int(header["height"]),
            "node_time": iso_utc(header["time"]),
            "confirmations": confirmations,
            "in_main_chain": confirmations > 0,
            "height_matches": int(header["height"]) == stamp.height,
            "time_matches": iso_utc(header["time"]) == stamp.time,
        }
    )
    result["ok"] = result["in_main_chain"] and result["height_matches"] and result["time_matches"]
    return result
