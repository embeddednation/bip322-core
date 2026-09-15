"""``bitcoin-cli`` as the only channel to a node.

Every call is a subprocess so the user's own configuration (network, cookie,
``-rpcconnect``, ``-rpcwallet``) applies unchanged and nothing here holds
credentials.  Amounts are parsed as :class:`decimal.Decimal` and converted to
satoshis exactly.
"""

from __future__ import annotations

import json
import shlex
import subprocess
from decimal import Decimal

SATOSHI = Decimal(100_000_000)


class RpcError(Exception):
    """bitcoin-cli failed or returned something unexpected."""


def btc(sat: int) -> str:
    """Satoshis as a BTC string with 8 decimals, exact."""
    return f"{Decimal(int(sat)) / SATOSHI:.8f}"


def to_sat(amount) -> int:
    """Exact BTC -> satoshi conversion for the numbers bitcoin-cli prints."""
    value = Decimal(str(amount)) * SATOSHI
    if value != value.to_integral_value():
        raise RpcError(f"amount {amount} is not a whole number of satoshis")
    return int(value)


class BitcoinCli:
    """Run ``bitcoin-cli`` with a fixed prefix, e.g. ``bitcoin-cli -signet -rpcwallet=watch``."""

    def __init__(self, command: str | list[str] = "bitcoin-cli", timeout: float = 600.0):
        self.argv = shlex.split(command) if isinstance(command, str) else list(command)
        self.timeout = timeout

    def call(self, method: str, *params):
        args = [str(p) if isinstance(p, str) else json.dumps(p) for p in params]
        try:
            proc = subprocess.run([*self.argv, method, *args], capture_output=True, text=True, timeout=self.timeout, check=False)
        except FileNotFoundError as exc:
            raise RpcError(f"cannot run {self.argv[0]!r}: {exc}") from exc
        except subprocess.TimeoutExpired as exc:
            raise RpcError(f"{method} timed out after {self.timeout}s") from exc
        if proc.returncode != 0:
            raise RpcError(f"{method}: {proc.stderr.strip() or proc.stdout.strip() or f'exit {proc.returncode}'}")
        text = proc.stdout.strip()
        if text == "":
            return None
        try:
            return json.loads(text, parse_float=Decimal)
        except json.JSONDecodeError:
            return text  # bare strings (getblockhash, getbestblockhash) come back unquoted

    # ---- convenience ------------------------------------------------------- #

    def chain(self) -> str:
        return self.call("getblockchaininfo")["chain"]

    def tip(self) -> tuple[int, str]:
        info = self.call("getblockchaininfo")
        return int(info["blocks"]), info["bestblockhash"]

    def block_header(self, block_hash: str) -> dict:
        return self.call("getblockheader", block_hash)

    def block_hash(self, height: int) -> str:
        return self.call("getblockhash", int(height))
