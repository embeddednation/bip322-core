"""Snapshot: the wallet's coins at the stamp block, and one BIP-322 PSBT per funded address.

Sources for the coins:

* ``listunspent`` on a Core wallet that holds the descriptor (``-rpcwallet=``);
  fast, and its ``desc`` field tells us branch and index of every address.
* ``scantxoutset`` with the wallet's descriptors; no Core wallet needed, scans
  the whole UTXO set (a minute or two on mainnet).

Only outputs confirmed at or before the stamp block are included, so the
snapshot means "the wallet's coins as of block N".
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from bip322.coldcard import lint_message_for_coldcard
from bip322.psbt import create_psbt
from bip322.wallet import DerivedAddress, Wallet, WalletError

from . import TOOL
from .rpc import BitcoinCli, RpcError, to_sat
from .stamp import DEFAULT_DEPTH, Stamp, compose_message, fetch_stamp

_ORIGIN_RE = re.compile(r"\[[0-9a-fA-F]{8}((?:/\d+[h'H]?)+)\]")


@dataclass
class Utxo:
    txid: str
    vout: int
    amount_sat: int
    height: int  # block that created it

    def to_dict(self) -> dict:
        return {"txid": self.txid, "vout": self.vout, "amount_sat": self.amount_sat, "height": self.height}

    @classmethod
    def from_dict(cls, d: dict) -> Utxo:
        return cls(str(d["txid"]), int(d["vout"]), int(d["amount_sat"]), int(d["height"]))


@dataclass
class AddressCoins:
    derived: DerivedAddress
    utxos: list[Utxo] = field(default_factory=list)

    @property
    def total_sat(self) -> int:
        return sum(u.amount_sat for u in self.utxos)


def _index_from_desc(wallet: Wallet, desc: str | None, address: str) -> DerivedAddress | None:
    """Branch/index from the concrete descriptor Core reports for a UTXO, confirmed by re-deriving."""
    if not desc:
        return None
    match = _ORIGIN_RE.search(desc)
    if not match:
        return None
    parts = match.group(1).strip("/").split("/")
    if len(parts) < 2 or not parts[-1].isdigit() or not parts[-2].isdigit():
        return None
    branch, index = int(parts[-2]), int(parts[-1])
    if branch >= max(wallet.num_branches, 1):
        return None
    candidate = wallet.derive(index, branch)
    return candidate if candidate.address == address else None


def _locate(wallet: Wallet, address: str, desc: str | None, max_index: int) -> DerivedAddress | None:
    """The wallet address behind a node entry, or None when it is not ours (or not an address at all)."""
    try:
        return _index_from_desc(wallet, desc, address) or wallet.find_address(address, max_index=max_index)
    except WalletError:
        return None


def coins_from_listunspent(cli: BitcoinCli, wallet: Wallet, stamp: Stamp, tip_height: int, *, max_index: int = 1000) -> list[AddressCoins]:
    """Wallet coins confirmed at the stamp block, via the Core wallet selected with ``-rpcwallet``."""
    minconf = tip_height - stamp.height + 1
    entries = cli.call("listunspent", minconf, 9999999)
    by_address: dict[str, AddressCoins] = {}
    for e in entries:
        address = e.get("address")
        if not address:
            continue
        derived = _locate(wallet, address, e.get("desc"), max_index)
        if derived is None:
            continue  # coins of another wallet in the same Core wallet
        height = tip_height - int(e["confirmations"]) + 1
        if height > stamp.height:
            continue
        by_address.setdefault(address, AddressCoins(derived)).utxos.append(Utxo(e["txid"], int(e["vout"]), to_sat(e["amount"]), height))
    return _sorted(by_address)


def coins_from_scantxoutset(cli: BitcoinCli, wallet: Wallet, stamp: Stamp, *, scan_range: int = 1000) -> list[AddressCoins]:
    """Wallet coins confirmed at the stamp block, via a UTXO-set scan of the wallet descriptors (no Core wallet)."""
    descriptors = [{"desc": d, "range": [0, scan_range]} for d in wallet.core_descriptors()]
    result = cli.call("scantxoutset", "start", descriptors)
    if not result or not result.get("success"):
        raise RpcError("scantxoutset did not succeed (another scan running?)")
    by_address: dict[str, AddressCoins] = {}
    for u in result.get("unspents", []):
        if int(u["height"]) > stamp.height:
            continue
        address = _address_of_scriptpubkey(wallet, u["scriptPubKey"])
        derived = _locate(wallet, address, u.get("desc"), scan_range) if address else None
        if derived is None:
            continue
        by_address.setdefault(derived.address, AddressCoins(derived)).utxos.append(Utxo(u["txid"], int(u["vout"]), to_sat(u["amount"]), int(u["height"])))
    return _sorted(by_address)


def _address_of_scriptpubkey(wallet: Wallet, spk_hex: str) -> str | None:
    from embit.networks import NETWORKS
    from embit.script import Script

    try:
        return Script(bytes.fromhex(spk_hex)).address(NETWORKS[wallet.network])
    except Exception:  # noqa: BLE001
        return None


def _sorted(by_address: dict[str, AddressCoins]) -> list[AddressCoins]:
    coins = sorted(by_address.values(), key=lambda c: (c.derived.branch, c.derived.index))
    for c in coins:
        c.utxos.sort(key=lambda u: (u.height, u.txid, u.vout))
    return coins


# --------------------------------------------------------------------------- #
# the bundle on disk
# --------------------------------------------------------------------------- #

CHAIN_BY_NETWORK = {"main": "main", "test": "test", "regtest": "regtest", "signet": "signet"}


def _multipath(desc: str) -> str:
    """``.../0/*`` or ``.../1/*`` descriptors as one ``<0;1>`` descriptor (checksum dropped)."""
    body = desc.split("#")[0]
    return body.replace("/0/*", "/<0;1>/*").replace("/1/*", "/<0;1>/*")


def wallet_from_node(cli: BitcoinCli, chain: str | None = None) -> Wallet:
    """The wallet behind the node's loaded wallet, from ``listdescriptors``.

    Works for descriptor wallets holding one supported descriptor family
    (``wsh(multi/sortedmulti(...))`` or ``wpkh(...)``, receive and change);
    anything else needs ``--descriptor``.
    """
    chain = chain or cli.chain()
    try:
        listing = cli.call("listdescriptors")
    except RpcError as exc:
        raise RpcError(f"cannot read the node wallet's descriptors ({exc}); pass --descriptor") from exc
    families: dict[str, Wallet] = {}
    unsupported = []
    for entry in listing.get("descriptors", []):
        text = _multipath(entry["desc"])
        try:
            wallet = Wallet.from_descriptor(text, network=CHAIN_BY_NETWORK.get(chain, chain))
        except WalletError:
            unsupported.append(entry["desc"].split("#")[0][:40] + "...")
            continue
        families.setdefault(wallet.to_descriptor(), wallet)
    if len(families) == 1:
        return next(iter(families.values()))
    if not families:
        raise RpcError("the node wallet has no wsh(multi/sortedmulti) or wpkh descriptor" + (f" (found: {', '.join(unsupported)})" if unsupported else "") + "; pass --descriptor")
    raise RpcError("the node wallet holds several descriptor families; pass --descriptor to choose: " + " | ".join(families))


def check_wallet_against_node(cli: BitcoinCli, wallet: Wallet) -> None:
    """Refuse a --descriptor that the node wallet does not contain."""
    try:
        listing = cli.call("listdescriptors")
    except RpcError:
        return  # legacy wallet or no descriptor support: nothing to compare with
    node_descs = {_multipath(e["desc"]) for e in listing.get("descriptors", [])}
    if wallet.to_descriptor(checksum=False) not in node_descs:
        raise RpcError("the given descriptor is not one of the node wallet's descriptors (listdescriptors); wrong wallet or wrong file?")


@dataclass
class Snapshot:
    created_utc: str
    chain: str
    tip_height: int
    stamp: Stamp
    message: str
    wallet_descriptor: str
    policy: str
    addresses: list[dict]
    source: str

    @property
    def total_sat(self) -> int:
        return sum(a["total_sat"] for a in self.addresses)

    def to_dict(self) -> dict:
        return {
            "tool": TOOL,
            "created_utc": self.created_utc,
            "chain": self.chain,
            "tip_height_at_snapshot": self.tip_height,
            "stamp": self.stamp.to_dict(),
            "message": self.message,
            "wallet": {"descriptor": self.wallet_descriptor, "policy": self.policy},
            "source": self.source,
            "addresses": self.addresses,
            "total_sat": self.total_sat,
        }


def take_snapshot(
    cli: BitcoinCli,
    wallet: Wallet,
    template: str,
    *,
    depth: int = DEFAULT_DEPTH,
    source: str = "auto",
    coldcard_strict: bool = True,
    max_index: int = 1000,
    utxo_mode: str = "witness",
    progress=None,
) -> tuple[Snapshot, dict[str, object]]:
    """Build the snapshot and the unsigned PSBTs; returns (snapshot, {address: BIP322PSBT}).

    ``progress`` is an optional callable given a line of text before slow steps.
    """
    chain = cli.chain()
    if wallet.network == "test" and chain in ("regtest", "signet"):
        # tpub keys are shared by every test chain; the node says which one this is
        wallet = Wallet.from_descriptor(wallet.to_descriptor(), network=chain, name=wallet.name)
    if CHAIN_BY_NETWORK.get(wallet.network) != chain:
        raise RpcError(f"node is on chain {chain!r} but the wallet is for network {wallet.network!r}; pass --network")
    stamp = fetch_stamp(cli, depth)
    tip_height, _ = cli.tip()
    message = compose_message(template, stamp)
    lint = lint_message_for_coldcard(message.encode("utf-8"))
    if lint and coldcard_strict:
        raise ValueError("message would be refused by a Coldcard: " + "; ".join(lint))
    if source == "auto":
        # a node with exactly one wallet loaded answers listunspent without -rpcwallet; only fall
        # back to the (minutes-long) UTXO-set scan when the node has no wallet to ask
        try:
            cli.call("getwalletinfo")
            source = "listunspent"
        except RpcError as exc:
            if progress:
                progress(f"no wallet available ({exc}); scanning the UTXO set for the descriptor instead")
            source = "scantxoutset"
    if source == "listunspent":
        coins = coins_from_listunspent(cli, wallet, stamp, tip_height, max_index=max_index)
    elif source == "scantxoutset":
        if progress:
            progress("scantxoutset: scanning the whole UTXO set for the wallet descriptor, this takes minutes on mainnet")
        coins = coins_from_scantxoutset(cli, wallet, stamp, scan_range=max_index)
    else:
        raise ValueError("source must be auto, listunspent or scantxoutset")
    if not coins:
        raise RpcError(f"no coins of this wallet confirmed at block {stamp.height} (source {source})")
    message_bytes = message.encode("utf-8")
    psbts: dict[str, object] = {}
    addresses: list[dict] = []
    for c in coins:
        psbt = create_psbt(c.derived, message_bytes, xpubs=wallet.global_xpubs(), utxo_mode=utxo_mode)
        psbts[c.derived.address] = psbt
        addresses.append(
            {
                "address": c.derived.address,
                "branch": c.derived.branch,
                "index": c.derived.index,
                "utxos": [u.to_dict() for u in c.utxos],
                "total_sat": c.total_sat,
                "to_sign_txid": psbt.tx.txid().hex(),
            }
        )
    snapshot = Snapshot(
        created_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        chain=chain,
        tip_height=tip_height,
        stamp=stamp,
        message=message,
        wallet_descriptor=wallet.to_descriptor(),
        policy=f"{wallet.threshold} of {len(wallet.cosigners)}",
        addresses=addresses,
        source=source,
    )
    return snapshot, psbts


def write_bundle(directory: Path, snapshot: Snapshot, psbts: dict[str, object]) -> list[Path]:
    """``snapshot.json``, ``message.txt`` and ``<address>.psbt`` files; returns the written paths."""
    directory.mkdir(parents=True, exist_ok=True)
    written = []
    path = directory / "snapshot.json"
    path.write_text(json.dumps(snapshot.to_dict(), indent=2) + "\n")
    written.append(path)
    path = directory / "message.txt"
    path.write_bytes(snapshot.message.encode("utf-8"))  # exact bytes, no trailing newline
    written.append(path)
    for address, psbt in psbts.items():
        path = directory / f"{address}.psbt"
        path.write_text(psbt.to_string() + "\n")
        written.append(path)
    (directory / "signed").mkdir(exist_ok=True)
    return written


def load_snapshot(directory: Path) -> dict:
    return json.loads((directory / "snapshot.json").read_text())
