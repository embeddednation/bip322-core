"""Wallet description: output descriptors and address derivation.

Supported descriptors are native segwit only: ``wsh(multi(...))`` /
``wsh(sortedmulti(...))`` for a multisig quorum and ``wpkh(...)`` for a single
key, with every key given as ``[fingerprint/origin-path]xpub/<0;1>/*`` (the
form Sparrow, Coldcard and Bitcoin Core all export).
"""

from __future__ import annotations

from dataclasses import dataclass

from embit.bip32 import HDKey
from embit.descriptor import Descriptor
from embit.descriptor.checksum import add_checksum
from embit.finalizer import parse_multisig
from embit.networks import NETWORKS
from embit.psbt import DerivationPath
from embit.script import Script, address_to_scriptpubkey

from .core import BIP322Error

HARDENED = 0x80000000


class WalletError(BIP322Error):
    """Unsupported or malformed wallet description."""


# --------------------------------------------------------------------------- #
# derivation path helpers
# --------------------------------------------------------------------------- #


def path_to_str(path, prefix: str = "m", hardened_marker: str = "h") -> str:
    parts = [prefix]
    for index in path:
        if index >= HARDENED:
            parts.append(f"{index - HARDENED}{hardened_marker}")
        else:
            parts.append(str(index))
    return "/".join(parts)


def path_from_str(text: str) -> list[int]:
    text = text.strip()
    if text in ("", "m", "m/"):
        return []
    if text.startswith("m/"):
        text = text[2:]
    elif text.startswith("m"):
        raise WalletError(f"invalid derivation path: {text!r}")
    path: list[int] = []
    for part in text.split("/"):
        if not part:
            raise WalletError(f"invalid derivation path: {text!r}")
        hardened = part[-1] in "h'H"
        num = part[:-1] if hardened else part
        if not num.isdigit():
            raise WalletError(f"invalid derivation path element: {part!r}")
        value = int(num)
        if value >= HARDENED:
            raise WalletError(f"derivation index too large: {part!r}")
        path.append(value + HARDENED if hardened else value)
    return path


# --------------------------------------------------------------------------- #
# data classes
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Cosigner:
    fingerprint: bytes
    origin_path: tuple[int, ...]
    xpub: HDKey  # public, at the origin path

    @property
    def fingerprint_hex(self) -> str:
        return self.fingerprint.hex()

    def origin(self) -> str:
        return f"[{self.fingerprint.hex()}/{path_to_str(self.origin_path, prefix='')[1:]}]"

    def key_expression(self, network: str = "main", branches: str = "<0;1>") -> str:
        xpub = self.xpub.to_base58(NETWORKS[network]["xpub"])
        return f"{self.origin()}{xpub}/{branches}/*"


@dataclass(frozen=True)
class DerivedAddress:
    branch: int
    index: int
    address: str
    script_pubkey: bytes
    #: the CHECKMULTISIG script for P2WSH; None for P2WPKH
    witness_script: bytes | None
    threshold: int
    #: public keys in witness-script order (a single key for P2WPKH)
    pubkeys: tuple[bytes, ...]
    #: pubkey (33-byte SEC) -> (master fingerprint, full derivation path)
    derivations: dict[bytes, tuple[bytes, tuple[int, ...]]]

    def derivation_paths(self) -> dict[str, str]:
        return {
            sec.hex(): f"{fp.hex()}:{path_to_str(path)}" for sec, (fp, path) in self.derivations.items()
        }


# --------------------------------------------------------------------------- #
# wallet
# --------------------------------------------------------------------------- #


class Wallet:
    """A native segwit wallet described by an output descriptor.

    ``kind`` is ``"p2wsh-multisig"`` for ``wsh(multi/sortedmulti(...))`` or
    ``"p2wpkh"`` for ``wpkh(...)``.
    """

    def __init__(self, descriptor: Descriptor, network: str | None = None, name: str | None = None):
        """``network`` selects the address encoding; ``None`` infers main/test from the xpub versions."""
        if network is not None and network not in NETWORKS:
            raise WalletError(f"unknown network {network!r}; expected one of {sorted(NETWORKS)}")
        if descriptor.sh or descriptor.taproot:
            raise WalletError("only native segwit descriptors are supported: wsh(multi/sortedmulti(...)) or wpkh(...)")
        if descriptor.miniscript is not None:
            if not descriptor.wsh:
                raise WalletError("bare scripts are not supported; use wsh(...)")
            if not descriptor.is_basic_multisig:
                raise WalletError("only multi()/sortedmulti() scripts are supported inside wsh()")
            self.kind = "p2wsh-multisig"
        elif descriptor.key is not None and descriptor.wpkh:
            self.kind = "p2wpkh"
        else:
            raise WalletError("unsupported descriptor; use wsh(multi/sortedmulti(...)) or wpkh(...)")
        cosigners: list[Cosigner] = []
        for key in descriptor.keys:
            if not key.is_extended or key.origin is None or key.allowed_derivation is None:
                raise WalletError(
                    "every key must be an extended key with origin info and a wildcard, "
                    "e.g. [0f056943/48h/0h/0h/2h]xpub.../<0;1>/*"
                )
            if key.allowed_derivation.has_hardend:
                raise WalletError("hardened derivation after the xpub is not supported")
            cosigners.append(
                Cosigner(
                    fingerprint=bytes(key.origin.fingerprint),
                    origin_path=tuple(key.origin.derivation),
                    xpub=key.key.to_public() if key.key.is_private else key.key,
                )
            )
        seen: set[str] = set()
        for c in cosigners:
            xpub = c.xpub.to_base58()
            if xpub in seen:
                raise WalletError("the same xpub appears more than once in the descriptor")
            seen.add(xpub)
        if network is None:
            network = _network_from_keys(cosigners)
        self.descriptor = descriptor.to_public()
        self.network = network
        self.name = name
        if self.kind == "p2wsh-multisig":
            self.threshold: int = descriptor.miniscript.args[0].num
            self.sorted: bool = bool(descriptor.is_sorted)
        else:
            self.threshold = 1
            self.sorted = False
        self.cosigners: list[Cosigner] = cosigners
        self.num_branches: int = descriptor.num_branches

    @property
    def is_multisig(self) -> bool:
        return self.kind == "p2wsh-multisig"

    # ---- constructors ----------------------------------------------------- #

    @classmethod
    def from_descriptor(cls, text: str, network: str | None = None, name: str | None = None) -> Wallet:
        text = text.strip()
        if "#" in text:
            body, _, checksum = text.partition("#")
            expected = add_checksum(body).split("#")[1]
            if checksum != expected:
                raise WalletError(f"descriptor checksum mismatch (expected #{expected})")
            text = body
        try:
            descriptor = Descriptor.from_string(text)
        except Exception as exc:  # noqa: BLE001
            raise WalletError(f"cannot parse descriptor: {exc}") from exc
        return cls(descriptor, network=network, name=name)

    # ---- descriptor output ------------------------------------------------ #

    def to_descriptor(self, *, checksum: bool = True, branches: str = "<0;1>") -> str:
        keys = ",".join(c.key_expression(self.network, branches) for c in self.cosigners)
        if self.is_multisig:
            fn = "sortedmulti" if self.sorted else "multi"
            text = f"wsh({fn}({self.threshold},{keys}))"
        else:
            text = f"wpkh({keys})"
        return add_checksum(text) if checksum else text

    def core_descriptors(self) -> list[str]:
        """Receive/change descriptors in the form Bitcoin Core's RPCs accept."""
        return [self.to_descriptor(branches=str(b)) for b in range(max(self.num_branches, 1))]

    # ---- derivation -------------------------------------------------------- #

    def derive(self, index: int, branch: int = 0) -> DerivedAddress:
        if index < 0 or index >= HARDENED:
            raise WalletError("index out of range")
        if branch < 0 or branch >= max(self.num_branches, 1):
            raise WalletError(f"descriptor has {self.num_branches} branch(es); branch {branch} does not exist")
        branch_index = branch if self.num_branches > 1 else None
        derived = self.descriptor.derive(index, branch_index=branch_index)
        script_pubkey = derived.script_pubkey().data
        address = derived.address(NETWORKS[self.network])
        derivations: dict[bytes, tuple[bytes, tuple[int, ...]]] = {}
        for key in derived.keys:
            derivations[key.sec()] = (bytes(key.origin.fingerprint), tuple(key.origin.derivation))
        if self.is_multisig:
            witness_script = derived.witness_script().data
            threshold, pubkeys = parse_multisig(Script(witness_script))
            ordered = tuple(pk.sec() for pk in pubkeys)
        else:
            witness_script = None
            threshold = 1
            ordered = (derived.key.sec(),)
        return DerivedAddress(
            branch=branch,
            index=index,
            address=address,
            script_pubkey=script_pubkey,
            witness_script=witness_script,
            threshold=threshold,
            pubkeys=ordered,
            derivations=derivations,
        )

    def find_address(self, address: str, *, max_index: int = 500, branches=None) -> DerivedAddress | None:
        """Locate ``address`` (any network encoding of the same script) in the wallet."""
        try:
            target = address_to_scriptpubkey(address).data
        except Exception as exc:  # noqa: BLE001
            raise WalletError(f"invalid address {address!r}: {exc}") from exc
        if branches is None:
            branches = range(max(self.num_branches, 1))
        for index in range(max_index + 1):
            for branch in branches:
                candidate = self.derive(index, branch)
                if candidate.script_pubkey == target:
                    return candidate
        return None

    def global_xpubs(self) -> dict[HDKey, DerivationPath]:
        """``PSBT_GLOBAL_XPUB`` entries for the cosigners, in this wallet's network encoding."""
        return {
            _with_version(c.xpub, NETWORKS[self.network]["xpub"]): DerivationPath(c.fingerprint, list(c.origin_path))
            for c in self.cosigners
        }

    def describe(self) -> dict:
        script = ("wsh(sortedmulti)" if self.sorted else "wsh(multi)") if self.is_multisig else "wpkh"
        return {
            "name": self.name,
            "network": self.network,
            "kind": self.kind,
            "policy": f"{self.threshold} of {len(self.cosigners)}",
            "script": script,
            "descriptor": self.to_descriptor(),
            "cosigners": [
                {"fingerprint": c.fingerprint_hex, "origin": path_to_str(c.origin_path), "xpub": c.xpub.to_base58(NETWORKS[self.network]["xpub"])}
                for c in self.cosigners
            ],
        }


#: backwards-compatible name
MultisigWallet = Wallet


def _with_version(xpub: HDKey, version: bytes) -> HDKey:
    """The same extended public key re-encoded with ``version`` bytes."""
    if xpub.version == version:
        return xpub
    return HDKey(xpub.key, xpub.chain_code, version=version, depth=xpub.depth, fingerprint=xpub.fingerprint, child_number=xpub.child_number)


def _network_from_keys(cosigners: list[Cosigner]) -> str:
    """``main`` for xpub-encoded keys, ``test`` for tpub; mixed encodings are refused."""
    found: set[str] = set()
    for c in cosigners:
        for net_name in ("main", "test"):
            net = NETWORKS[net_name]
            if c.xpub.version in (net["xpub"], net.get("ypub"), net.get("zpub"), net.get("Ypub"), net.get("Zpub")):
                found.add(net_name)
                break
        else:
            found.add("?")
    if found == {"test"}:
        return "test"
    if len(found) > 1:
        raise WalletError("keys use mixed mainnet/testnet encodings; pass --network explicitly")
    return "main"


def wallet_from_file(path: str, network: str | None = None) -> Wallet:
    """Load a wallet from a file holding a descriptor (comment lines starting with # are ignored).

    Without ``network`` the address encoding follows the key versions (xpub = main, tpub = test).
    """
    with open(path, encoding="utf-8") as fh:
        lines = [ln.strip() for ln in fh.read().splitlines()]
    lines = [ln for ln in lines if ln and not ln.startswith("#")]
    if len(lines) != 1:
        raise WalletError(f"{path}: expected exactly one descriptor line, found {len(lines)}")
    return Wallet.from_descriptor(lines[0], network=network)
