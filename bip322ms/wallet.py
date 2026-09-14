"""Multisig wallet description: output descriptors and address derivation.

Only native P2WSH ``multi`` / ``sortedmulti`` descriptors are supported, with
every key given as ``[fingerprint/origin-path]xpub/<0;1>/*`` (the form
Sparrow, Coldcard and Bitcoin Core all export).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from io import BytesIO

from embit.bip32 import HDKey
from embit.descriptor import Descriptor
from embit.descriptor.arguments import Key
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
    witness_script: bytes
    threshold: int
    #: public keys in witness-script order
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


class MultisigWallet:
    """A native P2WSH k-of-n wallet described by an output descriptor."""

    def __init__(self, descriptor: Descriptor, network: str = "main", name: str | None = None):
        if network not in NETWORKS:
            raise WalletError(f"unknown network {network!r}; expected one of {sorted(NETWORKS)}")
        if descriptor.sh or not descriptor.wsh or descriptor.taproot or descriptor.miniscript is None:
            raise WalletError("only native P2WSH descriptors are supported: wsh(multi(...)) / wsh(sortedmulti(...))")
        if not descriptor.is_basic_multisig:
            raise WalletError("only multi()/sortedmulti() scripts are supported inside wsh()")
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
        self.descriptor = descriptor.to_public()
        self.network = network
        self.name = name
        self.threshold: int = descriptor.miniscript.args[0].num
        self.sorted: bool = bool(descriptor.is_sorted)
        self.cosigners: list[Cosigner] = cosigners
        self.num_branches: int = descriptor.num_branches

    # ---- constructors ----------------------------------------------------- #

    @classmethod
    def from_descriptor(cls, text: str, network: str = "main", name: str | None = None) -> "MultisigWallet":
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
        fn = "sortedmulti" if self.sorted else "multi"
        keys = ",".join(c.key_expression(self.network, branches) for c in self.cosigners)
        text = f"wsh({fn}({self.threshold},{keys}))"
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
        witness_script = derived.witness_script().data
        script_pubkey = derived.script_pubkey().data
        address = derived.address(NETWORKS[self.network])
        derivations: dict[bytes, tuple[bytes, tuple[int, ...]]] = {}
        for key in derived.keys:
            derivations[key.sec()] = (bytes(key.origin.fingerprint), tuple(key.origin.derivation))
        threshold, pubkeys = parse_multisig(Script(witness_script))
        return DerivedAddress(
            branch=branch,
            index=index,
            address=address,
            script_pubkey=script_pubkey,
            witness_script=witness_script,
            threshold=threshold,
            pubkeys=tuple(pk.sec() for pk in pubkeys),
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
        """``PSBT_GLOBAL_XPUB`` entries for the cosigners."""
        return {
            c.xpub: DerivationPath(c.fingerprint, list(c.origin_path)) for c in self.cosigners
        }

    def describe(self) -> dict:
        return {
            "name": self.name,
            "network": self.network,
            "policy": f"{self.threshold} of {len(self.cosigners)}",
            "script": "wsh(sortedmulti)" if self.sorted else "wsh(multi)",
            "descriptor": self.to_descriptor(),
            "cosigners": [
                {"fingerprint": c.fingerprint_hex, "origin": path_to_str(c.origin_path), "xpub": c.xpub.to_base58(NETWORKS[self.network]["xpub"])}
                for c in self.cosigners
            ],
        }


def wallet_from_file(path: str, network: str | None = None) -> MultisigWallet:
    """Load a wallet from a file holding a descriptor (comment lines starting with # are ignored)."""
    with open(path, "r", encoding="utf-8") as fh:
        lines = [ln.strip() for ln in fh.read().splitlines()]
    lines = [ln for ln in lines if ln and not ln.startswith("#")]
    if len(lines) != 1:
        raise WalletError(f"{path}: expected exactly one descriptor line, found {len(lines)}")
    return MultisigWallet.from_descriptor(lines[0], network=network or "main")


# --------------------------------------------------------------------------- #
# building a wallet description from cosigner keys
# --------------------------------------------------------------------------- #

def cosigner_from_text(text: str) -> Cosigner:
    """Parse one cosigner given as

    * a ``bip322ms keygen`` JSON file path (uses its ``xpub_expression``),
    * a file holding a key expression, or
    * a key expression ``[fingerprint/path]xpub.../<0;1>/*`` (xprv accepted, public part used).
    """
    text = text.strip()
    if os.path.isfile(text):
        with open(text, "r", encoding="utf-8") as fh:
            content = fh.read().strip()
        if content.startswith("{"):
            data = json.loads(content)
            expr = data.get("xpub_expression") or data.get("xprv_expression")
            if not expr:
                raise WalletError(f"{text}: JSON has no xpub_expression")
            return cosigner_from_text(expr)
        return cosigner_from_text(content)
    if text.startswith("["):
        try:
            key = Key.read_from(BytesIO(text.encode()))
        except Exception as exc:  # noqa: BLE001
            raise WalletError(f"cannot parse key expression {text[:24]}...: {exc}") from exc
        if not key.is_extended or key.origin is None:
            raise WalletError("key expression must be an extended key with [fingerprint/path] origin")
        hd = key.key.to_public() if key.key.is_private else key.key
        return Cosigner(bytes(key.origin.fingerprint), tuple(key.origin.derivation), hd)
    raise WalletError(
        f"cannot interpret {text[:24]!r} as a cosigner: give a keygen JSON file "
        "or a [fingerprint/path]xpub expression"
    )


def wallet_from_cosigners(threshold: int, cosigners: list[Cosigner], network: str = "main", name: str | None = None, sorted_keys: bool = True) -> MultisigWallet:
    if not 1 <= threshold <= len(cosigners):
        raise WalletError(f"threshold {threshold} is not between 1 and {len(cosigners)}")
    fn = "sortedmulti" if sorted_keys else "multi"
    keys = ",".join(c.key_expression(network) for c in cosigners)
    return MultisigWallet.from_descriptor(f"wsh({fn}({threshold},{keys}))", network=network, name=name)
