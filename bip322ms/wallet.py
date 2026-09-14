"""Multisig wallet description: descriptors, Coldcard export files, derivation.

Only native P2WSH ``multi`` / ``sortedmulti`` descriptors are supported, with
every key given as ``[fingerprint/origin-path]xpub/<0;1>/*`` (the form
Sparrow, Coldcard and Bitcoin Core all export).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from io import BytesIO

from embit import ec
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

    @classmethod
    def from_coldcard_config(cls, text: str, network: str | None = None) -> "MultisigWallet":
        config = parse_coldcard_config(text)
        if config.format.upper() != "P2WSH":
            raise WalletError(f"Coldcard config format {config.format!r} is not P2WSH")
        keys = []
        detected_network = network
        for xfp, derivation, xpub_text in config.keys:
            hd = _parse_xpub_any_version(xpub_text)
            if detected_network is None:
                detected_network = _network_from_version(hd.version)
            xpub = hd.to_base58(NETWORKS[detected_network]["xpub"])
            keys.append(f"[{xfp.lower()}/{path_to_str(path_from_str(derivation), prefix='')[1:]}]{xpub}/<0;1>/*")
        detected_network = detected_network or "main"
        descriptor = f"wsh(sortedmulti({config.threshold},{','.join(keys)}))"
        wallet = cls.from_descriptor(descriptor, network=detected_network, name=config.name)
        if len(wallet.cosigners) != config.total:
            raise WalletError(f"Coldcard config says {config.total} keys but {len(wallet.cosigners)} were listed")
        return wallet

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


# --------------------------------------------------------------------------- #
# Coldcard multisig export file
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ColdcardConfig:
    name: str | None
    threshold: int
    total: int
    format: str
    #: (xfp hex, derivation path string, xpub text)
    keys: tuple[tuple[str, str, str], ...]


_XFP_LINE = re.compile(r"^([0-9A-Fa-f]{8})\s*:\s*([A-Za-z0-9]+)\s*$")
_POLICY = re.compile(r"^(\d+)\s*of\s*(\d+)$", re.IGNORECASE)


def parse_coldcard_config(text: str) -> ColdcardConfig:
    """Parse the ``Name/Policy/Derivation/Format`` + ``xfp: xpub`` export format."""
    name = None
    threshold = total = None
    fmt = "P2WSH"
    derivation = "m/48h/0h/0h/2h"
    keys: list[tuple[str, str, str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _XFP_LINE.match(line)
        if match:
            keys.append((match.group(1), derivation, match.group(2)))
            continue
        if ":" not in line:
            raise WalletError(f"unparseable line in Coldcard config: {line!r}")
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "name":
            name = value
        elif key == "policy":
            pm = _POLICY.match(value)
            if not pm:
                raise WalletError(f"bad Policy line: {value!r}")
            threshold, total = int(pm.group(1)), int(pm.group(2))
        elif key == "derivation":
            derivation = value
        elif key == "format":
            fmt = value
        else:
            raise WalletError(f"unknown Coldcard config key: {key!r}")
    if threshold is None or total is None:
        raise WalletError("Coldcard config is missing a Policy line")
    if not keys:
        raise WalletError("Coldcard config lists no xpubs")
    if len(keys) != total:
        raise WalletError(f"Policy says {total} keys but {len(keys)} xpubs listed")
    return ColdcardConfig(name=name, threshold=threshold, total=total, format=fmt, keys=tuple(keys))


def _parse_xpub_any_version(text: str) -> HDKey:
    try:
        return HDKey.from_base58(text)
    except Exception as exc:  # noqa: BLE001
        raise WalletError(f"cannot parse extended key {text[:12]}...: {exc}") from exc


def _network_from_version(version: bytes) -> str:
    for net_name, net in NETWORKS.items():
        for field in ("xpub", "ypub", "zpub", "Ypub", "Zpub"):
            if net.get(field) == version:
                return "main" if net_name == "main" else "test" if net_name == "test" else net_name
    raise WalletError(f"unknown extended key version {version.hex()}")


def wallet_from_file(path: str, network: str | None = None) -> MultisigWallet:
    """Load either a descriptor (single line) or a Coldcard export file."""
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    stripped = text.strip()
    if stripped.startswith("wsh(") or stripped.startswith("sh("):
        return MultisigWallet.from_descriptor(stripped, network=network or "main")
    return MultisigWallet.from_coldcard_config(text, network=network)


# --------------------------------------------------------------------------- #
# building a wallet description from cosigner keys
# --------------------------------------------------------------------------- #

DEFAULT_ORIGIN = "m/48h/0h/0h/2h"


def cosigner_from_text(text: str, *, default_origin: str = DEFAULT_ORIGIN) -> Cosigner:
    """Parse one cosigner given as

    * a ``bip322ms keygen`` JSON file path (uses its ``xpub_expression``),
    * a key expression ``[fingerprint/path]xpub.../<0;1>/*`` (xprv accepted, public part used),
    * a Coldcard export line ``XFP: xpub...`` (origin = ``default_origin``).
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
            return cosigner_from_text(expr, default_origin=default_origin)
        return cosigner_from_text(content, default_origin=default_origin)
    match = _XFP_LINE.match(text)
    if match:
        xfp, xpub_text = match.groups()
        hd = _parse_xpub_any_version(xpub_text)
        hd = hd.to_public() if hd.is_private else hd
        return Cosigner(bytes.fromhex(xfp), tuple(path_from_str(default_origin)), hd)
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
        f"cannot interpret {text[:24]!r} as a cosigner: give a keygen JSON file, "
        "a [fingerprint/path]xpub expression or a Coldcard 'XFP: xpub' line"
    )


def coldcard_config_text(name: str, threshold: int, cosigners: list[Cosigner], network: str = "main") -> str:
    """Render cosigners as a Coldcard multisig export file (Format: P2WSH)."""
    if not 1 <= threshold <= len(cosigners):
        raise WalletError(f"threshold {threshold} is not between 1 and {len(cosigners)}")
    lines = [f"Name: {name}", f"Policy: {threshold} of {len(cosigners)}", "Format: P2WSH"]
    origins = {c.origin_path for c in cosigners}
    if len(origins) == 1:
        lines.append("Derivation: " + path_to_str(cosigners[0].origin_path, hardened_marker="'"))
    lines.append("")
    for c in cosigners:
        if len(origins) > 1:
            lines.append("Derivation: " + path_to_str(c.origin_path, hardened_marker="'"))
        lines.append(f"{c.fingerprint_hex.upper()}: {c.xpub.to_base58(NETWORKS[network]['xpub'])}")
    return "\n".join(lines) + "\n"


def wallet_from_cosigners(threshold: int, cosigners: list[Cosigner], network: str = "main", name: str | None = None, sorted_keys: bool = True) -> MultisigWallet:
    fn = "sortedmulti" if sorted_keys else "multi"
    keys = ",".join(c.key_expression(network) for c in cosigners)
    return MultisigWallet.from_descriptor(f"wsh({fn}({threshold},{keys}))", network=network, name=name)
