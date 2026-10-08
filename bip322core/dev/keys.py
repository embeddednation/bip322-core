"""Dummy key generation and wallet assembly from cosigner keys (demos and tests)."""

from __future__ import annotations

import hashlib
import json
import os
from io import BytesIO

from embit.bip32 import HDKey
from embit.descriptor.arguments import Key
from embit.networks import NETWORKS

from ..wallet import Cosigner, Wallet, WalletError, path_from_str, path_to_str

__all__ = [
    "KEYGEN_DOMAIN",
    "cosigner_from_text",
    "generate_cosigner",
    "wallet_from_cosigners",
]

KEYGEN_DOMAIN = "bip322ms-keygen:"  # a fixed label, not a name: changing it changes every demo key


def generate_cosigner(
    label: str = "cosigner", seed_text: str | None = None, origin: str = "48h/0h/0h/2h", network: str = "regtest"
) -> dict:
    """A test cosigner: deterministic from ``seed_text`` or random. Never for real funds.

    A seed text with mainnet is refused: the documentation publishes its demo
    seeds, and their mainnet addresses would be ones anyone can spend from.
    """
    if seed_text is not None and network == "main":
        raise WalletError("--seed with --network main is refused: keys derived from a seed text are public to anyone who knows the text")
    seed = hashlib.sha512((KEYGEN_DOMAIN + seed_text).encode("utf-8")).digest() if seed_text is not None else os.urandom(64)
    net = NETWORKS[network]
    master = HDKey.from_seed(seed, version=net["xprv"])
    origin = path_to_str(path_from_str(origin), prefix="")[1:]
    account = master.derive("m/" + origin)
    fp = master.my_fingerprint.hex()
    xprv = account.to_base58(net["xprv"])
    xpub = account.to_public().to_base58(net["xpub"])
    return {
        "label": label,
        "warning": "test keys only; "
        + ("anyone with the seed text can derive them" if seed_text is not None else "random, and stored unencrypted in this file"),
        "deterministic": seed_text is not None,
        "fingerprint": fp,
        "origin": "m/" + origin,
        "xpub_expression": f"[{fp}/{origin}]{xpub}/<0;1>/*",
        "xprv_expression": f"[{fp}/{origin}]{xprv}/<0;1>/*",
    }


def cosigner_from_text(text: str) -> Cosigner:
    """Parse one cosigner given as

    * a ``bip322 keygen`` JSON file path (uses its ``xpub_expression``),
    * a file holding a key expression, or
    * a key expression ``[fingerprint/path]xpub.../<0;1>/*`` (xprv accepted, public part used).
    """
    text = text.strip()
    if os.path.isfile(text):
        try:
            with open(text, encoding="utf-8") as fh:
                content = fh.read().strip()
            data = json.loads(content) if content.startswith("{") else None
        except ValueError as exc:  # binary file or broken JSON
            raise WalletError(f"{text}: not a key file (expected keygen JSON or a key expression)") from exc
        if data is not None:
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
    raise WalletError(f"cannot interpret {text[:24]!r} as a cosigner: give a keygen JSON file or a [fingerprint/path]xpub expression")


def wallet_from_cosigners(
    threshold: int | None,
    cosigners: list[Cosigner],
    network: str = "main",
    name: str | None = None,
    sorted_keys: bool = True,
    wpkh: bool = False,
) -> Wallet:
    keys = ",".join(c.key_expression(network) for c in cosigners)
    if wpkh:
        if len(cosigners) != 1:
            raise WalletError("wpkh takes exactly one key")
        return Wallet.from_descriptor(f"wpkh({keys})", network=network, name=name)
    if threshold is None:
        raise WalletError("a threshold is required for a multisig wallet")
    if not 1 <= threshold <= len(cosigners):
        raise WalletError(f"threshold {threshold} is not between 1 and {len(cosigners)}")
    fn = "sortedmulti" if sorted_keys else "multi"
    return Wallet.from_descriptor(f"wsh({fn}({threshold},{keys}))", network=network, name=name)
