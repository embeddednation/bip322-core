"""Software signing of BIP-322 PSBTs (tests / non-hardware cosigners)."""

from __future__ import annotations

from io import BytesIO

from embit import ec
from embit.bip32 import HDKey
from embit.descriptor.arguments import Key
from embit.transaction import SIGHASH

from ..psbt import BIP322PSBT, PSBTBuildError


def parse_signer(text: str):
    """Accept a master xprv, a ``[fp/path]xprv`` key expression, or a WIF."""
    text = text.strip()
    if text.startswith("["):
        try:
            key = Key.read_from(BytesIO(text.encode()))
        except Exception as exc:  # noqa: BLE001
            raise PSBTBuildError(f"cannot parse signer key expression: {exc}") from exc
        if not key.is_private:
            raise PSBTBuildError("signer key expression has no private key")
        return key
    try:
        return HDKey.from_base58(text)
    except Exception:  # noqa: BLE001
        pass
    try:
        return ec.PrivateKey.from_wif(text)
    except Exception as exc:  # noqa: BLE001
        raise PSBTBuildError("signer must be an xprv, a [fp/path]xprv expression or a WIF") from exc


def sign_psbt(psbt: BIP322PSBT, signer, sighash: int = SIGHASH.ALL) -> int:
    """Add partial signatures with a software key; returns the number added."""
    if isinstance(signer, str):
        signer = parse_signer(signer)
    if isinstance(signer, HDKey) and not signer.is_private:
        raise PSBTBuildError("signer is a public key")
    return psbt.sign_with(signer, sighash)


