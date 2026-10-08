"""Test-only helpers: signing shortcuts on top of bip322core.dev.testing."""

from bip322core.dev.signing import sign_psbt
from bip322core.dev.testing import SIGHASH, der_decode, der_encode, high_s, sign_with_sighash  # noqa: F401 - re-exported
from bip322core.psbt import BIP322PSBT, create_psbt, finalize_psbt


def signed_psbt(wallet, signers, message: bytes, index: int = 0, branch: int = 0, **kwargs) -> BIP322PSBT:
    derived = wallet.derive(index, branch)
    psbt = create_psbt(derived, message, xpubs=wallet.global_xpubs(), **kwargs)
    for signer in signers:
        assert sign_psbt(psbt, signer) == 1
    return psbt


def finalized_psbt(wallet, signers, message: bytes, index: int = 0, branch: int = 0, **kwargs) -> BIP322PSBT:
    return finalize_psbt(signed_psbt(wallet, signers, message, index, branch, **kwargs))
