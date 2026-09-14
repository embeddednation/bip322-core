"""bip322: BIP-322 message signing for P2WSH multisig quorums and P2WPKH wallets.

Modules (no private key passes through any of them)
----------------------------------------------------
core      BIP-322 framing (message hash, to_spend / to_sign, smp/ful/pof encodings)
engines   Script interpreters used for verification (btclib, optional libbitcoinkernel)
wallet    Output-descriptor wallets and address derivation
psbt      BIP-322 PSBT creation, inspection, combining, finalizing
verify    The verifier (valid / invalid / inconclusive)
coldcard  Coldcard-specific message lint
cli       The ``bip322`` command

``bip322.dev`` (command ``bip322-dev``) holds the scaffolding that does handle
private keys: dummy cosigner generation, wallet assembly and software signing.
"""

from ._version import SPEC, __version__
from .core import (
    PREFIX_FULL,
    PREFIX_POF,
    PREFIX_SIMPLE,
    BIP322Error,
    SignatureFormatError,
    build_to_sign,
    build_to_spend,
    decode_signature,
    encode_full,
    encode_simple,
    message_hash,
)
from .verify import State, VerifyResult, verify_message

__all__ = [
    "SPEC",
    "__version__",
    "PREFIX_FULL",
    "PREFIX_POF",
    "PREFIX_SIMPLE",
    "BIP322Error",
    "SignatureFormatError",
    "State",
    "VerifyResult",
    "build_to_sign",
    "build_to_spend",
    "decode_signature",
    "encode_full",
    "encode_simple",
    "message_hash",
    "verify_message",
]
