"""bip322ms: BIP-322 message signing for P2WSH multisig quorums.

Modules
-------
core     BIP-322 framing (message hash, to_spend / to_sign, smp/ful/pof encodings)
engines  Script interpreters used for verification (btclib, optional libbitcoinkernel)
wallet   Multisig descriptor / Coldcard config handling and address derivation
psbt     BIP-322 PSBT creation, signing (software keys), combining, finalizing
verify   The verifier (valid / invalid / inconclusive)
coldcard Coldcard-specific message lint
cli      Command line interface
"""

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
