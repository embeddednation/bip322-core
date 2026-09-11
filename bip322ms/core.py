"""BIP-322 framing primitives.

Everything here is independent of wallets, PSBTs and script interpreters:
message hashing, the virtual ``to_spend`` / ``to_sign`` transactions and the
three text encodings (``smp``, ``ful``, ``pof``).  It is written against the
BIP text (v2.0.0, 2026-06-04) rather than against a BIP-322 library, so that
the verifier only shares a *script interpreter* with third parties, never the
framing.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass
from io import BytesIO
from typing import Iterable, Sequence

from embit import compact
from embit.script import Script, Witness
from embit.transaction import Transaction, TransactionInput, TransactionOutput

TAG = b"BIP0322-signed-message"

PREFIX_SIMPLE = "smp"
PREFIX_FULL = "ful"
PREFIX_POF = "pof"
PREFIXES = (PREFIX_SIMPLE, PREFIX_FULL, PREFIX_POF)
VARIANT_LEGACY = "legacy"

OP_RETURN_SCRIPT = b"\x6a"
NULL_TXID = bytes(32)
NULL_VOUT = 0xFFFFFFFF

# BIP-322 global PSBT field carrying the UTF-8 message (BIP-174 registry).
PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE = b"\x09"

SIGHASH_DEFAULT = 0x00
SIGHASH_ALL = 0x01


class BIP322Error(Exception):
    """Base class for errors raised by bip322ms."""


class SignatureFormatError(BIP322Error):
    """The signature text could not be decoded into a BIP-322 payload."""


# --------------------------------------------------------------------------- #
# hashing and the two virtual transactions
# --------------------------------------------------------------------------- #


def tagged_hash(tag: bytes, data: bytes) -> bytes:
    """BIP-340 tagged hash: sha256(sha256(tag) || sha256(tag) || data)."""
    th = hashlib.sha256(tag).digest()
    return hashlib.sha256(th + th + data).digest()


def message_hash(message: bytes) -> bytes:
    """``sha256_tag("BIP0322-signed-message", message)``; message is raw bytes."""
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes (encode text as UTF-8 first)")
    return tagged_hash(TAG, bytes(message))


def build_to_spend(message: bytes, script_pubkey: bytes) -> Transaction:
    """The ``to_spend`` transaction for ``message`` and the challenge script."""
    script_sig = Script(b"\x00\x20" + message_hash(message))
    vin = [TransactionInput(NULL_TXID, NULL_VOUT, script_sig=script_sig, sequence=0)]
    vout = [TransactionOutput(0, Script(bytes(script_pubkey)))]
    return Transaction(version=0, vin=vin, vout=vout, locktime=0)


def build_to_sign(
    to_spend_txid: bytes,
    *,
    witness: Iterable[bytes] | None = None,
    script_sig: bytes = b"",
    version: int = 0,
    locktime: int = 0,
    sequence: int = 0,
    extra_inputs: Sequence[TransactionInput] | None = None,
) -> Transaction:
    """The ``to_sign`` transaction spending ``to_spend``'s single output.

    ``to_spend_txid`` is in display order (what ``Transaction.txid()`` returns).
    """
    items = list(witness) if witness else []
    vin = [
        TransactionInput(
            bytes(to_spend_txid),
            0,
            script_sig=Script(bytes(script_sig)),
            sequence=sequence,
            witness=Witness(items),
        )
    ]
    if extra_inputs:
        vin.extend(extra_inputs)
    vout = [TransactionOutput(0, Script(OP_RETURN_SCRIPT))]
    return Transaction(version=version, vin=vin, vout=vout, locktime=locktime)


# --------------------------------------------------------------------------- #
# serialization helpers
# --------------------------------------------------------------------------- #


def serialize_witness(items: Iterable[bytes]) -> bytes:
    """Consensus encoding of a witness stack (vector of vectors of bytes)."""
    return Witness(list(items)).serialize()


def parse_witness(raw: bytes) -> list[bytes]:
    """Strict inverse of :func:`serialize_witness` (no trailing bytes allowed)."""
    stream = BytesIO(raw)
    items: list[bytes] = []
    try:
        count = compact.read_from(stream)
        for _ in range(count):
            length = compact.read_from(stream)
            data = stream.read(length)
            if len(data) != length:
                raise SignatureFormatError("truncated witness stack")
            items.append(data)
    except SignatureFormatError:
        raise
    except Exception as exc:  # noqa: BLE001 - any decoding failure is a format error
        raise SignatureFormatError(f"malformed witness stack: {exc}") from exc
    if stream.read():
        raise SignatureFormatError("trailing bytes after witness stack")
    return items


def parse_transaction(raw: bytes) -> Transaction:
    """Strictly parse a consensus-serialized transaction (no trailing bytes)."""
    stream = BytesIO(raw)
    try:
        tx = Transaction.read_from(stream)
    except Exception as exc:  # noqa: BLE001
        raise SignatureFormatError(f"malformed transaction: {exc}") from exc
    if stream.read():
        raise SignatureFormatError("trailing bytes after transaction")
    return tx


def is_native_segwit(script_pubkey: bytes) -> bool:
    """True for a witness program (v0 P2WPKH/P2WSH or v1+ programs)."""
    spk = bytes(script_pubkey)
    if len(spk) < 4 or len(spk) > 42:
        return False
    version, push = spk[0], spk[1]
    if version != 0 and not (0x51 <= version <= 0x60):
        return False
    return push == len(spk) - 2 and 2 <= push <= 40


def is_op_return_output(out: TransactionOutput) -> bool:
    return out.value == 0 and out.script_pubkey.data == OP_RETURN_SCRIPT


# --------------------------------------------------------------------------- #
# text encodings
# --------------------------------------------------------------------------- #


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def encode_simple(witness: Iterable[bytes]) -> str:
    """``smp`` + base64(consensus-encoded witness stack)."""
    return PREFIX_SIMPLE + _b64(serialize_witness(witness))


def encode_full(to_sign: Transaction) -> str:
    """``ful`` + base64(network-serialized ``to_sign``)."""
    return PREFIX_FULL + _b64(to_sign.serialize())


def encode_pof(psbt_bytes: bytes) -> str:
    """``pof`` + base64(finalized PSBT of ``to_sign``)."""
    return PREFIX_POF + _b64(bytes(psbt_bytes))


@dataclass(frozen=True)
class DecodedSignature:
    variant: str  # "smp" | "ful" | "pof" | "legacy"
    payload: bytes
    prefixed: bool


def decode_signature(signature: str, *, allow_unprefixed: bool = True) -> DecodedSignature:
    """Split a BIP-322 signature string into variant and raw payload.

    Without a recognised prefix the BIP allows a verifier to assume the simple
    variant; a 65-byte payload is treated as a legacy (BIP-137) signature since
    no witness stack can serialize to exactly 65 bytes.
    """
    if not isinstance(signature, str):
        raise TypeError("signature must be a str")
    sig = signature.strip()
    if not sig:
        raise SignatureFormatError("signature too short (empty)")
    prefix = sig[:3]
    if prefix in PREFIXES:
        body, variant, prefixed = sig[3:], prefix, True
    else:
        if not allow_unprefixed:
            raise SignatureFormatError("missing smp/ful/pof signature prefix")
        body, variant, prefixed = sig, None, False
    try:
        payload = base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SignatureFormatError(f"invalid base64 encoding: {exc}") from exc
    if not payload:
        raise SignatureFormatError("signature too short (empty payload)")
    if variant is None:
        variant = VARIANT_LEGACY if len(payload) == 65 else PREFIX_SIMPLE
    return DecodedSignature(variant=variant, payload=payload, prefixed=prefixed)
