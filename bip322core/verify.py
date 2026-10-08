"""BIP-322 verification: *valid*, *invalid* or *inconclusive*.

The framing (``to_spend`` / ``to_sign``, shape checks, variant rules and the
SIGHASH_ALL rule) is implemented here; script evaluation is delegated to the
engines in :mod:`bip322core.engines`.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum

from embit.script import Script
from embit.transaction import Transaction

from .core import (
    PREFIX_FULL,
    PREFIX_POF,
    PREFIX_SIMPLE,
    SIGHASH_ALL,
    SIGHASH_DEFAULT,
    VARIANT_LEGACY,
    BIP322Error,
    DecodedSignature,
    SignatureFormatError,
    build_to_sign,
    build_to_spend,
    decode_address,
    decode_signature,
    is_native_segwit,
    is_op_return_output,
    parse_transaction,
    parse_witness,
)
from .engines import (
    BTCLIB_REQUIRED,
    BTCLIB_UPGRADEABLE,
    EngineRun,
    btclib_ecdsa_default_inputs,
    btclib_run,
    check_engines,
    kernel_run,
)
from .psbt import extract_tx, is_finalized, parse_psbt, psbt_prevouts

__all__ = [
    "MAX_INPUTS",
    "MAX_SIGNATURE_BYTES",
    "State",
    "VerifyResult",
    "is_script_hex",
    "script_pubkey_from_address",
    "verify_message",
]

#: defaults for verify_message: a proof this large takes about a second to check; callers that expect more raise them
MAX_SIGNATURE_BYTES = 100_000
MAX_INPUTS = 100


class State(StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    INCONCLUSIVE = "inconclusive"


@dataclass
class VerifyResult:
    state: State
    reason: str
    address: str = ""
    variant: str | None = None
    script_pubkey: bytes | None = None  # the challenge actually verified (what the address encodes, or the bytes given)
    message: bytes = b""
    signature: str = ""
    to_spend_txid: str | None = None
    to_sign_txid: str | None = None
    locktime: int | None = None
    sequence: int | None = None
    version: int | None = None
    extra_inputs: int = 0
    sighash_types: list[int] = field(default_factory=list)
    engines: list[EngineRun] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.state is State.VALID

    def to_dict(self) -> dict:
        """A self-contained report: what was checked, by which tool, with which outcome."""
        from ._version import SPEC, __version__

        return {
            "tool": f"bip322-core {__version__}",
            "spec": SPEC,
            "state": self.state.value,
            "reason": self.reason,
            "address": self.address,
            "scriptPubKey": self.script_pubkey.hex() if self.script_pubkey else None,
            "message_utf8": self.message.decode("utf-8", errors="replace"),
            "message_hex": self.message.hex(),
            "signature": self.signature,
            "variant": self.variant,
            "to_spend_txid": self.to_spend_txid,
            "to_sign_txid": self.to_sign_txid,
            "version": self.version,
            "locktime": self.locktime,
            "sequence": self.sequence,
            "extra_inputs": self.extra_inputs,
            "sighash_types": self.sighash_types,
            "engines": [e.to_dict() for e in self.engines],
        }


_EXPLANATIONS = (
    ("failed OP_CHECKMULTISIG", "the signatures do not verify for this message and address"),
    ("failed OP_CHECKSIG", "the signature does not verify for this message and address"),
    ("witness script sha256", "the witness script does not belong to this address"),
    ("witness program", "the witness does not fit this address type"),
    ("high s", "a signature is not low-S (malleable encoding, forbidden by BIP-322)"),
    ("stack underflow", "the witness is missing elements"),
    ("clean stack", "the witness has extra elements"),
    ("der", "a signature is not strictly DER encoded"),
    ("dummy", "the CHECKMULTISIG dummy element is not empty"),
    ("false top stack", "the script evaluated to false"),
)


def _explain(error: str | None) -> str:
    text = (error or "").lower()
    for needle, explanation in _EXPLANATIONS:
        # whole words only: "der" is also inside "underflow"
        if re.search(rf"(?<![a-z]){re.escape(needle.lower())}(?![a-z])", text):
            return explanation
    return "script verification failed"


def is_script_hex(text: str) -> bool:
    """Does ``text`` look like a scriptPubKey given as hex rather than an address?"""
    t = text.strip().lower()
    return len(t) >= 8 and len(t) % 2 == 0 and all(c in "0123456789abcdef" for c in t)


def script_pubkey_from_address(address: str) -> bytes:
    """The challenge: the scriptPubKey an address encodes, or the scriptPubKey itself given as hex.

    BIP-322 signs and verifies for a scriptPubKey ("the key script to be
    proven"); an address is one way to hand it in, the bytes are the other.
    """
    if is_script_hex(address):
        return bytes.fromhex(address.strip())
    return decode_address(address)


def _legacy(address: str, spk: bytes, signature: str, message: bytes) -> VerifyResult:
    if Script(spk).script_type() != "p2pkh":
        return VerifyResult(State.INVALID, "legacy (BIP-137) signatures are only valid for P2PKH addresses", address, VARIANT_LEGACY)
    try:
        from btclib.ecc import bms

        ok = bms.verify(message, address, signature.strip())
    except Exception as exc:  # noqa: BLE001
        return VerifyResult(State.INVALID, f"legacy signature check failed: {exc}", address, VARIANT_LEGACY)
    if not ok:
        return VerifyResult(State.INVALID, "legacy signature does not recover to the address", address, VARIANT_LEGACY)
    return VerifyResult(State.VALID, "valid legacy (BIP-137) signature", address, VARIANT_LEGACY)


def verify_message(
    address: str,
    signature: str,
    message: bytes,
    *,
    engines: Sequence[str] = ("btclib",),
    allow_unprefixed: bool = True,
    allow_legacy: bool = True,
    max_signature_bytes: int = MAX_SIGNATURE_BYTES,
    max_inputs: int = MAX_INPUTS,
) -> VerifyResult:
    """Verify a BIP-322 signature for ``address`` over ``message`` (bytes).

    A signature string longer than ``max_signature_bytes`` or a proof with more
    than ``max_inputs`` inputs is *invalid* without being evaluated: the cost of
    checking grows faster than the size, and the string comes from a stranger.

    ``engines`` may contain ``"btclib"`` (always run) and ``"kernel"``; asking
    for an engine that is not installed raises :class:`EngineError` rather than
    producing a verdict.
    """
    if isinstance(message, str):
        raise TypeError("message must be bytes; encode text as UTF-8")
    check_engines(engines)
    message = bytes(message)
    signature = signature.strip()
    if len(signature) > max_signature_bytes:
        reason = f"signature is {len(signature)} characters, more than the limit of {max_signature_bytes} (max_signature_bytes)"
        return VerifyResult(State.INVALID, reason, address, message=message, signature=signature[:64] + "...")
    try:
        spk = script_pubkey_from_address(address)
        decoded = decode_signature(signature, allow_unprefixed=allow_unprefixed)
    except SignatureFormatError as exc:
        return VerifyResult(State.INVALID, str(exc), address, message=message, signature=signature)
    if decoded.variant == VARIANT_LEGACY and is_native_segwit(spk):
        # 65 unprefixed bytes can be a witness stack too (one 63-byte item): legacy is decided by the address type
        try:
            parse_witness(decoded.payload)
            decoded = DecodedSignature(PREFIX_SIMPLE, decoded.payload, False)
        except BIP322Error:
            pass
    result = _verify_challenge(address, spk, decoded, signature, message, engines, allow_legacy, max_inputs)
    result.script_pubkey = spk
    return result


class _Verdict(Exception):
    """A step's early verdict: the proof is invalid (or inconclusive), and why."""

    def __init__(self, reason: str, state: State = State.INVALID):
        super().__init__(reason)
        self.reason, self.state = reason, state


@dataclass
class _Proof:
    """``to_sign`` as the signature string gives it, with the (value, scriptPubKey) each of its inputs spends."""

    to_sign: Transaction
    prevouts: list[tuple[int, bytes]]


def _verify_challenge(
    address: str,
    spk: bytes,
    decoded: DecodedSignature,
    signature: str,
    message: bytes,
    engines: Sequence[str],
    allow_legacy: bool,
    max_inputs: int = 10**9,
) -> VerifyResult:
    if decoded.variant == VARIANT_LEGACY:
        if not allow_legacy:
            return VerifyResult(
                State.INVALID, "legacy signatures are not accepted", address, VARIANT_LEGACY, message=message, signature=signature
            )
        result = _legacy(address, spk, signature, message)
        result.message, result.signature = message, signature
        return result

    to_spend_txid = build_to_spend(message, spk).txid()
    result = VerifyResult(
        State.INVALID, "", address, decoded.variant, message=message, signature=signature, to_spend_txid=to_spend_txid.hex()
    )
    try:
        proof = _decode_to_sign(decoded, spk, to_spend_txid)
        if len(proof.to_sign.vin) > max_inputs:
            raise _Verdict(f"proof has {len(proof.to_sign.vin)} inputs, more than the limit of {max_inputs} (max_inputs)")
        _check_shape(result, proof, to_spend_txid)
        tx_bytes = proof.to_sign.serialize()
        _run_required_rules(result, proof.prevouts, tx_bytes, engines)
        _run_upgradeable_rules(result, proof, tx_bytes)
    except _Verdict as verdict:
        result.state, result.reason = verdict.state, verdict.reason
        return result

    result.state = State.VALID
    notes = []
    if proof.to_sign.locktime or proof.to_sign.vin[0].sequence:
        notes.append(f"at time {proof.to_sign.locktime} and age {proof.to_sign.vin[0].sequence}")
    if result.extra_inputs:
        notes.append(f"{result.extra_inputs} additional input(s) signed; their existence in the UTXO set was not checked")
    result.reason = "valid" + (" " + "; ".join(notes) if notes else "")
    return result


def _decode_to_sign(decoded: DecodedSignature, spk: bytes, to_spend_txid: bytes) -> _Proof:
    """Step 1: ``to_sign`` and the outputs it spends, as the variant encodes them."""
    try:
        if decoded.variant == PREFIX_SIMPLE:
            return _to_sign_simple(decoded.payload, spk, to_spend_txid)
        if decoded.variant == PREFIX_FULL:
            return _to_sign_full(decoded.payload, spk)
        if decoded.variant == PREFIX_POF:
            return _to_sign_pof(decoded.payload, spk, to_spend_txid)
        raise _Verdict(f"unknown variant {decoded.variant}")  # pragma: no cover
    except BIP322Error as exc:
        raise _Verdict(f"error parsing signature as {decoded.variant} variant: {exc}") from exc
    except (IndexError, ValueError, TypeError) as exc:  # malformed payload that slipped past the parsers
        raise _Verdict(f"error parsing signature as {decoded.variant} variant: malformed payload ({type(exc).__name__})") from exc


def _to_sign_simple(payload: bytes, spk: bytes, to_spend_txid: bytes) -> _Proof:
    if not is_native_segwit(spk):
        raise _Verdict("simple (smp) signatures are only valid for native segwit addresses (P2WPKH, P2WSH, P2TR)")
    return _Proof(build_to_sign(to_spend_txid, witness=parse_witness(payload)), [(0, spk)])


def _to_sign_full(payload: bytes, spk: bytes) -> _Proof:
    to_sign = parse_transaction(payload)
    if len(to_sign.vin) != 1:
        raise _Verdict(f"full (ful) signature must have exactly one input, found {len(to_sign.vin)}; proofs with extra inputs use pof")
    return _Proof(to_sign, [(0, spk)])


def _to_sign_pof(payload: bytes, spk: bytes, to_spend_txid: bytes) -> _Proof:
    if not payload.startswith(b"psbt\xff"):  # parse_psbt also reads base64 text: one spelling per proof
        raise _Verdict("proof-of-funds payload is not a binary PSBT")
    psbt = parse_psbt(payload)
    if not psbt.inputs:
        raise _Verdict("proof-of-funds PSBT has no inputs")
    if not is_finalized(psbt):
        raise _Verdict("proof-of-funds PSBT is not finalized")
    to_sign = extract_tx(psbt)
    prevouts = psbt_prevouts(psbt)
    inp0 = psbt.inputs[0]
    if inp0.witness_utxo is not None and (inp0.witness_utxo.value != 0 or inp0.witness_utxo.script_pubkey.data != spk):
        raise _Verdict("PSBT witness_utxo for input 0 is not the to_spend output")
    if inp0.non_witness_utxo is not None and inp0.non_witness_utxo.txid() != to_spend_txid:
        raise _Verdict("PSBT non_witness_utxo for input 0 is not the to_spend transaction")
    return _Proof(to_sign, [(0, spk)] + prevouts[1:])


def _check_shape(result: VerifyResult, proof: _Proof, to_spend_txid: bytes) -> None:
    """Step 2: record what ``to_sign`` is, and check that it has the shape BIP-322 gives it."""
    to_sign = proof.to_sign
    result.to_sign_txid = to_sign.txid().hex()
    result.version = to_sign.version
    result.locktime = to_sign.locktime
    result.sequence = to_sign.vin[0].sequence
    result.extra_inputs = len(to_sign.vin) - 1
    if to_sign.vin[0].txid != to_spend_txid or to_sign.vin[0].vout != 0:
        raise _Verdict("to_sign input 0 does not spend the to_spend output for this message and address")
    if len(to_sign.vout) != 1 or not is_op_return_output(to_sign.vout[0]):
        raise _Verdict("to_sign must have exactly one zero-value OP_RETURN output")
    if len(proof.prevouts) != len(to_sign.vin):
        raise _Verdict("missing spent-output data for additional inputs")
    outpoints = [(vin.txid, vin.vout) for vin in to_sign.vin]
    if len(set(outpoints)) != len(outpoints):
        raise _Verdict("to_sign spends the same output more than once")


def _run_required_rules(result: VerifyResult, prevouts: list[tuple[int, bytes]], tx_bytes: bytes, engines: Sequence[str]) -> None:
    """Step 3: consensus and the rules BIP-322 requires; failing them makes the proof invalid."""
    required = btclib_run(prevouts, tx_bytes, BTCLIB_REQUIRED, name="btclib-required")
    result.engines.append(required)
    result.sighash_types = list(required.sighash_types)
    # every requested engine runs even when the verdict is already known, so the
    # per-engine report shows *what kind* of failure this is (e.g. consensus-valid
    # but policy-invalid); the verdict itself never depends on the extra engines
    # passing where btclib failed
    consensus = kernel_run(prevouts, tx_bytes) if "kernel" in engines else None
    if consensus is not None:
        result.engines.append(consensus)
    if not required.ok:
        raise _Verdict(f"{_explain(required.error)} ({required.error})")
    bad = [h for h in required.sighash_types if h not in (SIGHASH_ALL, SIGHASH_DEFAULT)]
    if bad:
        raise _Verdict(f"signature uses sighash type 0x{bad[0]:02x}; BIP-322 requires SIGHASH_ALL (or DEFAULT for taproot)")
    # 0x00 is a Schnorr hash type only; for ECDSA it is undefined (Core's STRICTENC rejects it, btclib's lets it through)
    if SIGHASH_DEFAULT in required.sighash_types and btclib_ecdsa_default_inputs(prevouts, tx_bytes, BTCLIB_REQUIRED):
        raise _Verdict("an ECDSA signature uses sighash type 0x00; BIP-322 requires SIGHASH_ALL (0x00 is DEFAULT for taproot only)")
    if consensus is not None and not consensus.ok:
        raise _Verdict(f"Bitcoin Core consensus engine rejected the proof: {consensus.error}")


def _run_upgradeable_rules(result: VerifyResult, proof: _Proof, tx_bytes: bytes) -> None:
    """Step 4: the rules a later soft fork may relax; failing them makes the verdict inconclusive."""
    if proof.to_sign.version not in (0, 2):
        raise _Verdict(f"to_sign version {proof.to_sign.version} is not 0 or 2", State.INCONCLUSIVE)
    upgradeable = btclib_run(proof.prevouts, tx_bytes, BTCLIB_REQUIRED | BTCLIB_UPGRADEABLE, name="btclib-upgradeable")
    result.engines.append(upgradeable)
    if not upgradeable.ok:
        raise _Verdict(f"uses upgradeable script features: {upgradeable.error}", State.INCONCLUSIVE)
