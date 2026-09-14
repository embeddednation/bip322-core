"""BIP-322 verification: *valid*, *invalid* or *inconclusive*.

The framing (``to_spend`` / ``to_sign``, shape checks, variant rules and the
SIGHASH_ALL rule) is implemented here; script evaluation is delegated to the
engines in :mod:`bip322.engines`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Sequence

from embit.script import Script, address_to_scriptpubkey
from embit.transaction import Transaction

from .core import (
    PREFIX_FULL,
    PREFIX_POF,
    PREFIX_SIMPLE,
    SIGHASH_ALL,
    SIGHASH_DEFAULT,
    VARIANT_LEGACY,
    SignatureFormatError,
    build_to_sign,
    build_to_spend,
    decode_signature,
    is_native_segwit,
    is_op_return_output,
    parse_transaction,
    parse_witness,
)
from .engines import BTCLIB_REQUIRED, BTCLIB_UPGRADEABLE, EngineRun, btclib_run, kernel_run
from .psbt import PSBTBuildError, extract_tx, is_finalized, parse_psbt, psbt_prevouts


class State(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    INCONCLUSIVE = "inconclusive"


@dataclass
class VerifyResult:
    state: State
    reason: str
    address: str = ""
    variant: str | None = None
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
        return {
            "state": self.state.value,
            "reason": self.reason,
            "address": self.address,
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
    ("der", "a signature is not strictly DER encoded"),
    ("clean stack", "the witness has extra elements"),
    ("stack underflow", "the witness is missing elements"),
    ("dummy", "the CHECKMULTISIG dummy element is not empty"),
    ("false top stack", "the script evaluated to false"),
)


def _explain(error: str | None) -> str:
    text = (error or "").lower()
    for needle, explanation in _EXPLANATIONS:
        if needle.lower() in text:
            return explanation
    return "script verification failed"


def script_pubkey_from_address(address: str) -> bytes:
    try:
        return address_to_scriptpubkey(address.strip()).data
    except Exception as exc:  # noqa: BLE001
        raise SignatureFormatError(f"invalid address {address!r}: {exc}") from exc


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
) -> VerifyResult:
    """Verify a BIP-322 signature for ``address`` over ``message`` (bytes).

    ``engines`` may contain ``"btclib"`` (always run) and ``"kernel"``.
    """
    if isinstance(message, str):
        raise TypeError("message must be bytes; encode text as UTF-8")
    try:
        spk = script_pubkey_from_address(address)
        decoded = decode_signature(signature, allow_unprefixed=allow_unprefixed)
    except SignatureFormatError as exc:
        return VerifyResult(State.INVALID, str(exc), address)

    if decoded.variant == VARIANT_LEGACY:
        if not allow_legacy:
            return VerifyResult(State.INVALID, "legacy signatures are not accepted", address, VARIANT_LEGACY)
        return _legacy(address, spk, signature, message)

    to_spend = build_to_spend(message, spk)
    to_spend_txid = to_spend.txid()
    prevouts: list[tuple[int, bytes]] = [(0, spk)]
    result = VerifyResult(State.INVALID, "", address, decoded.variant, to_spend_txid=to_spend_txid.hex())

    try:
        if decoded.variant == PREFIX_SIMPLE:
            if not is_native_segwit(spk):
                result.reason = "simple (smp) signatures are only valid for native segwit addresses (P2WPKH, P2WSH, P2TR)"
                return result
            witness = parse_witness(decoded.payload)
            to_sign = build_to_sign(to_spend_txid, witness=witness)
        elif decoded.variant == PREFIX_FULL:
            to_sign = parse_transaction(decoded.payload)
            if len(to_sign.vin) != 1:
                result.reason = f"full (ful) signature must have exactly one input, found {len(to_sign.vin)}; proofs with extra inputs use pof"
                return result
        elif decoded.variant == PREFIX_POF:
            psbt = parse_psbt(decoded.payload)
            if not is_finalized(psbt):
                result.reason = "proof-of-funds PSBT is not finalized"
                return result
            to_sign = extract_tx(psbt)
            pp = psbt_prevouts(psbt)
            inp0 = psbt.inputs[0]
            if inp0.witness_utxo is not None and (inp0.witness_utxo.value != 0 or inp0.witness_utxo.script_pubkey.data != spk):
                result.reason = "PSBT witness_utxo for input 0 is not the to_spend output"
                return result
            if inp0.non_witness_utxo is not None and inp0.non_witness_utxo.txid() != to_spend_txid:
                result.reason = "PSBT non_witness_utxo for input 0 is not the to_spend transaction"
                return result
            prevouts = [(0, spk)] + pp[1:]
        else:  # pragma: no cover
            result.reason = f"unknown variant {decoded.variant}"
            return result
    except (SignatureFormatError, PSBTBuildError) as exc:
        result.reason = f"error parsing signature as {decoded.variant} variant: {exc}"
        return result

    # ---- shape checks ------------------------------------------------------ #
    result.to_sign_txid = to_sign.txid().hex()
    result.version = to_sign.version
    result.locktime = to_sign.locktime
    result.sequence = to_sign.vin[0].sequence
    result.extra_inputs = len(to_sign.vin) - 1
    if to_sign.vin[0].txid != to_spend_txid or to_sign.vin[0].vout != 0:
        result.reason = "to_sign input 0 does not spend the to_spend output for this message and address"
        return result
    if len(to_sign.vout) != 1 or not is_op_return_output(to_sign.vout[0]):
        result.reason = "to_sign must have exactly one zero-value OP_RETURN output"
        return result
    if len(prevouts) != len(to_sign.vin):
        result.reason = "missing spent-output data for additional inputs"
        return result

    # ---- required rules ---------------------------------------------------- #
    tx_bytes = to_sign.serialize()
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
        result.reason = f"{_explain(required.error)} ({required.error})"
        return result
    bad = [h for h in required.sighash_types if h not in (SIGHASH_ALL, SIGHASH_DEFAULT)]
    if bad:
        result.reason = f"signature uses sighash type 0x{bad[0]:02x}; BIP-322 requires SIGHASH_ALL (or DEFAULT for taproot)"
        return result
    if consensus is not None and not consensus.ok:
        result.reason = f"Bitcoin Core consensus engine rejected the proof: {consensus.error}"
        return result

    # ---- upgradeable rules ------------------------------------------------- #
    if to_sign.version not in (0, 2):
        result.state = State.INCONCLUSIVE
        result.reason = f"to_sign version {to_sign.version} is not 0 or 2"
        return result
    upgradeable = btclib_run(prevouts, tx_bytes, BTCLIB_REQUIRED | BTCLIB_UPGRADEABLE, name="btclib-upgradeable")
    result.engines.append(upgradeable)
    if not upgradeable.ok:
        result.state = State.INCONCLUSIVE
        result.reason = f"uses upgradeable script features: {upgradeable.error}"
        return result

    result.state = State.VALID
    if to_sign.locktime or to_sign.vin[0].sequence:
        result.reason = f"valid at time {to_sign.locktime} and age {to_sign.vin[0].sequence}"
    else:
        result.reason = "valid"
    return result


def verify_to_sign(address: str, to_sign: Transaction, message: bytes, **kwargs) -> VerifyResult:
    """Convenience: verify an already-built ``to_sign`` transaction (``ful`` semantics)."""
    from .core import encode_full

    return verify_message(address, encode_full(to_sign), message, **kwargs)
