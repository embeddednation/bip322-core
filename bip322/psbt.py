"""BIP-322 PSBTs: creation, inspection, combining, finalizing, extraction.

The PSBT is the ``to_sign`` transaction (version 0, locktime 0, one input with
sequence 0, one zero-value ``OP_RETURN`` output) plus the metadata a signer
needs: the ``to_spend`` output as ``witness_utxo`` (and optionally the whole
``to_spend`` as ``non_witness_utxo``), the witness script, BIP32 derivations
for every cosigner and the global ``PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE``
field holding the message.

embit's ``PSBT`` reconstructs the unsigned transaction with ``version or 2``
and ``sequence or 0xffffffff``, which silently turns the BIP-322 zeros into
defaults; :class:`BIP322PSBT` fixes both.
"""

from __future__ import annotations

import copy
import hashlib
from collections import OrderedDict
from collections.abc import Sequence
from dataclasses import dataclass, field

from embit import ec
from embit.finalizer import parse_multisig
from embit.hashes import hash160
from embit.networks import NETWORKS
from embit.psbt import PSBT, DerivationPath, InputScope
from embit.script import Script, Witness
from embit.transaction import SIGHASH, Transaction, TransactionInput, TransactionOutput

from .core import (
    PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE,
    SIGHASH_ALL,
    BIP322Error,
    build_to_sign,
    build_to_spend,
    encode_full,
    encode_pof,
    encode_simple,
    is_native_segwit,
    is_op_return_output,
)
from .wallet import DerivedAddress

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class PSBTBuildError(BIP322Error):
    """The PSBT is not a well-formed BIP-322 PSBT."""


class FinalizeError(BIP322Error):
    """Not enough (valid) signatures to finalize."""


# --------------------------------------------------------------------------- #
# embit fixes
# --------------------------------------------------------------------------- #


class BIP322InputScope(InputScope):
    def __init__(self, unknown: dict | None = None, vin=None, compress=None):
        kwargs = {} if compress is None else {"compress": compress}
        super().__init__({} if unknown is None else unknown, vin=vin, **kwargs)

    @property
    def vin(self):
        sequence = self.sequence if self.sequence is not None else 0xFFFFFFFF
        return TransactionInput(self.txid, self.vout, sequence=sequence)


class BIP322PSBT(PSBT):
    PSBTIN_CLS = BIP322InputScope

    def __init__(self, tx=None, unknown: dict | None = None, version=None):
        super().__init__(tx, {} if unknown is None else unknown, version=version)

    @property
    def tx(self):
        version = self.tx_version if self.tx_version is not None else 2
        return self.TX_CLS(
            version=version,
            locktime=self.locktime or 0,
            vin=[inp.vin for inp in self.inputs],
            vout=[out.vout for out in self.outputs],
        )

    @property
    def message(self) -> bytes | None:
        return self.unknown.get(PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE)

    @message.setter
    def message(self, value: bytes | None) -> None:
        if value is None:
            self.unknown.pop(PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE, None)
        else:
            self.unknown[PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE] = bytes(value)


def parse_psbt(data: bytes | str) -> BIP322PSBT:
    """Parse binary or base64 PSBT text."""
    if isinstance(data, str):
        text = data.strip()
        try:
            return BIP322PSBT.from_string(text)
        except Exception as exc:  # noqa: BLE001
            raise PSBTBuildError(f"cannot parse PSBT: {exc}") from exc
    raw = bytes(data)
    if raw.startswith(b"psbt\xff"):
        try:
            return BIP322PSBT.parse(raw)
        except Exception as exc:  # noqa: BLE001
            raise PSBTBuildError(f"cannot parse PSBT: {exc}") from exc
    try:
        text = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise PSBTBuildError("not a PSBT (bad magic bytes)") from exc
    if not text.startswith("cHNidP8"):
        raise PSBTBuildError("not a PSBT (neither binary magic nor base64 magic)")
    return parse_psbt(text)


# --------------------------------------------------------------------------- #
# creation
# --------------------------------------------------------------------------- #


def create_psbt(
    derived: DerivedAddress,
    message: bytes,
    *,
    xpubs: dict | None = None,
    utxo_mode: str = "witness",
    version: int = 0,
    locktime: int = 0,
    sequence: int = 0,
    psbt_version: int | None = None,
    explicit_sighash: bool = True,
) -> BIP322PSBT:
    """Build the BIP-322 PSBT for ``message`` and a derived wallet address.

    ``utxo_mode`` is ``"witness"`` (witness_utxo only, default), ``"non_witness"``
    (the whole ``to_spend`` as non_witness_utxo) or ``"both"``.
    """
    if utxo_mode not in ("witness", "non_witness", "both"):
        raise ValueError("utxo_mode must be witness, non_witness or both")
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes")
    to_spend = build_to_spend(message, derived.script_pubkey)
    to_sign = build_to_sign(to_spend.txid(), version=version, locktime=locktime, sequence=sequence)
    psbt = BIP322PSBT(to_sign, unknown={}, version=psbt_version)
    inp = psbt.inputs[0]
    if utxo_mode in ("witness", "both"):
        inp.witness_utxo = TransactionOutput(0, Script(bytes(derived.script_pubkey)))
    if utxo_mode in ("non_witness", "both"):
        inp.non_witness_utxo = to_spend
    if derived.witness_script is not None:
        inp.witness_script = Script(bytes(derived.witness_script))
    for sec, (fingerprint, path) in derived.derivations.items():
        inp.bip32_derivations[ec.PublicKey.parse(sec)] = DerivationPath(bytes(fingerprint), list(path))
    if explicit_sighash:
        inp.sighash_type = SIGHASH_ALL
    psbt.message = bytes(message)
    if xpubs:
        for xpub, derivation in xpubs.items():
            psbt.xpubs[xpub] = derivation
    return psbt


# --------------------------------------------------------------------------- #
# inspection (the BIP's "PSBT signer" detection rules)
# --------------------------------------------------------------------------- #


@dataclass
class PSBTInfo:
    is_bip322: bool
    problems: list[str] = field(default_factory=list)
    message: bytes | None = None
    script_pubkey: bytes | None = None
    address: str | None = None
    to_spend_txid: str | None = None
    to_sign_txid: str | None = None
    tx_version: int | None = None
    locktime: int | None = None
    sequence: int | None = None
    num_inputs: int = 0
    witness_script: bytes | None = None
    threshold: int | None = None
    pubkeys: list[str] = field(default_factory=list)
    #: input 0 partial signatures: pubkey hex -> sighash byte
    partial_sigs: dict[str, int] = field(default_factory=dict)
    #: input 0 cosigners: one entry per known key (from the key paths or the witness script)
    signers: list[dict] = field(default_factory=list)
    finalized: bool = False
    #: not BIP-322 violations, but things a hardware signer will refuse without
    warnings: list[str] = field(default_factory=list)


def inspect_psbt(psbt: BIP322PSBT, network: str = "main") -> PSBTInfo:
    info = PSBTInfo(is_bip322=False)
    tx = psbt.tx
    info.tx_version = tx.version
    info.locktime = tx.locktime
    info.num_inputs = len(psbt.inputs)
    info.to_sign_txid = tx.txid().hex()
    message = psbt.message
    if message is None:
        info.problems.append("PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE (0x09) missing")
    info.message = message
    if not psbt.inputs:
        info.problems.append("PSBT has no inputs")
        return info
    inp = psbt.inputs[0]
    info.sequence = inp.sequence
    spk = inp.script_pubkey.data if inp.script_pubkey is not None else None
    if spk is None:
        info.problems.append("input 0 has neither witness_utxo nor non_witness_utxo")
    else:
        info.script_pubkey = spk
        try:
            info.address = Script(spk).address(NETWORKS[network])
        except Exception:  # noqa: BLE001
            info.address = None
    if inp.vout != 0:
        info.problems.append(f"input 0 spends prevout n={inp.vout}, expected 0")
    if message is not None and spk is not None:
        to_spend = build_to_spend(message, spk)
        info.to_spend_txid = to_spend.txid().hex()
        if inp.txid != to_spend.txid():
            info.problems.append("input 0 prevout txid is not the to_spend txid for this message and script")
        if inp.non_witness_utxo is not None and inp.non_witness_utxo.serialize() != to_spend.serialize():
            info.problems.append("non_witness_utxo of input 0 is not the to_spend transaction")
        if inp.witness_utxo is not None and (inp.witness_utxo.value != 0 or inp.witness_utxo.script_pubkey.data != spk):
            info.problems.append("witness_utxo of input 0 is not the to_spend output")
    outs = tx.vout
    if len(outs) != 1 or not is_op_return_output(outs[0]):
        info.problems.append("to_sign must have exactly one zero-value OP_RETURN output")
    if tx.version not in (0, 2):
        info.problems.append(f"to_sign version {tx.version} is not 0 or 2")
    if inp.sighash_type not in (None, SIGHASH_ALL):
        info.problems.append(f"input 0 requests sighash type 0x{inp.sighash_type:02x}; BIP-322 requires SIGHASH_ALL")
    spk_type = Script(spk).script_type() if spk is not None else None
    already_final = bool(inp.final_scriptwitness) or bool(inp.final_scriptsig)
    if not already_final:  # the finalizer removes these on purpose
        if spk_type == "p2wsh" and inp.witness_script is None:
            info.warnings.append("no witness_script for the P2WSH input (hardware signers need it)")
        if spk is not None and not inp.bip32_derivations:
            info.warnings.append("no BIP32 derivation paths (hardware signers need them to find their key)")
    if inp.witness_script is not None:
        info.witness_script = inp.witness_script.data
        try:
            threshold, pubkeys = parse_multisig(inp.witness_script)
            info.threshold = threshold
            info.pubkeys = [pk.sec().hex() for pk in pubkeys]
        except Exception:  # noqa: BLE001
            pass
    elif spk is not None and Script(spk).script_type() == "p2wpkh":
        info.threshold = 1
        info.pubkeys = [pk.sec().hex() for pk in inp.bip32_derivations] or [pk.sec().hex() for pk in inp.partial_sigs]
    for pub, sig in inp.partial_sigs.items():
        info.partial_sigs[pub.sec().hex()] = sig[-1] if sig else -1
        if not sig or sig[-1] != SIGHASH_ALL:
            info.problems.append(f"partial signature by {pub.sec().hex()[:16]}... does not use SIGHASH_ALL")
    info.finalized = bool(inp.final_scriptwitness) or bool(inp.final_scriptsig)
    if not info.finalized:
        info.signers = signer_report(psbt, 0)
    info.is_bip322 = not info.problems
    return info


# --------------------------------------------------------------------------- #
# signers: who has signed, and does each signature verify
# --------------------------------------------------------------------------- #


def signer_report(psbt: BIP322PSBT, input_index: int = 0) -> list[dict]:
    """One entry per known key of the input: fingerprint, path, pubkey, and the state of its signature.

    ``signature`` is ``"valid"``, ``"missing"`` or ``"invalid: <reason>"``; each partial
    signature is verified against the input's sighash exactly as the finalizer does.
    """
    inp = psbt.inputs[input_index]
    from .wallet import path_to_str

    report = []
    for pub in _input_keys(inp):
        derivation = inp.bip32_derivations.get(pub)
        entry = {
            "pubkey": pub.sec().hex(),
            "fingerprint": derivation.fingerprint.hex() if derivation else None,
            "path": path_to_str(derivation.derivation) if derivation else None,
        }
        sig = inp.partial_sigs.get(pub)
        if sig is None:
            entry["signature"] = "missing"
        else:
            try:
                check_partial_signature(psbt, input_index, pub, sig)
                entry["signature"] = "valid"
            except FinalizeError as exc:
                entry["signature"] = f"invalid: {exc}"
        report.append(entry)
    return report


def resolve_signers(psbt: BIP322PSBT, selectors: Sequence[str], input_index: int = 0) -> set[ec.PublicKey]:
    """Map fingerprints or pubkey (prefixes) to the input's keys; unknown selectors are an error."""
    inp = psbt.inputs[input_index]
    by_hex = {pub.sec().hex(): pub for pub in _input_keys(inp)}
    fingerprints = {pub.sec().hex(): inp.bip32_derivations[pub].fingerprint.hex() for pub in inp.bip32_derivations}
    chosen: set[ec.PublicKey] = set()
    for selector in selectors:
        sel = selector.strip().lower()
        matches = [h for h in by_hex if sel and (fingerprints.get(h) == sel or h.startswith(sel))]
        if len(matches) != 1:
            known = ", ".join(fingerprints.get(h) or h[:16] for h in by_hex)
            raise FinalizeError(f"signer {selector!r} does not identify exactly one key of input {input_index} (known: {known})")
        chosen.add(by_hex[matches[0]])
    return chosen


def _input_keys(inp) -> list[ec.PublicKey]:
    """The input's keys in witness-script order, then any others with a path or a signature."""
    keys: list[ec.PublicKey] = []
    if inp.witness_script is not None:
        try:
            keys = list(parse_multisig(inp.witness_script)[1])
        except Exception:  # noqa: BLE001
            keys = []
    for pub in list(inp.bip32_derivations) + list(inp.partial_sigs):
        if pub not in keys:
            keys.append(pub)
    return keys


# --------------------------------------------------------------------------- #
# combine / finalize / extract
# --------------------------------------------------------------------------- #


def combine_psbts(psbts: Sequence[BIP322PSBT]) -> BIP322PSBT:
    if not psbts:
        raise PSBTBuildError("nothing to combine")
    base = copy.deepcopy(psbts[0])
    base_txid = base.tx.txid()
    for other in psbts[1:]:
        if other.tx.txid() != base_txid:
            raise PSBTBuildError("PSBTs sign different transactions and cannot be combined")
        if other.message != base.message:
            raise PSBTBuildError("PSBTs carry different messages and cannot be combined")
        for index, (mine, theirs) in enumerate(zip(base.inputs, other.inputs, strict=True)):
            _check_mergeable(index, mine, theirs)
            mine.update(theirs)
        for mine, theirs in zip(base.outputs, other.outputs, strict=True):
            mine.update(theirs)
        base.xpubs.update(other.xpubs)
        for key, value in other.unknown.items():
            base.unknown.setdefault(key, value)
    return base


def _check_mergeable(index: int, mine, theirs) -> None:
    """Refuse to combine inputs whose shared fields disagree (BIP-174 combiner rule)."""
    pairs = (
        ("witness_utxo", lambda x: x.serialize() if x is not None else None),
        ("non_witness_utxo", lambda x: x.serialize() if x is not None else None),
        ("witness_script", lambda x: x.data if x is not None else None),
        ("redeem_script", lambda x: x.data if x is not None else None),
        ("sighash_type", lambda x: x),
    )
    for name, view in pairs:
        a, b = view(getattr(mine, name)), view(getattr(theirs, name))
        if a is not None and b is not None and a != b:
            raise PSBTBuildError(f"input {index}: {name} differs between the PSBTs being combined")


def _der_r_s(der: bytes) -> tuple[int, int]:
    """Strict DER (BIP-66) parse of an ECDSA signature without its sighash byte."""
    bad = FinalizeError("signature is not strictly DER encoded (BIP-66)")
    if not 8 <= len(der) <= 72 or der[0] != 0x30 or der[1] != len(der) - 2 or der[2] != 0x02:
        raise bad
    len_r = der[3]
    if len_r == 0 or 5 + len_r >= len(der):
        raise bad
    if der[4 + len_r] != 0x02:
        raise bad
    len_s = der[5 + len_r]
    if len_s == 0 or len_r + len_s + 6 != len(der):
        raise bad
    r_bytes = der[4 : 4 + len_r]
    s_bytes = der[6 + len_r : 6 + len_r + len_s]
    for part in (r_bytes, s_bytes):
        if part[0] & 0x80:  # negative
            raise bad
        if len(part) > 1 and part[0] == 0 and not part[1] & 0x80:  # non-minimal
            raise bad
    return int.from_bytes(r_bytes, "big"), int.from_bytes(s_bytes, "big")


def check_partial_signature(psbt: BIP322PSBT, input_index: int, pubkey: ec.PublicKey, sig: bytes) -> None:
    """Raise :class:`FinalizeError` unless ``sig`` is a valid low-S SIGHASH_ALL signature by ``pubkey``."""
    if not sig or sig[-1] != SIGHASH_ALL:
        raise FinalizeError(f"signature by {pubkey.sec().hex()} does not use SIGHASH_ALL")
    der = sig[:-1]
    _, s = _der_r_s(der)
    if s > SECP256K1_N // 2:
        raise FinalizeError(f"signature by {pubkey.sec().hex()} is not low-S")
    digest = psbt.sighash(input_index, sighash=SIGHASH.ALL)
    try:
        signature = ec.Signature.parse(der)
    except Exception as exc:  # noqa: BLE001
        raise FinalizeError(f"signature by {pubkey.sec().hex()} is malformed: {exc}") from exc
    if not pubkey.verify(signature, digest):
        raise FinalizeError(f"signature by {pubkey.sec().hex()} does not verify against the to_sign sighash")


def _finalize_p2wpkh(psbt: BIP322PSBT, input_index: int, inp, spk: bytes) -> Witness:
    program = spk[2:]
    for pub, sig in inp.partial_sigs.items():
        if hash160(pub.sec()) != program:
            continue
        check_partial_signature(psbt, input_index, pub, sig)
        return Witness([sig, pub.sec()])
    raise FinalizeError(f"input {input_index}: no partial signature by the key of this P2WPKH address ({len(inp.partial_sigs)} present)")


def finalize_input(psbt: BIP322PSBT, input_index: int, *, strict: bool = True, signers: set[ec.PublicKey] | None = None) -> Witness:
    """Build the witness for one input (BIP-174 input finalizer): P2WSH multisig or P2WPKH.

    ``signers`` restricts which keys' partial signatures may be used (e.g. to prove
    that a particular pair of cosigners works); every selected signer must have a
    valid signature.
    """
    inp = psbt.inputs[input_index]
    if inp.final_scriptwitness:
        return inp.final_scriptwitness
    if signers is not None:
        absent = [pub for pub in signers if pub not in inp.partial_sigs]
        if absent:
            raise FinalizeError(f"input {input_index}: selected signer(s) without a signature: " + ", ".join(p.sec().hex()[:16] + "..." for p in absent))
    spk = inp.script_pubkey
    if spk is None:
        raise FinalizeError(f"input {input_index}: no witness_utxo / non_witness_utxo")
    if inp.witness_script is None:
        if spk.script_type() != "p2wpkh":
            raise FinalizeError(f"input {input_index}: no witness_script; only P2WSH multisig and P2WPKH inputs can be finalized")
        witness = _finalize_p2wpkh(psbt, input_index, inp, spk.data)
    else:
        try:
            threshold, pubkeys = parse_multisig(inp.witness_script)
        except Exception as exc:  # noqa: BLE001
            raise FinalizeError(f"input {input_index}: witness script is not a k-of-n CHECKMULTISIG: {exc}") from exc
        if spk.data != b"\x00\x20" + hashlib.sha256(inp.witness_script.data).digest():
            raise FinalizeError(f"input {input_index}: witness_script does not hash to the spent script_pubkey")
        sigs: list[bytes] = []
        rejected: list[str] = []
        for pub in pubkeys:
            sig = inp.partial_sigs.get(pub)
            if sig is None or (signers is not None and pub not in signers):
                continue
            try:
                check_partial_signature(psbt, input_index, pub, sig)
            except FinalizeError as exc:
                if strict:
                    raise
                rejected.append(str(exc))
                continue
            sigs.append(sig)
            if len(sigs) == threshold:
                break
        if len(sigs) < threshold:
            have = len(inp.partial_sigs) if signers is None else len([p for p in signers if p in inp.partial_sigs])
            detail = f" ({'; '.join(rejected)})" if rejected else ""
            scope = " among the selected signers" if signers is not None else ""
            raise FinalizeError(f"input {input_index}: need {threshold} valid signatures, have {len(sigs)} of {have} partial signatures{scope}{detail}")
        witness = Witness([b""] + sigs + [inp.witness_script.data])
    inp.final_scriptwitness = witness
    if inp.redeem_script is not None:  # sh(wsh()) - not produced by this tool but handled
        inp.final_scriptsig = Script(_push(inp.redeem_script.data))
    # BIP-174: the finalizer removes the fields the signatures replaced; unknown
    # (proprietary) fields are kept
    inp.partial_sigs = OrderedDict()
    inp.sighash_type = None
    inp.redeem_script = None
    inp.witness_script = None
    inp.bip32_derivations = OrderedDict()
    return witness


def _push(data: bytes) -> bytes:
    if len(data) < 0x4C:
        return bytes([len(data)]) + data
    if len(data) <= 0xFF:
        return b"\x4c" + bytes([len(data)]) + data
    return b"\x4d" + len(data).to_bytes(2, "little") + data


def finalize_psbt(psbt: BIP322PSBT, *, strict: bool = True, signers: Sequence[str] | None = None) -> BIP322PSBT:
    """Finalize every input in place and return the PSBT.

    ``signers`` selects cosigners by fingerprint or pubkey prefix; only their
    signatures are used (input 0), and each must be present and valid.
    """
    chosen = resolve_signers(psbt, signers, 0) if signers else None
    for index in range(len(psbt.inputs)):
        finalize_input(psbt, index, strict=strict, signers=chosen if index == 0 else None)
    return psbt


def is_finalized(psbt: BIP322PSBT) -> bool:
    return bool(psbt.inputs) and all(bool(i.final_scriptwitness) or bool(i.final_scriptsig) for i in psbt.inputs)


def extract_tx(psbt: BIP322PSBT) -> Transaction:
    """The signed ``to_sign`` transaction from a finalized PSBT."""
    tx = psbt.tx
    for index, inp in enumerate(psbt.inputs):
        if not inp.final_scriptwitness and not inp.final_scriptsig:
            raise FinalizeError(f"input {index} is not finalized")
        if inp.final_scriptsig:
            tx.vin[index].script_sig = inp.final_scriptsig
        if inp.final_scriptwitness:
            tx.vin[index].witness = inp.final_scriptwitness
    return tx


def psbt_prevouts(psbt: BIP322PSBT) -> list[tuple[int, bytes]]:
    """``(value, script_pubkey)`` for every input, using the BIP-322 same-txid fallback."""
    prevouts: list[tuple[int, bytes]] = []
    seen_non_witness: dict[bytes, Transaction] = {}
    for index, inp in enumerate(psbt.inputs):
        from_tx = None
        prev_tx = inp.non_witness_utxo
        if prev_tx is not None:
            if prev_tx.txid() != inp.txid:
                raise PSBTBuildError(f"input {index}: non_witness_utxo is not the transaction the input spends")
            seen_non_witness[inp.txid] = prev_tx
        elif inp.txid in seen_non_witness:
            prev_tx = seen_non_witness[inp.txid]  # BIP-322: reuse an earlier input's non_witness_utxo
        if prev_tx is not None:
            if inp.vout >= len(prev_tx.vout):
                raise PSBTBuildError(f"input {index}: prevout index {inp.vout} beyond the previous transaction's outputs")
            from_tx = prev_tx.vout[inp.vout]
        utxo = inp.witness_utxo if inp.witness_utxo is not None else from_tx
        if utxo is None:
            raise PSBTBuildError(f"input {index} has no witness_utxo / non_witness_utxo")
        if from_tx is not None and inp.witness_utxo is not None and from_tx.serialize() != inp.witness_utxo.serialize():
            raise PSBTBuildError(f"input {index}: witness_utxo and non_witness_utxo disagree")
        prevouts.append((utxo.value, utxo.script_pubkey.data))
    return prevouts


def choose_variant(psbt: BIP322PSBT) -> str:
    """``smp`` when the BIP allows it, ``ful`` for one input otherwise, ``pof`` for more."""
    tx = psbt.tx
    if len(tx.vin) > 1:
        return "pof"
    inp = psbt.inputs[0]
    spk = inp.script_pubkey.data if inp.script_pubkey is not None else b""
    simple_ok = (
        tx.version == 0
        and tx.locktime == 0
        and tx.vin[0].sequence == 0
        and not (inp.final_scriptsig and inp.final_scriptsig.data)
        and is_native_segwit(spk)
    )
    return "smp" if simple_ok else "ful"


def signature_from_psbt(psbt: BIP322PSBT, variant: str = "auto") -> str:
    """Encode the finalized PSBT as a BIP-322 signature string."""
    if not is_finalized(psbt):
        raise FinalizeError("PSBT is not finalized")
    if variant == "auto":
        variant = choose_variant(psbt)
    tx = extract_tx(psbt)
    if variant == "smp":
        if choose_variant(psbt) != "smp":
            raise FinalizeError("the simple (smp) variant is only allowed for a native segwit address with default version/locktime/sequence and no extra inputs")
        return encode_simple(tx.vin[0].witness.items)
    if variant == "ful":
        if len(tx.vin) != 1:
            raise FinalizeError("the full (ful) variant cannot carry additional inputs; use pof")
        return encode_full(tx)
    if variant == "pof":
        return encode_pof(psbt.serialize())
    raise ValueError(f"unknown variant {variant!r}")
