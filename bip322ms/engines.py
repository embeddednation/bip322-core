"""Script interpreters used by the verifier.

Two engines are wired in:

* ``btclib`` - pure-Python interpreter with the full policy flag set, so the
  BIP-322 *required* and *upgradeable* rule lists can be expressed exactly.
* ``kernel`` - Bitcoin Core's own interpreter through libbitcoinkernel
  (``py-bitcoinkernel``).  The kernel C API only exposes consensus flags, so it
  is used as an additional consensus check, never as the sole judge.

Both take the same inputs: the spent outputs ``[(value, script_pubkey), ...]``
in input order and the serialized spending transaction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

Prevout = tuple[int, bytes]


@dataclass
class EngineRun:
    engine: str
    ok: bool
    error: str | None = None
    #: sighash types of every stack element the interpreter consumed as a
    #: signature (btclib only; the kernel does not report them)
    sighash_types: list[int] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# btclib
# --------------------------------------------------------------------------- #

from btclib.exceptions import BTClibRuntimeError, BTClibValueError  # noqa: E402
from btclib.script.engine import ALL_FLAGS, ScriptFlag, verify_transaction  # noqa: E402
from btclib.tx import Tx, TxOut  # noqa: E402

#: BIP-322 "required rules" (plus consensus): failing these is *invalid*.
BTCLIB_REQUIRED = (
    ALL_FLAGS
    | ScriptFlag.STRICTENC
    | ScriptFlag.LOW_S
    | ScriptFlag.NULLFAIL
    | ScriptFlag.MINIMALDATA
    | ScriptFlag.CLEANSTACK
    | ScriptFlag.MINIMALIF
    | ScriptFlag.CONST_SCRIPTCODE
)

#: BIP-322 "upgradeable rules": failing these is *inconclusive*.
BTCLIB_UPGRADEABLE = (
    ScriptFlag.DISCOURAGE_UPGRADABLE_NOPS
    | ScriptFlag.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
    | ScriptFlag.DISCOURAGE_UPGRADABLE_PUBKEYTYPE
    | ScriptFlag.DISCOURAGE_OP_SUCCESS
    | ScriptFlag.DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
)


def btclib_run(prevouts: Sequence[Prevout], tx_bytes: bytes, flags: ScriptFlag, name: str = "btclib") -> EngineRun:
    hash_types: list[int] = []
    try:
        tx = Tx.parse(tx_bytes)
        outs = [TxOut(value, spk) for value, spk in prevouts]
        verify_transaction(outs, tx, flags, check_amounts=True, hash_types=hash_types)
    except (BTClibValueError, BTClibRuntimeError, ValueError, RuntimeError) as exc:
        return EngineRun(name, False, f"{type(exc).__name__}: {exc}", hash_types)
    return EngineRun(name, True, None, hash_types)


# --------------------------------------------------------------------------- #
# libbitcoinkernel (optional)
# --------------------------------------------------------------------------- #


def kernel_available() -> bool:
    try:
        import pbk.script  # noqa: F401
        import pbk.transaction  # noqa: F401
    except Exception:  # noqa: BLE001
        return False
    return True


def kernel_run(prevouts: Sequence[Prevout], tx_bytes: bytes) -> EngineRun:
    """Verify every input with Bitcoin Core's interpreter (consensus flags)."""
    try:
        from pbk.script import (
            PrecomputedTransactionData,
            ScriptPubkey,
            ScriptVerificationFlags,
            ScriptVerifyException,
        )
        from pbk.transaction import Transaction, TransactionOutput
    except Exception as exc:  # noqa: BLE001
        return EngineRun("kernel", False, f"py-bitcoinkernel not available: {exc}")
    try:
        tx = Transaction(bytes(tx_bytes))
        outs = [TransactionOutput(ScriptPubkey(bytes(spk)), value) for value, spk in prevouts]
        precomputed = PrecomputedTransactionData(tx, outs)
        for index, (value, spk) in enumerate(prevouts):
            ok = ScriptPubkey(bytes(spk)).verify(value, tx, precomputed, index, ScriptVerificationFlags.ALL)
            if not ok:
                return EngineRun("kernel", False, f"input {index}: script evaluation failed")
    except ScriptVerifyException as exc:
        return EngineRun("kernel", False, f"script verify status: {exc.status.name}")
    except Exception as exc:  # noqa: BLE001
        return EngineRun("kernel", False, f"{type(exc).__name__}: {exc}")
    return EngineRun("kernel", True)


def available_engines() -> list[str]:
    engines = ["btclib"]
    if kernel_available():
        engines.append("kernel")
    return engines
