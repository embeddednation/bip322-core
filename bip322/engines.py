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

import functools
from collections.abc import Sequence
from dataclasses import dataclass, field

from .core import BIP322Error

Prevout = tuple[int, bytes]
KNOWN_ENGINES = ("btclib", "kernel")


class EngineError(BIP322Error):
    """A requested script engine is unknown or not installed."""


def check_engines(engines: Sequence[str]) -> None:
    """Raise :class:`EngineError` unless every requested engine can run."""
    unknown = [e for e in engines if e not in KNOWN_ENGINES]
    if unknown:
        raise EngineError(f"unknown engine(s) {unknown}; known: {list(KNOWN_ENGINES)}")
    if "kernel" in engines and not kernel_available():
        raise EngineError("the kernel engine was requested but py-bitcoinkernel is not installed")


@dataclass
class EngineRun:
    engine: str
    ok: bool
    error: str | None = None
    #: sighash types of every stack element the interpreter consumed as a
    #: signature (btclib only; the kernel does not report them)
    sighash_types: list[int] = field(default_factory=list)
    #: version of the interpreter that ran (btclib release, or the Bitcoin Core version inside libbitcoinkernel)
    version: str | None = None
    #: for the kernel: the Python bindings package and version
    bindings: str | None = None

    def to_dict(self) -> dict:
        out = {"engine": self.engine, "version": self.version}
        if self.bindings:
            out["bindings"] = self.bindings
        out.update({"ok": self.ok, "error": self.error})
        return out


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
    import btclib

    hash_types: list[int] = []
    try:
        tx = Tx.parse(tx_bytes)
        outs = [TxOut(value, spk) for value, spk in prevouts]
        verify_transaction(outs, tx, flags, check_amounts=True, hash_types=hash_types)
    except (BTClibValueError, BTClibRuntimeError, ValueError, RuntimeError) as exc:
        return EngineRun(name, False, f"{type(exc).__name__}: {exc}", hash_types, version=btclib.__version__)
    except Exception as exc:  # noqa: BLE001 - fail closed: an interpreter crash is never a pass
        return EngineRun(name, False, f"engine crashed: {type(exc).__name__}: {exc}", hash_types, version=btclib.__version__)
    return EngineRun(name, True, None, hash_types, version=btclib.__version__)


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
    versions = engine_versions().get("kernel") or {}
    meta = {"version": versions.get("bitcoin-core"), "bindings": f"py-bitcoinkernel {versions.get('py-bitcoinkernel')}" if versions else None}
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
                return EngineRun("kernel", False, f"input {index}: script evaluation failed", **meta)
    except ScriptVerifyException as exc:
        return EngineRun("kernel", False, f"script verify status: {exc.status.name}", **meta)
    except Exception as exc:  # noqa: BLE001
        return EngineRun("kernel", False, f"{type(exc).__name__}: {exc}", **meta)
    return EngineRun("kernel", True, **meta)


def available_engines() -> list[str]:
    engines = ["btclib"]
    if kernel_available():
        engines.append("kernel")
    return engines


@functools.lru_cache(maxsize=1)
def kernel_core_version() -> str | None:
    """The Bitcoin Core version bundled in libbitcoinkernel (read once from the shared library)."""
    import re
    from pathlib import Path

    try:
        import pbk

        libs = list((Path(pbk.__file__).parent / "_libs").glob("libbitcoinkernel*"))
        for lib in libs:
            match = re.search(rb"v\d+\.\d+\.\d+(?:rc\d+)?(?:-[A-Za-z0-9]+)?", lib.read_bytes())
            if match:
                return match.group(0).decode()
    except Exception:  # noqa: BLE001
        return None
    return None


def engine_versions() -> dict:
    """Version per engine: ``{"btclib": "2026.9.10", "kernel": {"bitcoin-core": ..., "py-bitcoinkernel": ...}}``."""
    import importlib.metadata as metadata

    import btclib

    versions: dict = {"btclib": btclib.__version__}
    if kernel_available():
        try:
            pkg = metadata.version("py-bitcoinkernel")
        except metadata.PackageNotFoundError:
            pkg = None
        versions["kernel"] = {"bitcoin-core": kernel_core_version(), "py-bitcoinkernel": pkg}
    return versions


def engine_labels() -> dict[str, str]:
    """Short human-readable name with version per engine, for text output."""
    versions = engine_versions()
    labels = {"btclib": f"btclib {versions['btclib']}"}
    if "kernel" in versions:
        k = versions["kernel"]
        labels["kernel"] = f"Bitcoin Core kernel {k.get('bitcoin-core') or '?'} (py-bitcoinkernel {k.get('py-bitcoinkernel') or '?'})"
    return labels
