"""Deterministic test cosigners and signature-tampering helpers.

Shared by the test suite and by refcheck so that neither depends on the other.
The seed domains are fixed: changing them would change every address and
signature the documentation and reference corpus were generated with.
"""

from __future__ import annotations

import hashlib

from embit.bip32 import HDKey
from embit.transaction import SIGHASH

from ..psbt import BIP322PSBT

ORIGIN_PATH = "48h/0h/0h/2h"
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def master_key(label: str) -> HDKey:
    """The test wallet's cosigner master keys (labels A, B, C); never for real funds."""
    seed = hashlib.sha256(f"bip322ms-test-cosigner-{label}".encode()).digest()
    seed += hashlib.sha256(label.encode()).digest()
    return HDKey.from_seed(seed)


def key_expression(master: HDKey, private: bool = False, branches: str = "<0;1>") -> str:
    """``[fp/48h/0h/0h/2h]xpub_or_xprv/<0;1>/*`` for a master key."""
    account = master.derive("m/" + ORIGIN_PATH)
    key = account if private else account.to_public()
    return f"[{master.my_fingerprint.hex()}/{ORIGIN_PATH}]{key.to_base58()}/{branches}/*"


# ---- DER helpers for negative tests ---------------------------------------- #


def der_decode(der: bytes) -> tuple[int, int]:
    assert der[0] == 0x30 and der[2] == 0x02
    r_len = der[3]
    r = int.from_bytes(der[4 : 4 + r_len], "big")
    pos = 4 + r_len
    assert der[pos] == 0x02
    s_len = der[pos + 1]
    s = int.from_bytes(der[pos + 2 : pos + 2 + s_len], "big")
    return r, s


def _int_der(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return b"\x02" + bytes([len(raw)]) + raw


def der_encode(r: int, s: int) -> bytes:
    body = _int_der(r) + _int_der(s)
    return b"\x30" + bytes([len(body)]) + body


def high_s(sig_with_hashtype: bytes) -> bytes:
    """The same signature re-encoded with the high S value (consensus-valid, policy-invalid)."""
    r, s = der_decode(sig_with_hashtype[:-1])
    return der_encode(r, SECP256K1_N - s) + sig_with_hashtype[-1:]


def sign_with_sighash(psbt: BIP322PSBT, master: HDKey, sighash: int):
    """A signature by ``master`` for input 0 with an arbitrary sighash byte; returns (sig, pubkey)."""
    inp = psbt.inputs[0]
    for pub, der in inp.bip32_derivations.items():
        if der.fingerprint == master.my_fingerprint:
            key = master.derive(list(der.derivation))
            digest = psbt.sighash(0, sighash=sighash)
            return key.sign(digest).serialize() + bytes([sighash]), pub
    raise AssertionError("master not in PSBT derivations")


__all__ = ["ORIGIN_PATH", "SIGHASH", "der_decode", "der_encode", "high_s", "key_expression", "master_key", "sign_with_sighash"]
