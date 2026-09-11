"""Shared helpers for tests: signing, tampering with DER signatures."""

from embit.transaction import SIGHASH

from bip322ms.psbt import BIP322PSBT, create_psbt, finalize_psbt, sign_psbt

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


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
    r, s = der_decode(sig_with_hashtype[:-1])
    return der_encode(r, SECP256K1_N - s) + sig_with_hashtype[-1:]


def signed_psbt(wallet, signers, message: bytes, index: int = 0, branch: int = 0, **kwargs) -> BIP322PSBT:
    derived = wallet.derive(index, branch)
    psbt = create_psbt(derived, message, xpubs=wallet.global_xpubs(), **kwargs)
    for signer in signers:
        assert sign_psbt(psbt, signer) == 1
    return psbt


def finalized_psbt(wallet, signers, message: bytes, index: int = 0, branch: int = 0, **kwargs) -> BIP322PSBT:
    return finalize_psbt(signed_psbt(wallet, signers, message, index, branch, **kwargs))


def sign_with_sighash(psbt: BIP322PSBT, master, sighash: int) -> bytes:
    """Produce a signature by ``master`` for input 0 with an arbitrary sighash byte."""
    inp = psbt.inputs[0]
    for pub, der in inp.bip32_derivations.items():
        if der.fingerprint == master.my_fingerprint:
            key = master.derive(list(der.derivation))
            digest = psbt.sighash(0, sighash=sighash)
            return key.sign(digest).serialize() + bytes([sighash]), pub
    raise AssertionError("master not in PSBT derivations")


__all__ = ["SIGHASH", "der_decode", "der_encode", "high_s", "signed_psbt", "finalized_psbt", "sign_with_sighash"]
