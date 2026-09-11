import base64

import pytest

from bip322ms.core import (
    PREFIX_FULL,
    PREFIX_POF,
    PREFIX_SIMPLE,
    VARIANT_LEGACY,
    SignatureFormatError,
    build_to_sign,
    build_to_spend,
    decode_signature,
    encode_simple,
    is_native_segwit,
    message_hash,
    parse_witness,
    serialize_witness,
)
from bip322ms.verify import script_pubkey_from_address
from tests.conftest import load_vectors


def test_message_hash_and_txids_match_basic_vectors():
    vectors = load_vectors("basic-test-vectors.json")
    for v in vectors["tx_hashes"]:
        message = v["message"].encode("utf-8")
        spk = script_pubkey_from_address(v["address"])
        assert message_hash(message).hex() == v["message_hash"]
        to_spend = build_to_spend(message, spk)
        assert to_spend.txid().hex() == v["to_spend_tx_hash"]
        to_sign = build_to_sign(to_spend.txid())
        assert to_sign.txid().hex() == v["to_sign_tx_hash"]


def test_to_spend_layout():
    spk = bytes.fromhex("0014" + "11" * 20)
    tx = build_to_spend(b"hello", spk)
    assert tx.version == 0 and tx.locktime == 0
    assert len(tx.vin) == 1 and len(tx.vout) == 1
    assert tx.vin[0].txid == bytes(32) and tx.vin[0].vout == 0xFFFFFFFF and tx.vin[0].sequence == 0
    assert tx.vin[0].script_sig.data == b"\x00\x20" + message_hash(b"hello")
    assert tx.vout[0].value == 0 and tx.vout[0].script_pubkey.data == spk


def test_to_sign_layout():
    txid = bytes(range(32))
    tx = build_to_sign(txid, witness=[b"\x01\x02"], version=2, locktime=5, sequence=7)
    assert tx.version == 2 and tx.locktime == 5
    assert tx.vin[0].txid == txid and tx.vin[0].vout == 0 and tx.vin[0].sequence == 7
    assert tx.vin[0].witness.items == [b"\x01\x02"]
    assert tx.vout[0].value == 0 and tx.vout[0].script_pubkey.data == b"\x6a"


def test_witness_roundtrip_and_strictness():
    items = [b"", b"\x30\x44" + b"\x01" * 68, b"\x52" * 105]
    raw = serialize_witness(items)
    assert parse_witness(raw) == items
    with pytest.raises(SignatureFormatError):
        parse_witness(raw + b"\x00")
    with pytest.raises(SignatureFormatError):
        parse_witness(raw[:-1])
    assert parse_witness(b"\x00") == []


def test_decode_signature_prefixes():
    wit = encode_simple([b"\x01"])
    d = decode_signature(wit)
    assert d.variant == PREFIX_SIMPLE and d.prefixed and d.payload == b"\x01\x01\x01"
    body = wit[3:]
    d = decode_signature(body)
    assert d.variant == PREFIX_SIMPLE and not d.prefixed
    with pytest.raises(SignatureFormatError):
        decode_signature(body, allow_unprefixed=False)
    for prefix in (PREFIX_FULL, PREFIX_POF):
        assert decode_signature(prefix + body).variant == prefix
    legacy = base64.b64encode(b"\x1f" + b"\x00" * 64).decode()
    assert decode_signature(legacy).variant == VARIANT_LEGACY
    assert decode_signature("smp" + legacy).variant == PREFIX_SIMPLE


@pytest.mark.parametrize("bad", ["", "   ", "not-valid-base64!!!", "fooAA==", "smp", "smp!!!!", "AA=", "ful=="])
def test_decode_signature_rejects_garbage(bad):
    with pytest.raises(SignatureFormatError):
        decode_signature(bad)


def test_is_native_segwit():
    assert is_native_segwit(bytes.fromhex("0014" + "00" * 20))
    assert is_native_segwit(bytes.fromhex("0020" + "00" * 32))
    assert is_native_segwit(bytes.fromhex("5120" + "00" * 32))
    assert not is_native_segwit(bytes.fromhex("76a914" + "00" * 20 + "88ac"))
    assert not is_native_segwit(bytes.fromhex("a914" + "00" * 20 + "87"))
    assert not is_native_segwit(bytes.fromhex("0015" + "00" * 20))
