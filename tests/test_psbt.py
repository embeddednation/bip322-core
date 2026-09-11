import itertools

import pytest
from embit.finalizer import finalize_psbt as embit_finalize

from bip322ms.core import PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE, build_to_spend, encode_simple
from bip322ms.psbt import (
    BIP322PSBT,
    FinalizeError,
    choose_variant,
    combine_psbts,
    create_psbt,
    extract_tx,
    finalize_psbt,
    inspect_psbt,
    parse_psbt,
    sign_psbt,
    signature_from_psbt,
)
from bip322ms.verify import State, verify_message
from tests.helpers import finalized_psbt, signed_psbt

MESSAGE = b"Proof that the 2-of-3 quorum controls this address"


def test_create_psbt_fields(wallet):
    derived = wallet.derive(0)
    psbt = create_psbt(derived, MESSAGE, xpubs=wallet.global_xpubs())
    tx = psbt.tx
    assert tx.version == 0 and tx.locktime == 0
    assert len(tx.vin) == 1 and tx.vin[0].sequence == 0 and tx.vin[0].vout == 0
    assert tx.vin[0].txid == build_to_spend(MESSAGE, derived.script_pubkey).txid()
    assert len(tx.vout) == 1 and tx.vout[0].value == 0 and tx.vout[0].script_pubkey.data == b"\x6a"
    inp = psbt.inputs[0]
    assert inp.witness_utxo.value == 0 and inp.witness_utxo.script_pubkey.data == derived.script_pubkey
    assert inp.non_witness_utxo is None
    assert inp.witness_script.data == derived.witness_script
    assert len(inp.bip32_derivations) == 3 and inp.sighash_type == 1
    assert psbt.message == MESSAGE and psbt.unknown[PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE] == MESSAGE
    assert len(psbt.xpubs) == 3


def test_serialization_keeps_version_zero_and_sequence_zero(wallet):
    """embit's stock PSBT class silently rewrites version 0 -> 2 and sequence 0 -> 0xffffffff."""
    psbt = create_psbt(wallet.derive(0), MESSAGE)
    raw = psbt.serialize()
    again = parse_psbt(raw)
    assert again.tx.version == 0 and again.tx.vin[0].sequence == 0
    assert again.tx.txid() == psbt.tx.txid()
    assert again.message == MESSAGE
    assert parse_psbt(psbt.to_string()).serialize() == raw
    assert again.inputs[0].witness_script.data == psbt.inputs[0].witness_script.data
    assert len(again.inputs[0].bip32_derivations) == 3
    assert len(again.xpubs) == 0  # no xpubs requested


@pytest.mark.parametrize("utxo_mode", ["witness", "non_witness", "both"])
@pytest.mark.parametrize("psbt_version", [None, 2])
def test_inspect_accepts_our_psbt(wallet, utxo_mode, psbt_version):
    derived = wallet.derive(2, 1)
    psbt = create_psbt(derived, MESSAGE, utxo_mode=utxo_mode, psbt_version=psbt_version, xpubs=wallet.global_xpubs())
    again = parse_psbt(psbt.to_string())
    info = inspect_psbt(again)
    assert info.is_bip322, info.problems
    assert info.address == derived.address and info.message == MESSAGE
    assert info.threshold == 2 and len(info.pubkeys) == 3
    assert info.to_spend_txid == build_to_spend(MESSAGE, derived.script_pubkey).txid().hex()
    assert info.tx_version == 0 and info.sequence == 0 and info.locktime == 0


def test_inspect_flags_problems(wallet):
    psbt = create_psbt(wallet.derive(0), MESSAGE)
    psbt.message = b"a different message"
    info = inspect_psbt(psbt)
    assert not info.is_bip322 and any("to_spend" in p for p in info.problems)
    psbt = create_psbt(wallet.derive(0), MESSAGE)
    psbt.message = None
    assert not inspect_psbt(psbt).is_bip322
    psbt = create_psbt(wallet.derive(0), MESSAGE)
    psbt.inputs[0].witness_utxo = None
    assert "witness_utxo" in " ".join(inspect_psbt(psbt).problems)


def test_btclib_recognises_our_psbt_as_bip322(wallet):
    """Independent implementation of the BIP's *PSBT signer* detection rules."""
    from btclib.bip322 import assert_signed_message, signed_message
    from btclib.psbt import Psbt

    derived = wallet.derive(5)
    for utxo_mode in ("witness", "non_witness", "both"):
        ours = create_psbt(derived, MESSAGE, xpubs=wallet.global_xpubs(), utxo_mode=utxo_mode)
        theirs = Psbt.b64decode(ours.to_string())
        assert theirs.signed_message == MESSAGE
        assert signed_message(theirs) == MESSAGE
        assert_signed_message(theirs)
        assert theirs.tx.version == 0 and theirs.tx.vin[0].sequence == 0


@pytest.mark.parametrize("pair", list(itertools.combinations(range(3), 2)))
def test_two_of_three_roundtrip(wallet, signer_expressions, kernel_engines, pair):
    signers = [signer_expressions[i] for i in pair]
    psbt = finalized_psbt(wallet, signers, MESSAGE, index=1)
    inp = psbt.inputs[0]
    assert inp.final_scriptwitness is not None and len(inp.final_scriptwitness.items) == 4
    assert inp.final_scriptwitness.items[0] == b"" and inp.final_scriptwitness.items[-1] == wallet.derive(1).witness_script
    assert not inp.partial_sigs and inp.witness_script is None and not inp.bip32_derivations
    assert inp.witness_utxo is not None  # kept for pof / verification
    signature = signature_from_psbt(psbt)
    assert signature.startswith("smp")
    address = wallet.derive(1).address
    result = verify_message(address, signature, MESSAGE, engines=kernel_engines)
    assert result.state is State.VALID, result.reason
    assert set(result.sighash_types) == {1}
    assert {e.engine for e in result.engines} >= {"btclib-required", "btclib-upgradeable"}
    if "kernel" in kernel_engines:
        assert any(e.engine == "kernel" and e.ok for e in result.engines)
    # the same witness also verifies as ful and pof
    assert verify_message(address, signature_from_psbt(psbt, "ful"), MESSAGE).ok
    assert verify_message(address, signature_from_psbt(psbt, "pof"), MESSAGE).ok


def test_witness_matches_embit_finalizer_and_is_order_independent(wallet, signer_expressions):
    a = signed_psbt(wallet, [signer_expressions[0], signer_expressions[2]], MESSAGE)
    b = signed_psbt(wallet, [signer_expressions[2], signer_expressions[0]], MESSAGE)
    embit_tx = embit_finalize(parse_psbt(a.serialize()))
    ours_a = extract_tx(finalize_psbt(a))
    ours_b = extract_tx(finalize_psbt(b))
    assert ours_a.serialize() == ours_b.serialize() == embit_tx.serialize()


def test_three_signatures_use_first_two_in_script_order(wallet, signer_expressions):
    psbt = signed_psbt(wallet, signer_expressions, MESSAGE)
    assert len(psbt.inputs[0].partial_sigs) == 3
    sigs = {pub.sec(): sig for pub, sig in psbt.inputs[0].partial_sigs.items()}
    derived = wallet.derive(0)
    finalize_psbt(psbt)
    items = psbt.inputs[0].final_scriptwitness.items
    assert items[1:3] == [sigs[derived.pubkeys[0]], sigs[derived.pubkeys[1]]]
    assert verify_message(derived.address, signature_from_psbt(psbt), MESSAGE).ok


def test_combine_separately_signed_psbts(wallet, signer_expressions):
    unsigned = create_psbt(wallet.derive(0), MESSAGE, xpubs=wallet.global_xpubs())
    parts = []
    for signer in signer_expressions[:2]:
        part = parse_psbt(unsigned.to_string())
        assert sign_psbt(part, signer) == 1
        parts.append(parse_psbt(part.to_string()))
    combined = combine_psbts(parts)
    assert len(combined.inputs[0].partial_sigs) == 2
    assert combined.message == MESSAGE and len(combined.xpubs) == 3
    finalize_psbt(combined)
    sequential = finalized_psbt(wallet, signer_expressions[:2], MESSAGE)
    assert extract_tx(combined).serialize() == extract_tx(sequential).serialize()
    with pytest.raises(FinalizeError):
        signature_from_psbt(parse_psbt(unsigned.to_string()))


def test_not_enough_signatures(wallet, signer_expressions):
    psbt = signed_psbt(wallet, signer_expressions[:1], MESSAGE)
    with pytest.raises(FinalizeError, match="need 2 valid signatures"):
        finalize_psbt(psbt)


def test_foreign_key_adds_nothing(wallet):
    from tests.conftest import key_expression, master_key

    psbt = create_psbt(wallet.derive(0), MESSAGE)
    assert sign_psbt(psbt, key_expression(master_key("Z"), private=True)) == 0
    assert sign_psbt(psbt, master_key("Z").to_base58()) == 0


def test_master_xprv_signer(wallet, masters):
    psbt = create_psbt(wallet.derive(0), MESSAGE)
    assert sign_psbt(psbt, masters[0].to_base58()) == 1
    assert sign_psbt(psbt, masters[1]) == 1
    finalize_psbt(psbt)
    assert verify_message(wallet.derive(0).address, signature_from_psbt(psbt), MESSAGE).ok


def test_choose_variant(wallet, signer_expressions):
    psbt = finalized_psbt(wallet, signer_expressions[:2], MESSAGE)
    assert choose_variant(psbt) == "smp"
    psbt = finalized_psbt(wallet, signer_expressions[:2], MESSAGE, version=2)
    assert choose_variant(psbt) == "ful"
    with pytest.raises(FinalizeError):
        signature_from_psbt(psbt, "smp")
    assert verify_message(wallet.derive(0).address, signature_from_psbt(psbt), MESSAGE).ok


def test_tampered_partial_signature_is_rejected_at_finalize(wallet, signer_expressions):
    from tests.helpers import high_s

    psbt = signed_psbt(wallet, signer_expressions[:2], MESSAGE)
    inp = psbt.inputs[0]
    pub = next(iter(inp.partial_sigs))
    inp.partial_sigs[pub] = high_s(inp.partial_sigs[pub])
    with pytest.raises(FinalizeError, match="low-S"):
        finalize_psbt(psbt)
    psbt = signed_psbt(wallet, signer_expressions[:2], MESSAGE)
    inp = psbt.inputs[0]
    pub = next(iter(inp.partial_sigs))
    inp.partial_sigs[pub] = inp.partial_sigs[pub][:-1] + b"\x02"
    with pytest.raises(FinalizeError, match="SIGHASH_ALL"):
        finalize_psbt(psbt)
    psbt = signed_psbt(wallet, signer_expressions[:2], MESSAGE)
    other = signed_psbt(wallet, signer_expressions[:2], b"other message")
    for pub in list(psbt.inputs[0].partial_sigs):
        psbt.inputs[0].partial_sigs[pub] = other.inputs[0].partial_sigs[pub]
    with pytest.raises(FinalizeError, match="does not verify"):
        finalize_psbt(psbt)
