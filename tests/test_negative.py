"""Verification must reject everything that is not a valid proof for (address, message)."""

import base64

import pytest
from embit.transaction import SIGHASH

from bip322.core import build_to_sign, build_to_spend, encode_full, encode_simple
from bip322.psbt import create_psbt, signature_from_psbt
from bip322.verify import State, verify_message
from tests.helpers import finalized_psbt, high_s, sign_with_sighash

MESSAGE = b"negative tests"


@pytest.fixture(scope="module")
def proof(wallet, signer_expressions):
    psbt = finalized_psbt(wallet, signer_expressions[:2], MESSAGE, index=4)
    derived = wallet.derive(4)
    witness = list(psbt.inputs[0].final_scriptwitness.items)
    return derived, witness, signature_from_psbt(psbt)


def test_baseline_valid(proof, kernel_engines):
    derived, _, sig = proof
    assert verify_message(derived.address, sig, MESSAGE, engines=kernel_engines).ok


def test_wrong_message(proof):
    derived, _, sig = proof
    r = verify_message(derived.address, sig, b"negative tests ")
    assert r.state is State.INVALID and "do not verify for this message" in r.reason


def test_wrong_address_same_wallet(proof, wallet):
    _, _, sig = proof
    r = verify_message(wallet.derive(5).address, sig, MESSAGE)
    assert r.state is State.INVALID


def test_wrong_network_encoding_is_fine(proof, wallet):
    from bip322.wallet import MultisigWallet

    derived, _, sig = proof
    regtest = MultisigWallet.from_descriptor(wallet.to_descriptor(), network="regtest").derive(4)
    assert verify_message(regtest.address, sig, MESSAGE).ok


def test_high_s_signature_is_invalid_by_policy_only(proof, kernel_engines):
    from bip322.engines import kernel_run

    derived, witness, _ = proof
    tampered = list(witness)
    tampered[1] = high_s(tampered[1])
    r = verify_message(derived.address, encode_simple(tampered), MESSAGE, engines=kernel_engines)
    assert r.state is State.INVALID and "high s" in r.reason.lower()
    if "kernel" in kernel_engines:
        # consensus alone accepts a high-S signature; BIP-322's required rules do not
        to_sign = build_to_sign(build_to_spend(MESSAGE, derived.script_pubkey).txid(), witness=tampered)
        assert kernel_run([(0, derived.script_pubkey)], to_sign.serialize()).ok


def test_swapped_signature_order(proof):
    derived, witness, _ = proof
    swapped = [witness[0], witness[2], witness[1], witness[3]]
    assert verify_message(derived.address, encode_simple(swapped), MESSAGE).state is State.INVALID


def test_non_empty_dummy_element(proof):
    derived, witness, _ = proof
    bad = [b"\x00"] + witness[1:]
    assert verify_message(derived.address, encode_simple(bad), MESSAGE).state is State.INVALID


def test_extra_witness_element(proof):
    derived, witness, _ = proof
    assert verify_message(derived.address, encode_simple([b""] + witness), MESSAGE).state is State.INVALID
    assert verify_message(derived.address, encode_simple(witness[1:]), MESSAGE).state is State.INVALID


def test_one_signature_only(proof):
    derived, witness, _ = proof
    assert verify_message(derived.address, encode_simple([witness[0], witness[1], witness[3]]), MESSAGE).state is State.INVALID


def test_sighash_none_is_rejected(wallet, masters):
    derived = wallet.derive(4)
    psbt = create_psbt(derived, MESSAGE)
    sigs = []
    for master in masters[:2]:
        sig, pub = sign_with_sighash(psbt, master, SIGHASH.NONE)
        sigs.append((pub.sec(), sig))
    ordered = [sig for pk in derived.pubkeys for sec, sig in sigs if sec == pk]
    witness = [b""] + ordered + [derived.witness_script]
    r = verify_message(derived.address, encode_simple(witness), MESSAGE)
    assert r.state is State.INVALID and "sighash" in r.reason.lower()
    assert set(r.sighash_types) == {2}


def test_unknown_prefix_and_junk(proof):
    derived, _, sig = proof
    assert verify_message(derived.address, "xyz" + sig[3:], MESSAGE).state is State.INVALID
    assert verify_message(derived.address, "pof" + sig[3:], MESSAGE).state is State.INVALID
    assert verify_message(derived.address, "ful" + sig[3:], MESSAGE).state is State.INVALID
    assert verify_message(derived.address, "", MESSAGE).state is State.INVALID
    assert verify_message(derived.address, "smp", MESSAGE).state is State.INVALID
    assert verify_message("not-an-address", sig, MESSAGE).state is State.INVALID


def test_unprefixed_fallback(proof):
    derived, _, sig = proof
    assert verify_message(derived.address, sig[3:], MESSAGE).ok
    assert verify_message(derived.address, sig[3:], MESSAGE, allow_unprefixed=False).state is State.INVALID


def test_full_variant_versions_and_locktime(wallet, signer_expressions):
    """Signatures commit to version/locktime/sequence, so each case is signed afresh."""
    address = wallet.derive(4).address
    psbt = finalized_psbt(wallet, signer_expressions[:2], MESSAGE, index=4, version=2)
    r = verify_message(address, signature_from_psbt(psbt), MESSAGE)
    assert r.ok and r.version == 2 and r.variant == "ful"
    psbt = finalized_psbt(wallet, signer_expressions[:2], MESSAGE, index=4, version=1)
    r = verify_message(address, signature_from_psbt(psbt, "ful"), MESSAGE)
    assert r.state is State.INCONCLUSIVE and "version 1" in r.reason
    psbt = finalized_psbt(wallet, signer_expressions[:2], MESSAGE, index=4, version=2, locktime=800000, sequence=10)
    r = verify_message(address, signature_from_psbt(psbt), MESSAGE)
    assert r.ok and r.locktime == 800000 and r.sequence == 10 and "800000" in r.reason
    # a witness made for version 0 must not verify inside a version 2 to_sign
    derived, witness = wallet.derive(4), list(finalized_psbt(wallet, signer_expressions[:2], MESSAGE, index=4).inputs[0].final_scriptwitness.items)
    txid = build_to_spend(MESSAGE, derived.script_pubkey).txid()
    assert verify_message(address, encode_full(build_to_sign(txid, witness=witness, version=2)), MESSAGE).state is State.INVALID


def test_full_variant_shape_errors(proof):
    derived, witness, _ = proof
    txid = build_to_spend(MESSAGE, derived.script_pubkey).txid()
    tx = build_to_sign(txid, witness=witness)
    tx.vout[0].value = 1
    assert verify_message(derived.address, encode_full(tx), MESSAGE).state is State.INVALID
    tx = build_to_sign(txid, witness=witness)
    tx.vout[0].script_pubkey.data = b"\x6a\x00"
    assert verify_message(derived.address, encode_full(tx), MESSAGE).state is State.INVALID
    tx = build_to_sign(bytes(32), witness=witness)
    assert "does not spend" in verify_message(derived.address, encode_full(tx), MESSAGE).reason
    tx = build_to_sign(txid, witness=witness)
    tx.vin.append(build_to_sign(txid, witness=witness).vin[0])
    assert "exactly one input" in verify_message(derived.address, encode_full(tx), MESSAGE).reason


def test_simple_variant_rejected_for_non_segwit(proof):
    _, witness, _ = proof
    r = verify_message("1BitcoinEaterAddressDontSendf59kuE", encode_simple(witness), MESSAGE)
    assert r.state is State.INVALID and "native segwit" in r.reason


def test_legacy_signature_only_for_p2pkh(proof):
    derived, _, _ = proof
    fake = base64.b64encode(b"\x1f" + b"\x11" * 64).decode()
    r = verify_message(derived.address, fake, MESSAGE)
    assert r.state is State.INVALID and "P2PKH" in r.reason
    r = verify_message("1BitcoinEaterAddressDontSendf59kuE", fake, MESSAGE)
    assert r.state is State.INVALID
    assert verify_message("1BitcoinEaterAddressDontSendf59kuE", fake, MESSAGE, allow_legacy=False).state is State.INVALID


def test_all_requested_engines_run_on_failure(proof, kernel_engines):
    derived, witness, sig = proof
    r = verify_message(derived.address, sig, b"some other message", engines=kernel_engines)
    assert r.state is State.INVALID
    assert [e.engine for e in r.engines] == ["btclib-required"] + (["kernel"] if "kernel" in kernel_engines else [])
    assert all(not e.ok for e in r.engines)
    if "kernel" in kernel_engines:
        tampered = list(witness)
        tampered[1] = high_s(tampered[1])
        r = verify_message(derived.address, encode_simple(tampered), MESSAGE, engines=kernel_engines)
        assert r.state is State.INVALID and "low-S" in r.reason
        by_name = {e.engine: e.ok for e in r.engines}
        assert by_name == {"btclib-required": False, "kernel": True}
