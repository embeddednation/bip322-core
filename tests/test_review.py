"""Checks added by the code review: canonical encodings, strict DER, PSBT field
consistency, engine selection errors, fail-closed engines, and CLI edge cases."""

import json

import pytest
from embit.script import Script
from embit.transaction import Transaction, TransactionOutput

from bip322.core import (
    SignatureFormatError,
    build_to_sign,
    build_to_spend,
    encode_full,
    encode_pof,
    encode_simple,
    is_native_segwit,
    parse_transaction,
    parse_witness,
    serialize_witness,
)
from bip322.dev.signing import sign_psbt
from bip322.engines import EngineError, btclib_run, BTCLIB_REQUIRED
from bip322.psbt import (
    BIP322PSBT,
    FinalizeError,
    PSBTBuildError,
    _der_r_s,
    combine_psbts,
    create_psbt,
    finalize_psbt,
    inspect_psbt,
    parse_psbt,
    psbt_prevouts,
    signature_from_psbt,
)
from bip322.verify import State, verify_message
from bip322.wallet import Wallet, WalletError
from tests.helpers import der_decode, der_encode, finalized_psbt, signed_psbt

MESSAGE = b"review tests"


@pytest.fixture(scope="module")
def proof(wallet, signer_expressions):
    psbt = finalized_psbt(wallet, signer_expressions[:2], MESSAGE, index=6)
    return wallet.derive(6), list(psbt.inputs[0].final_scriptwitness.items), psbt


# ---- canonical encodings --------------------------------------------------- #


def test_non_minimal_witness_length_is_rejected(proof):
    derived, witness, _ = proof
    raw = serialize_witness(witness)
    assert raw[0] == 4
    padded = b"\xfd\x04\x00" + raw[1:]  # same stack, 3-byte count
    with pytest.raises(SignatureFormatError, match="non-canonical"):
        parse_witness(padded)
    import base64

    r = verify_message(derived.address, "smp" + base64.b64encode(padded).decode(), MESSAGE)
    assert r.state is State.INVALID and "non-canonical" in r.reason


def test_non_canonical_transaction_is_rejected(proof):
    derived, witness, _ = proof
    tx = build_to_sign(build_to_spend(MESSAGE, derived.script_pubkey).txid(), witness=witness)
    raw = tx.serialize()
    assert raw[4:6] == b"\x00\x01" and raw[6] == 1
    padded = raw[:6] + b"\xfd\x01\x00" + raw[7:]  # vin count as 3-byte compact size
    with pytest.raises(SignatureFormatError, match="non-canonical"):
        parse_transaction(padded)
    import base64

    assert verify_message(derived.address, "ful" + base64.b64encode(padded).decode(), MESSAGE).state is State.INVALID
    # a segwit marker with only empty witnesses ("superfluous witness record")
    legacy = build_to_spend(MESSAGE, derived.script_pubkey).serialize()
    superfluous = legacy[:4] + b"\x00\x01" + legacy[4:-4] + b"\x00" + legacy[-4:]
    with pytest.raises(SignatureFormatError):
        parse_transaction(superfluous)


def test_is_native_segwit_program_lengths():
    assert not is_native_segwit(b"\x00\x15" + b"\x00" * 21)
    assert not is_native_segwit(b"\x00\x02" + b"\x00" * 2)
    assert is_native_segwit(b"\x51\x02" + b"\x00" * 2)
    assert not is_native_segwit(b"\x61\x20" + b"\x00" * 32)


# ---- strict DER in the finalizer ----------------------------------------- #


@pytest.mark.parametrize(
    "der",
    [b"", b"\x30", b"\x30\x05\x02\x01", b"\x30\x06\x02\x01\x01\x02\x01", b"\x30\x06\x02\x01\x01\x03\x01\x01",
     b"\x30\x06\x02\x01\x81\x02\x01\x01", b"\x30\x07\x02\x02\x00\x01\x02\x01\x01", b"\x30\x06\x02\x00\x02\x02\x01\x01"],
)
def test_der_parser_never_crashes_on_malformed_input(der):
    with pytest.raises(FinalizeError):
        _der_r_s(der)


def test_non_minimal_der_r_is_rejected(wallet, signer_expressions):
    psbt = signed_psbt(wallet, signer_expressions[:2], MESSAGE, index=6)
    inp = psbt.inputs[0]
    pub = next(iter(inp.partial_sigs))
    sig = inp.partial_sigs[pub]
    r, s = der_decode(sig[:-1])
    body = der_encode(r, s)
    # re-encode R with a superfluous leading zero byte
    len_r = body[3]
    padded = b"\x30" + bytes([body[1] + 1]) + b"\x02" + bytes([len_r + 1]) + b"\x00" + body[4 : 4 + len_r] + body[4 + len_r :]
    assert (padded[4 + 1] & 0x80) == 0  # so the zero is non-minimal
    inp.partial_sigs[pub] = padded + sig[-1:]
    with pytest.raises(FinalizeError, match="DER"):
        finalize_psbt(psbt)


# ---- PSBT field consistency ---------------------------------------------- #


def test_combine_refuses_conflicting_fields(wallet, signer_expressions):
    a = signed_psbt(wallet, signer_expressions[:1], MESSAGE, index=6)
    b = signed_psbt(wallet, signer_expressions[1:2], MESSAGE, index=6)
    b.inputs[0].sighash_type = 3
    with pytest.raises(PSBTBuildError, match="sighash_type differs"):
        combine_psbts([a, b])
    b = signed_psbt(wallet, signer_expressions[1:2], MESSAGE, index=6)
    b.inputs[0].witness_utxo = TransactionOutput(1, b.inputs[0].witness_utxo.script_pubkey)
    with pytest.raises(PSBTBuildError, match="witness_utxo differs"):
        combine_psbts([a, b])
    b = signed_psbt(wallet, signer_expressions[1:2], MESSAGE, index=6)
    b.inputs[0].witness_script = Script(b"\x51")
    with pytest.raises(PSBTBuildError, match="witness_script differs"):
        combine_psbts([a, b])
    good = combine_psbts([a, signed_psbt(wallet, signer_expressions[1:2], MESSAGE, index=6)])
    assert len(good.inputs[0].partial_sigs) == 2


def test_psbt_prevouts_cross_checks_utxo_fields(wallet, signer_expressions):
    derived = wallet.derive(6)
    to_spend = build_to_spend(MESSAGE, derived.script_pubkey)
    psbt = create_psbt(derived, MESSAGE, utxo_mode="both")
    assert psbt_prevouts(psbt) == [(0, derived.script_pubkey)]
    psbt.inputs[0].non_witness_utxo = build_to_spend(b"other", derived.script_pubkey)
    with pytest.raises(PSBTBuildError, match="not the transaction the input spends"):
        psbt_prevouts(psbt)
    psbt = create_psbt(derived, MESSAGE, utxo_mode="both")
    psbt.inputs[0].witness_utxo = TransactionOutput(5, Script(derived.script_pubkey))
    with pytest.raises(PSBTBuildError, match="disagree"):
        psbt_prevouts(psbt)
    psbt = create_psbt(derived, MESSAGE, utxo_mode="non_witness")
    psbt.inputs[0].vout = 3
    with pytest.raises(PSBTBuildError, match="beyond"):
        psbt_prevouts(psbt)
    # and through the verifier: a pof payload with a bad non_witness_utxo is INVALID, not a crash
    psbt = finalized_psbt(wallet, signer_expressions[:2], MESSAGE, index=6, utxo_mode="both")
    psbt.inputs[0].non_witness_utxo = build_to_spend(b"other", derived.script_pubkey)
    r = verify_message(derived.address, encode_pof(psbt.serialize()), MESSAGE)
    assert r.state is State.INVALID and "non_witness_utxo" in r.reason
    assert verify_message(derived.address, encode_pof(to_spend.serialize()), MESSAGE).state is State.INVALID


def test_pof_without_inputs_is_invalid(wallet):
    derived = wallet.derive(6)
    empty = BIP322PSBT(Transaction(version=0, vin=[], vout=[TransactionOutput(0, Script(b"\x6a"))]))
    # embit cannot even parse a zero-input PSBT (ambiguous with the segwit marker); either way: invalid, no crash
    r = verify_message(derived.address, encode_pof(empty.serialize()), MESSAGE)
    assert r.state is State.INVALID and r.variant == "pof"


def test_finalizer_keeps_unknown_input_fields(wallet, signer_expressions):
    psbt = signed_psbt(wallet, signer_expressions[:2], MESSAGE, index=6)
    psbt.inputs[0].unknown[b"\xfc\x04demo"] = b"kept"
    finalize_psbt(parse_psbt(psbt.to_string()))
    finalized = finalize_psbt(psbt)
    assert finalized.inputs[0].unknown[b"\xfc\x04demo"] == b"kept"
    again = parse_psbt(finalized.to_string())
    assert again.inputs[0].unknown[b"\xfc\x04demo"] == b"kept" and again.inputs[0].final_scriptwitness


def test_analyzepsbt_sighash_problems_and_signer_warnings(wallet, signer_expressions):
    derived = wallet.derive(6)
    psbt = create_psbt(derived, MESSAGE)
    psbt.inputs[0].sighash_type = 2
    info = inspect_psbt(psbt)
    assert not info.is_bip322 and any("SIGHASH_ALL" in p for p in info.problems)
    psbt = signed_psbt(wallet, signer_expressions[:1], MESSAGE, index=6)
    pub = next(iter(psbt.inputs[0].partial_sigs))
    psbt.inputs[0].partial_sigs[pub] = psbt.inputs[0].partial_sigs[pub][:-1] + b"\x02"
    assert any("SIGHASH_ALL" in p for p in inspect_psbt(psbt).problems)
    psbt = create_psbt(derived, MESSAGE)
    psbt.inputs[0].witness_script = None
    psbt.inputs[0].bip32_derivations.clear()
    info = inspect_psbt(psbt)
    assert info.is_bip322 and len(info.warnings) == 2
    assert any("witness_script" in w for w in info.warnings) and any("derivation" in w for w in info.warnings)
    assert inspect_psbt(create_psbt(derived, MESSAGE)).warnings == []


# ---- engines --------------------------------------------------------------- #


def test_engine_selection_errors(proof, monkeypatch):
    derived, _, psbt = proof
    sig = signature_from_psbt(psbt)
    with pytest.raises(EngineError, match="unknown engine"):
        verify_message(derived.address, sig, MESSAGE, engines=("btclib", "nope"))
    import bip322.engines as engines_module

    monkeypatch.setattr(engines_module, "kernel_available", lambda: False)
    with pytest.raises(EngineError, match="not installed"):
        verify_message(derived.address, sig, MESSAGE, engines=("btclib", "kernel"))
    assert verify_message(derived.address, sig, MESSAGE, engines=("btclib",)).ok


def test_engine_crash_fails_closed(proof, monkeypatch):
    derived, witness, _ = proof
    import bip322.engines as engines_module

    def boom(*args, **kwargs):
        raise AssertionError("interpreter bug")

    monkeypatch.setattr(engines_module, "verify_transaction", boom)
    tx = build_to_sign(build_to_spend(MESSAGE, derived.script_pubkey).txid(), witness=witness)
    run = btclib_run([(0, derived.script_pubkey)], tx.serialize(), BTCLIB_REQUIRED)
    assert not run.ok and "engine crashed" in run.error
    assert verify_message(derived.address, encode_simple(witness), MESSAGE, engines=("btclib",)).state is State.INVALID


# ---- wallet ---------------------------------------------------------------- #


def test_duplicate_xpub_is_rejected(masters):
    from tests.conftest import key_expression

    keys = [key_expression(masters[0]), key_expression(masters[1]), key_expression(masters[0])]
    with pytest.raises(WalletError, match="more than once"):
        Wallet.from_descriptor("wsh(sortedmulti(2," + ",".join(keys) + "))")


# ---- CLI ------------------------------------------------------------------- #


def test_cli_strict_coldcard_writes_nothing_and_missing_files_are_clean_errors(tmp_path, wallet, capsys):
    from bip322.cli import main

    cfg = tmp_path / "w.desc"
    cfg.write_text(wallet.to_descriptor() + "\n")
    out = tmp_path / "p.psbt"
    assert main(["-w", str(cfg), "createpsbt", "--index", "0", "-m", " leading space", "--strict-coldcard", "-o", str(out)]) == 2
    assert not out.exists() and "Coldcard" in capsys.readouterr().err
    assert main(["analyzepsbt", str(tmp_path / "missing.psbt")]) == 2
    err = capsys.readouterr().err
    assert err.startswith("error:") and "missing.psbt" in err and "Traceback" not in err
    assert main(["-w", str(tmp_path / "nope.desc"), "deriveaddresses"]) == 2
    assert "nope.desc" in capsys.readouterr().err
