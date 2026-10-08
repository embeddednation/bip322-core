"""Regression tests for the findings of the review before the first public release."""

import base64
import copy
import hashlib
import json
import os
import stat
import sys

import pytest
from embit.script import Script

from bip322core import cli
from bip322core.cli import main
from bip322core.core import SignatureFormatError, decode_address, encode_simple
from bip322core.dev.cli import main as dev_main
from bip322core.msglint import lint_message
from bip322core.psbt import FinalizeError, PSBTBuildError, combine_psbts, create_psbt, finalize_psbt, parse_psbt, signature_from_psbt
from bip322core.signers import check_signers
from bip322core.verify import State, _explain, verify_message
from bip322core.wallet import Wallet, WalletError
from tests.conftest import key_expression
from tests.helpers import der_decode, finalized_psbt, sign_with_sighash, signed_psbt

MESSAGE = b"release review"
P2WPKH_SPK = "0014751e76e8199196d454941c45d1b3a323f1433bd6"
P2WPKH_ADDR = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"


def rc_of(run, argv) -> int:
    """The exit code, whether returned or raised by argparse."""
    try:
        return run(argv)
    except SystemExit as exc:
        return exc.code


@pytest.fixture
def proof(wallet, signer_expressions):
    psbt = finalized_psbt(wallet, signer_expressions[:2], MESSAGE)
    return wallet.derive(0).address, signature_from_psbt(psbt), psbt


# ---- must fix ---------------------------------------------------------------- #


def test_ecdsa_sighash_zero_is_invalid(wallet, masters):
    """0x00 is SIGHASH_DEFAULT for Schnorr only; an ECDSA signature with it breaks a required rule (P2WSH and P2WPKH)."""
    derived = wallet.derive(0)
    psbt = create_psbt(derived, MESSAGE)
    sigs = dict(reversed(sign_with_sighash(psbt, m, 0)) for m in masters[:2])
    ordered = [sigs[pub] for pub in map(type(next(iter(sigs))).parse, derived.pubkeys) if pub in sigs]
    r = verify_message(derived.address, encode_simple([b"", *ordered, derived.witness_script]), MESSAGE)
    assert r.state is State.INVALID and "0x00" in r.reason and set(r.sighash_types) == {0}
    single = Wallet.from_descriptor(f"wpkh({key_expression(masters[0])})")
    derived = single.derive(0)
    sig, pub = sign_with_sighash(create_psbt(derived, MESSAGE), masters[0], 0)
    r = verify_message(derived.address, encode_simple([sig, pub.sec()]), MESSAGE)
    assert r.state is State.INVALID and "0x00" in r.reason


@pytest.mark.parametrize(
    "argv",
    [
        ["verifymessage", P2WPKH_ADDR, "AAAA", "-h"],
        ["verifymessage", P2WPKH_ADDR, "AAAA", "--help"],
        ["verifymessage", P2WPKH_ADDR, "-h", "message"],
        ["verifymessage", "-h"],
        ["verifymessage", P2WPKH_ADDR, "--signature-file", "x.sig", "--help"],
        ["createpsbt", P2WPKH_ADDR, "-hello"],
        ["createpsbt", P2WPKH_ADDR, "--help"],
        ["lint-message", "-h"],
        ["lint-message", "--help"],
    ],
)
def test_free_text_that_looks_like_help_never_exits_zero(argv, capsys):
    assert rc_of(main, argv) == 2
    captured = capsys.readouterr()
    assert captured.out == ""  # no help text where a verdict or a PSBT is expected
    assert "goes after --" in captured.err and "error:" in captured.err


def test_dash_leading_message_after_double_dash(proof, capsys):
    address, sig, _ = proof
    assert main(["verifymessage", address, sig, "--", "-h"]) == 1  # a real verdict: not the signed message
    assert main(["lint-message", "--", "-h"]) == 0 and "ok" in capsys.readouterr().out


def test_unexpected_input_is_a_one_line_error_and_exit_2(tmp_path, wallet, masters, signer_expressions, monkeypatch, capsys):
    binary = tmp_path / "binary"
    binary.write_bytes(b"\xff\xfe\x00\x80 not text")
    broken = tmp_path / "broken.json"
    broken.write_text('{"xprv_expression": ')
    no_utxo = signed_psbt(wallet, signer_expressions[:1], MESSAGE)
    no_utxo.inputs[0].witness_utxo = None
    (tmp_path / "no-utxo.psbt").write_bytes(no_utxo.serialize())
    short = create_psbt(wallet.derive(0), MESSAGE, utxo_mode="non_witness")
    short.inputs[0].vout = 5
    (tmp_path / "short.psbt").write_bytes(short.serialize())
    good = tmp_path / "good.psbt"
    good.write_text(create_psbt(wallet.derive(0), MESSAGE).to_string())
    seventeen = "wsh(sortedmulti(2," + ",".join(key_expression(masters[0]).replace("/2h]", f"/{i}h]") for i in range(17)) + "))"
    cases = [(main, ["verifymessage", P2WPKH_ADDR, "msg", "--signature-file", str(binary)]), (main, ["-w", str(binary), "wallet"])]
    for name in ("no-utxo.psbt", "short.psbt"):
        cases += [(main, [cmd, str(tmp_path / name)]) for cmd in ("analyzepsbt", "finalizepsbt", "checksigners", "combinepsbt")]
    cases += [
        (main, ["validateaddress", "6a6a6a6a"]),
        (main, ["validateaddress", "51024e73ff"]),
        (main, ["-d", seventeen, "deriveaddresses", "0"]),
        (dev_main, ["signpsbt", str(good), str(broken)]),
        (dev_main, ["signpsbt", str(good), str(binary)]),
        (dev_main, ["makewallet", "-t", "2", str(broken), str(broken)]),
    ]
    for run, argv in cases:
        rc = rc_of(run, argv)
        captured = capsys.readouterr()
        if argv[0] in ("analyzepsbt", "checksigners") and rc == 1:  # a report that names the problem is as good as an error
            assert "prevout" in captured.out or "witness_utxo" in captured.out, argv
            assert captured.err == "", argv
            continue
        if argv[0] == "combinepsbt" and rc == 0:  # the combiner passes a single file through; it gives no verdict
            assert "Traceback" not in captured.err
            continue
        assert rc == 2, (argv, captured)
        assert captured.err.startswith("error: ") and captured.err.count("\n") == 1 and "Traceback" not in captured.err, argv
    # last resort: an exception nobody planned for is never exit 1 ("invalid")
    monkeypatch.setattr(cli, "cmd_engines", lambda args: 1 / 0)
    assert main(["engines"]) == 2 and "error: unexpected ZeroDivisionError" in capsys.readouterr().err
    monkeypatch.setattr("bip322core.dev.cli.cmd_keygen", lambda args: 1 / 0)
    assert dev_main(["keygen"]) == 2 and "error: unexpected ZeroDivisionError" in capsys.readouterr().err


def test_extension_that_cannot_run_is_an_error(tmp_path, monkeypatch, capsys):
    (tmp_path / "bip322-broken").write_bytes(b"\x00not a program")
    (tmp_path / "bip322-broken").chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    assert main(["broken"]) == 2
    assert capsys.readouterr().err.startswith("error: cannot run extension")


def test_dev_keys_are_regtest_and_seeded_mainnet_is_refused(tmp_path, capsys):
    assert dev_main(["keygen", "--seed", "demo cosigner A"]) == 0
    captured = capsys.readouterr()
    seeded = json.loads(captured.out)
    assert seeded["xprv_expression"].split("]")[1].startswith("tprv") and seeded["deterministic"] is True
    assert "seed text" in seeded["warning"] and "note:" in captured.err
    assert dev_main(["keygen", "--seed", "demo cosigner A", "--network", "main"]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "--seed with --network main is refused" in captured.err
    assert dev_main(["keygen", "--network", "main"]) == 0  # random mainnet keys are the user's own business
    random_key = json.loads(capsys.readouterr().out)
    assert random_key["deterministic"] is False and "seed text" not in random_key["warning"]
    assert random_key["xprv_expression"].split("]")[1].startswith("xprv")
    assert dev_main(["makewallet", "--wpkh", seeded["xpub_expression"]]) == 0
    assert json.loads(capsys.readouterr().err)["first_address"].startswith("bcrt1q")
    key_file = tmp_path / "key.json"
    key_file.write_text("old")
    key_file.chmod(0o664)
    assert dev_main(["keygen", "-o", str(key_file)]) == 0
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600 and json.loads(key_file.read_text())["fingerprint"]


def test_validateaddress_honours_the_global_network(capsys):
    assert main(["--network", "regtest", "validateaddress", P2WPKH_SPK, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["address"].startswith("bcrt1q")
    assert main(["validateaddress", P2WPKH_SPK, "--network", "test", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["address"].startswith("tb1q")


# ---- verifier and wallet ----------------------------------------------------- #


def test_size_and_input_limits(proof, wallet, signer_expressions):
    address, sig, psbt = proof
    r = verify_message(address, "smp" + "A" * 200_000, MESSAGE)
    assert r.state is State.INVALID and "max_signature_bytes" in r.reason and len(r.signature) < 100
    assert verify_message(address, sig, MESSAGE, max_signature_bytes=len(sig)).ok
    assert "max_signature_bytes" in verify_message(address, sig, MESSAGE, max_signature_bytes=len(sig) - 1).reason
    pof = signature_from_psbt(psbt, "pof")
    assert verify_message(address, pof, MESSAGE, max_inputs=1).ok
    r = verify_message(address, pof, MESSAGE, max_inputs=0)
    assert r.state is State.INVALID and "max_inputs" in r.reason


def test_strict_address_decoder():
    assert decode_address(P2WPKH_ADDR.upper()).hex() == P2WPKH_SPK  # BIP-173: upper case is valid
    assert decode_address("bc1pfeessrawgf").hex() == "51024e73"  # P2A: a short v1 program
    v2 = decode_address("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs")  # BIP-350 vector, witness v2
    assert v2.hex() == "5210751e76e8199196d454941c45d1b3a323"
    bad = [
        "ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9",  # another coin's prefix
        P2WPKH_ADDR[:10] + P2WPKH_ADDR[10:].upper(),  # mixed case
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",  # v0 with a bech32m checksum
        "notanaddress",
        "LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXpGc1",  # base58 version byte of another coin
        base58_address(b"\x00" + bytes(21)),  # 21 payload bytes
        base58_address(b"\x00" + bytes(5)),
    ]
    for address in bad:
        with pytest.raises(SignatureFormatError, match="not a Bitcoin network" if address.startswith("ltc1") else "invalid address"):
            decode_address(address)
        assert verify_message(address, "smpAA==", b"x").state is State.INVALID  # the library never raises for it


def base58_address(payload: bytes) -> str:
    from embit import base58

    return base58.encode_check(payload)


def test_future_witness_version_same_verdict_as_address_or_script():
    address = "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs"
    as_address = verify_message(address, encode_simple([b"\x01"]), b"x")
    as_script = verify_message(decode_address(address).hex(), encode_simple([b"\x01"]), b"x")
    assert as_address.state is as_script.state is State.INCONCLUSIVE


def test_undecodable_address_is_exit_2_on_the_command_line(proof, capsys):
    address, sig, _ = proof
    assert main(["verifymessage", "notanaddress", sig, "x"]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "invalid address" in captured.err
    assert main(["verifymessage", address.upper(), sig, MESSAGE.decode()]) == 0


def test_explanations_match_whole_words():
    r = verify_message(P2WPKH_ADDR, "smpAA==", b"x")
    assert "witness is missing elements" in r.reason and "DER" not in r.reason.split("(")[0]
    assert _explain("ScriptError: stack underflow") == "the witness is missing elements"
    assert _explain("invalid DER encoding") == "a signature is not strictly DER encoded"
    assert _explain("non-empty dummy") == "the CHECKMULTISIG dummy element is not empty"
    assert _explain("something else") == "script verification failed"


def test_unprefixed_65_byte_witness_is_not_a_legacy_signature():
    script = b"\x51" + b"\x61" * 62  # OP_1 and 62 OP_NOP: a 63-byte item serializes to a 65-byte stack
    spk = (b"\x00\x20" + hashlib.sha256(script).digest()).hex()
    prefixed = encode_simple([script])
    assert len(base64.b64decode(prefixed[3:])) == 65
    assert verify_message(spk, prefixed[3:], b"x").state is verify_message(spk, prefixed, b"x").state is State.VALID
    r = verify_message(spk, base64.b64encode(bytes([31]) + bytes(64)).decode(), b"x")  # a legacy signature's shape
    assert r.state is State.INVALID and "only valid for P2PKH" in r.reason


def test_one_spelling_per_proof(proof):
    address, sig, psbt = proof
    assert base64.b64decode("AB==") == base64.b64decode("AA==")
    assert "non-canonical base64" in verify_message(P2WPKH_ADDR, "smpAB==", b"x").reason
    pof = signature_from_psbt(psbt, "pof")
    assert verify_message(address, pof, MESSAGE).ok
    double = "pof" + base64.b64encode(pof[3:].encode()).decode()
    r = verify_message(address, double, MESSAGE)
    assert r.state is State.INVALID and "not a binary PSBT" in r.reason


def test_legacy_bip137_signatures_verify():
    """The positive path: Bitcoin Core's vector, then an uncompressed key and a testnet address."""
    core = (
        "15CRxFdyRpGZLW9w8HnHvVduizdL5jKNbs",
        "IPojfrX2dfPnH26UegfbGQQLrdK844DlHq5157/P6h57WyuS/Qsl+h/WSVGDF4MUi4rWSswW38oimDYfNNUBUOk=",
    )
    r = verify_message(core[0], core[1], b"Trust no one")
    assert r.state is State.VALID and r.variant == "legacy"
    assert verify_message(core[0], core[1], b"Trust no one ").state is State.INVALID
    assert verify_message(core[0], core[1], b"Trust no one", allow_legacy=False).state is State.INVALID
    from embit import ec
    from embit.networks import NETWORKS
    from embit.script import p2pkh

    for compressed, network in ((False, "main"), (True, "test"), (False, "test")):
        key = ec.PrivateKey(hashlib.sha256(b"legacy test key").digest(), compressed=compressed, network=NETWORKS[network])
        address = p2pkh(key.get_public_key()).address(NETWORKS[network])
        text = b"\x18Bitcoin Signed Message:\n" + bytes([14]) + b"legacy message"
        r, s = der_decode(key.sign(hashlib.sha256(hashlib.sha256(text).digest()).digest()).serialize())
        body = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        sigs = [base64.b64encode(bytes([27 + recid + (0 if not compressed else 4)]) + body).decode() for recid in range(4)]
        states = [verify_message(address, sig, b"legacy message").state for sig in sigs]
        assert states.count(State.VALID) == 1, (compressed, network)  # one header byte recovers the key, the others do not
        good = sigs[states.index(State.VALID)]
        assert verify_message(address, good, b"another message").state is State.INVALID


def test_check_signers_with_a_shared_fingerprint(masters):
    fp = masters[0].my_fingerprint.hex()
    same_fp = [key_expression(masters[0]), f"[{fp}" + key_expression(masters[1])[9:]]
    wallet = Wallet.from_descriptor("wsh(sortedmulti(2," + ",".join(same_fp) + "))")
    psbt = create_psbt(wallet.derive(0), MESSAGE)
    inp = psbt.inputs[0]
    for pub, derivation in inp.bip32_derivations.items():  # by key: the fingerprint no longer says whose it is
        for master in masters[:2]:
            child = master.derive(list(derivation.derivation))
            if child.sec() == pub.sec():
                inp.partial_sigs[pub] = child.sign(psbt.sighash(0)).serialize() + b"\x01"
    assert len(inp.partial_sigs) == 2
    report = check_signers(psbt)
    assert report["ok"] and report["summary"]["combinations_valid"] == "1/1", report["combinations"]


def test_finalizer_refuses_a_redeem_script(wallet, signer_expressions):
    psbt = signed_psbt(wallet, signer_expressions[:2], MESSAGE)
    psbt.inputs[0].redeem_script = Script(wallet.derive(0).script_pubkey)
    with pytest.raises(FinalizeError, match="redeem_script"):
        finalize_psbt(psbt)


def test_strict_finalization_does_not_depend_on_key_order(wallet, signer_expressions):
    address = wallet.derive(0).address
    for position in range(3):
        psbt = signed_psbt(wallet, signer_expressions, MESSAGE)
        pub = psbt.inputs[0].witness_script and list(psbt.inputs[0].partial_sigs)[0]
        ordered = [p for p in map(type(pub).parse, wallet.derive(0).pubkeys)]
        sig = bytearray(psbt.inputs[0].partial_sigs[ordered[position]])
        sig[10] ^= 1
        psbt.inputs[0].partial_sigs[ordered[position]] = bytes(sig)
        with pytest.raises(FinalizeError, match="does not verify"):
            finalize_psbt(copy.deepcopy(psbt))
        lenient = finalize_psbt(copy.deepcopy(psbt), strict=False)
        assert verify_message(address, signature_from_psbt(lenient), MESSAGE).ok


def test_combine_psbts_conflicts(wallet, signer_expressions):
    signed = signed_psbt(wallet, signer_expressions[:2], MESSAGE)
    garbage = copy.deepcopy(signed)
    pub = next(iter(garbage.inputs[0].partial_sigs))
    bad = bytearray(garbage.inputs[0].partial_sigs[pub])
    bad[10] ^= 1
    garbage.inputs[0].partial_sigs[pub] = bytes(bad)
    for order in ([signed, garbage], [garbage, signed]):  # the valid signature wins wherever it stands
        assert combine_psbts(order).inputs[0].partial_sigs[pub] == signed.inputs[0].partial_sigs[pub]
    with pytest.raises(PSBTBuildError, match="none of them valid"):
        combine_psbts(
            [garbage, parse_psbt(garbage.serialize().replace(bytes(bad), bytes(bad[:10]) + bytes([bad[10] ^ 3]) + bytes(bad[11:])))]
        )
    unsigned = create_psbt(wallet.derive(0), MESSAGE)
    with pytest.raises(PSBTBuildError, match="finalized in one"):
        combine_psbts([unsigned, finalize_psbt(copy.deepcopy(signed))])
    with pytest.raises(PSBTBuildError, match="different versions"):
        combine_psbts([unsigned, create_psbt(wallet.derive(0), MESSAGE, psbt_version=2)])
    dropped = copy.deepcopy(signed)
    dropped.message = None  # a signer that does not copy unknown global fields
    assert combine_psbts([unsigned, dropped]).message == MESSAGE and combine_psbts([dropped, unsigned]).message == MESSAGE
    with pytest.raises(PSBTBuildError, match="different"):
        combine_psbts([unsigned, create_psbt(wallet.derive(0), b"another message")])


def test_wallet_refuses_private_keys_fixed_paths_and_unknown_versions(masters):
    with pytest.raises(WalletError, match="private key"):
        Wallet.from_descriptor(f"wpkh({key_expression(masters[0], private=True)})")
    with pytest.raises(WalletError, match="wildcard"):
        Wallet.from_descriptor(f"wpkh({key_expression(masters[0]).replace('/<0;1>/*', '/0/5')})")
    with pytest.raises(WalletError, match="at most 16"):
        Wallet.from_descriptor(
            "wsh(sortedmulti(2," + ",".join(key_expression(masters[0]).replace("/2h]", f"/{i}h]") for i in range(17)) + "))"
        )
    from types import SimpleNamespace

    from bip322core.wallet import _network_from_keys

    with pytest.raises(WalletError, match="unknown version"):  # used to mean "main"
        _network_from_keys([SimpleNamespace(xpub=SimpleNamespace(version=b"\x01\x02\x03\x04"))])


def test_origin_without_a_path_has_no_slash(masters):
    fp = masters[0].my_fingerprint.hex()
    wallet = Wallet.from_descriptor(f"wpkh([{fp}]{masters[0].to_public().to_base58()}/<0;1>/*)")
    assert f"wpkh([{fp}]xpub" in wallet.to_descriptor() and "/]" not in "".join(wallet.core_descriptors())
    from bip322core.wallet import path_from_str

    with pytest.raises(WalletError):
        path_from_str("m/4²")


def test_lint_flags_leading_and_trailing_newline_or_tab():
    assert lint_message(b"\nlead") == ["leading newline or tab"]
    assert lint_message(b"trail\t") == lint_message(b"trail\n") == ["trailing newline or tab"]
    assert lint_message(b"two\nlines\tok") == []


# ---- command line ------------------------------------------------------------ #


def test_options_between_positionals(tmp_path, proof, wallet, capsys):
    address, sig, _ = proof
    assert main(["verifymessage", address, "--json", sig, MESSAGE.decode()]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "valid"
    assert main(["verifymessage", "--no-legacy", address, sig, "--require-prefix", MESSAGE.decode()]) == 0
    out = tmp_path / "out.psbt"
    assert main(["-d", wallet.to_descriptor(), "createpsbt", address, "-o", str(out), "--", "-dash message"]) == 0
    assert parse_psbt(out.read_bytes()).message == b"-dash message"
    msg = tmp_path / "msg.txt"
    msg.write_bytes(MESSAGE)
    assert main(["verifymessage", address, "--message-file", str(msg), sig]) == 0
    assert main(["lint-message", "--message-file", str(msg)]) == 0
    assert rc_of(main, ["verifymessage", address, sig, "extra", "--message-file", str(msg)]) == 2


def test_extensions_listed_are_the_ones_dispatched_and_never_from_the_current_directory(tmp_path, monkeypatch, capsys):
    bindir = tmp_path / "bin"
    (bindir / "bip322-adir").mkdir(parents=True)
    for name in ("bip322-foo.bak", "bip322-we ird", "bip322-ok"):
        (bindir / name).write_text("#!/bin/sh\n")
        (bindir / name).chmod(0o755)
    monkeypatch.setenv("PATH", str(bindir))
    monkeypatch.setattr(sys, "argv", [str(tmp_path / "elsewhere" / "bip322")])
    assert cli.list_extensions("bip322") == ["ok"]
    assert all(cli.extension_path("bip322", name) is None for name in ("adir", "foo.bak", "we ird"))
    # a program name that is not a path, and relative PATH entries, would mean the current directory
    monkeypatch.chdir(bindir)
    for argv0, path in (("-c", "/nonexistent"), ("bip322", ""), ("", os.pathsep.join([".", "", "/nonexistent"]))):
        monkeypatch.setattr(sys, "argv", [argv0])
        monkeypatch.setenv("PATH", path)
        assert cli.extension_path("bip322", "ok") is None and cli.list_extensions("bip322") == []
        assert main(["ok"]) == 2
        assert "bip322: 'ok' is not a bip322 command. See 'bip322 help'." in capsys.readouterr().err


def test_binary_needs_a_file(tmp_path, wallet, signer_expressions, capsys):
    address = wallet.derive(0).address
    assert main(["-d", wallet.to_descriptor(), "createpsbt", address, "msg", "--binary"]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "--binary needs a file" in captured.err
    signed = tmp_path / "signed.psbt"
    signed.write_bytes(signed_psbt(wallet, signer_expressions[:2], MESSAGE).serialize())
    assert main(["finalizepsbt", str(signed), "--binary"]) == 2 and "--output-psbt" in capsys.readouterr().err
    assert main(["finalizepsbt", str(signed), "--binary", "--output-psbt", str(tmp_path / "final.psbt")]) == 0
    assert (tmp_path / "final.psbt").read_bytes().startswith(b"psbt\xff")


def test_help_texts_say_what_the_command_does(capsys):
    assert main(["help", "verifymessage"]) == 0
    out = capsys.readouterr().out
    assert "2. signature    (required) the signature string" in out and "3. message      (required) the message text" in out
    assert "after --" in out
    assert main(["help", "wallet"]) == 0
    out = capsys.readouterr().out
    assert "default: main" not in out and "from the key versions" in out


def test_engines_are_checked_first_and_trimmed(tmp_path, proof, wallet, signer_expressions, capsys):
    address, sig, _ = proof
    one = tmp_path / "one.psbt"
    one.write_bytes(signed_psbt(wallet, signer_expressions[:1], MESSAGE).serialize())
    assert main(["checksigners", str(one), "--engines", "nosuch"]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "unknown engine" in captured.err
    assert main(["verifymessage", "notanaddress", sig, "x", "--engines", "nosuch"]) == 2 and "unknown engine" in capsys.readouterr().err
    assert main(["verifymessage", address, sig, MESSAGE.decode(), "--engines", " btclib , "]) == 0


def test_message_file_with_a_trailing_newline_is_noted(tmp_path, capsys):
    msg = tmp_path / "msg.txt"
    msg.write_bytes(b"demo proof\n")
    assert main(["lint-message", "--message-file", str(msg)]) == 1
    captured = capsys.readouterr()
    assert "ends with a newline; the message is all 11 bytes" in captured.err and "trailing newline" in captured.out
    msg.write_bytes(b"demo proof")
    assert main(["lint-message", "--message-file", str(msg)]) == 0 and capsys.readouterr().err == ""


def test_refcheck_corpus_has_the_ecdsa_sighash_zero_case():
    from refcheck.corpus import Fixture, build_corpus

    case = next(c for c in build_corpus(Fixture()) if c.id == "bad-sighash-zero-ecdsa")
    assert case.kind == "invalid" and verify_message(case.address_main, case.signature, case.message).state is State.INVALID
