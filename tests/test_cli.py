import json

import pytest

from bip322.cli import main
from bip322.dev.cli import main as dev_main

MESSAGE = "cli roundtrip message"


def test_cli_roundtrip(tmp_path, wallet, signer_expressions, capsys):
    cfg = tmp_path / "wallet.desc"
    cfg.write_text(wallet.to_descriptor() + "\n")
    address = wallet.derive(3).address
    unsigned = tmp_path / "unsigned.psbt"
    assert main(["createpsbt", "-w", str(cfg), address, MESSAGE, "-o", str(unsigned)]) == 0
    assert unsigned.read_text().startswith("cHNidP8")
    assert main(["analyzepsbt", str(unsigned)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["is_bip322"] and out["address"] == address and out["message_utf8"] == MESSAGE
    parts = []
    for i, key in enumerate(signer_expressions[:2]):
        part = tmp_path / f"part{i}.psbt"
        assert dev_main(["signpsbt", str(unsigned), key, "-o", str(part)]) == 0
        parts.append(str(part))
    combined = tmp_path / "combined.psbt"
    assert main(["combinepsbt", *parts, "-o", str(combined)]) == 0
    sig_file = tmp_path / "sig.txt"
    assert main(["finalizepsbt", str(combined), "-o", str(sig_file)]) == 0
    assert capsys.readouterr().out == ""  # -o given: nothing on stdout
    signature = sig_file.read_text().strip()
    assert signature.startswith("smp")
    assert main(["finalizepsbt", str(combined), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["signature"] == signature and "self_verification" not in out
    assert main(["verifymessage", address, signature, MESSAGE]) == 0
    assert "VALID" in capsys.readouterr().out
    assert main(["verifymessage", address, signature, MESSAGE + "!"]) == 1
    assert "INVALID" in capsys.readouterr().out
    assert main(["verifymessage", address, signature, MESSAGE, "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["state"] == "valid"
    assert all(e["version"] for e in out["engines"])
    assert any(e["engine"] == "kernel" and e["bindings"].startswith("py-bitcoinkernel") for e in out["engines"]) or "kernel" not in out["engines"]


def test_cli_rejects_one_signature(tmp_path, wallet, descriptor_text, signer_expressions, capsys):
    unsigned = tmp_path / "u.psbt"
    assert main(["createpsbt", "-d", descriptor_text, wallet.derive(0).address, MESSAGE, "-o", str(unsigned)]) == 0
    part = tmp_path / "p.psbt"
    assert dev_main(["signpsbt", str(unsigned), signer_expressions[0], "-o", str(part)]) == 0
    assert main(["finalizepsbt", str(part)]) == 2
    assert "need 2 valid signatures" in capsys.readouterr().err


def test_cli_lint(capsys):
    assert main(["lint-message", "ok message"]) == 0
    assert main(["lint-message", " leading"]) == 1
    assert main(["lint-message", "x"]) == 1
    assert main(["lint-message", "a" * 331]) == 1
    assert main(["lint-message", "tab\tand\nnewline are fine"]) == 0


def test_cli_keygen_is_deterministic_and_usable(capsys, tmp_path):
    assert dev_main(["keygen", "--label", "A", "--seed", "demo cosigner A"]) == 0
    first = json.loads(capsys.readouterr().out)
    assert dev_main(["keygen", "--seed", "demo cosigner A"]) == 0
    second = json.loads(capsys.readouterr().out)
    assert first["xpub_expression"] == second["xpub_expression"]
    assert first["fingerprint"] == "ea34d476" and first["origin"] == "m/48h/0h/0h/2h"
    assert first["xprv_expression"].startswith("[ea34d476/48h/0h/0h/2h]xprv") and first["xprv_expression"].endswith("/<0;1>/*")
    from bip322.wallet import MultisigWallet

    keys = []
    for label in "ABC":
        assert dev_main(["keygen", "--seed", f"demo cosigner {label}"]) == 0
        keys.append(json.loads(capsys.readouterr().out)["xpub_expression"])
    wallet = MultisigWallet.from_descriptor("wsh(sortedmulti(2," + ",".join(keys) + "))")
    assert wallet.derive(0).address == "bc1qw7ysc083rxm7094nm68hhqa2zlvfqu92xzejuwqcvcfah6gavyrs3fucvy"
    assert dev_main(["keygen", "--network", "regtest", "--seed", "x"]) == 0
    assert json.loads(capsys.readouterr().out)["xpub_expression"].split("]")[1].startswith("tpub")


def test_cli_makewallet_and_sign_from_keygen_files(tmp_path, capsys):
    files = []
    for label in "ABC":
        assert dev_main(["keygen", "--seed", f"demo cosigner {label}"]) == 0
        f = tmp_path / f"cosigner-{label}.json"
        f.write_text(capsys.readouterr().out)
        files.append(str(f))
    wallet_file = tmp_path / "wallet.desc"
    assert dev_main(["makewallet", "-t", "2", *files, "--name", "demo", "-o", str(wallet_file)]) == 0
    text = wallet_file.read_text().strip()
    assert text.startswith("wsh(sortedmulti(2,[ea34d476/48h/0h/0h/2h]xpub") and text.endswith("#tqx5n4ds")
    info = json.loads(capsys.readouterr().err)
    assert info["first_address"] == "bc1qw7ysc083rxm7094nm68hhqa2zlvfqu92xzejuwqcvcfah6gavyrs3fucvy"
    from bip322.wallet import MultisigWallet

    assert MultisigWallet.from_descriptor(text).derive(0).address == info["first_address"]
    # a mix of inputs: JSON file, key expression, file holding a key expression
    expr = json.loads((tmp_path / "cosigner-B.json").read_text())["xpub_expression"]
    kfile = tmp_path / "c.key"
    kfile.write_text(json.loads((tmp_path / "cosigner-C.json").read_text())["xpub_expression"] + "\n")
    assert dev_main(["makewallet", "-t", "2", files[0], expr, str(kfile)]) == 0
    assert capsys.readouterr().out.strip() == text
    # duplicate cosigner and bad threshold are refused
    assert dev_main(["makewallet", "-t", "2", files[0], files[0], files[1]]) == 2
    assert dev_main(["makewallet", "-t", "4", *files]) == 2
    capsys.readouterr()
    # sign with -k pointing at the keygen JSON files, sequentially, then finalize
    address = info["first_address"]
    unsigned = tmp_path / "u.psbt"
    assert main(["createpsbt", "-w", str(wallet_file), address, MESSAGE, "-o", str(unsigned)]) == 0
    a = tmp_path / "a.psbt"
    ab = tmp_path / "ab.psbt"
    assert dev_main(["signpsbt", str(unsigned), files[0], "-o", str(a)]) == 0
    assert dev_main(["signpsbt", str(a), files[1], "-o", str(ab)]) == 0
    assert main(["finalizepsbt", str(ab)]) == 0
    sig = capsys.readouterr().out.strip().splitlines()[0]
    assert main(["verifymessage", address, sig, MESSAGE]) == 0


def test_cli_deriveaddresses_and_getaddressinfo(tmp_path, wallet, capsys):
    cfg = tmp_path / "wallet.desc"
    cfg.write_text(wallet.to_descriptor() + "\n")
    assert main(["deriveaddresses", "-w", str(cfg), "0", "2"]) == 0
    lines = capsys.readouterr().out.split()
    assert lines == [wallet.derive(i).address for i in range(3)]
    assert main(["deriveaddresses", "-w", str(cfg), "4", "--change", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows == [{"branch": 1, "index": 4, "address": wallet.derive(4, 1).address}]
    assert main(["deriveaddresses", "-w", str(cfg), "3", "1"]) == 2
    capsys.readouterr()
    target = wallet.derive(4, 1)
    assert main(["getaddressinfo", "-w", str(cfg), target.address]) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["ismine"] and info["branch"] == 1 and info["index"] == 4
    assert info["scriptPubKey"] == target.script_pubkey.hex() and info["hex"] == target.witness_script.hex()
    assert info["sigsrequired"] == 2 and info["pubkeys"] == [pk.hex() for pk in target.pubkeys]
    assert info["witness_program"] == target.script_pubkey[2:].hex() and info["script"] == "multisig"
    assert list(info["hdkeypaths"]) == info["pubkeys"] and all(v.endswith(":m/48h/0h/0h/2h/1/4") for v in info["hdkeypaths"].values())
    from embit.descriptor import Descriptor

    from bip322.wallet import MultisigWallet

    concrete = Descriptor.from_string(info["desc"].split("#")[0])
    assert concrete.address() == target.address
    assert MultisigWallet.from_descriptor(info["wallet_desc"]).derive(4, 1).address == target.address
    assert main(["getaddressinfo", "-w", str(cfg), wallet.derive(600).address, "--max-index", "10"]) == 1
    assert json.loads(capsys.readouterr().out)["ismine"] is False


def test_cli_wallet_options_before_subcommand(tmp_path, wallet, capsys):
    cfg = tmp_path / "wallet.desc"
    cfg.write_text(wallet.to_descriptor() + "\n")
    addr = wallet.derive(2).address
    assert main(["-w", str(cfg), "getaddressinfo", addr]) == 0
    assert json.loads(capsys.readouterr().out)["index"] == 2
    assert main(["-w", str(cfg), "deriveaddresses", "2"]) == 0
    assert capsys.readouterr().out.strip() == addr
    assert main(["-d", wallet.to_descriptor(), "--network", "regtest", "deriveaddresses", "2"]) == 0
    assert capsys.readouterr().out.strip().startswith("bcrt1q")
    # the subcommand position still works and wins when both are given
    other = tmp_path / "other.desc"
    other.write_text(wallet.to_descriptor() + "\n")
    assert main(["-w", str(tmp_path / "missing.desc"), "deriveaddresses", "-w", str(other), "2"]) == 0
    assert capsys.readouterr().out.strip() == addr
    assert main(["deriveaddresses", "2"]) == 2


def test_cli_verifymessage_positional_like_core(tmp_path, wallet, signer_expressions, capsys):
    from bip322.psbt import signature_from_psbt
    from tests.helpers import finalized_psbt

    psbt = finalized_psbt(wallet, signer_expressions[:2], b"positional form")
    address = wallet.derive(0).address
    sig = signature_from_psbt(psbt)
    assert main(["verifymessage", address, sig, "positional form"]) == 0
    assert "VALID" in capsys.readouterr().out
    assert main(["verifymessage", address, sig, "wrong"]) == 1
    capsys.readouterr()
    sig_file = tmp_path / "s.sig"
    sig_file.write_text(sig + "\n")
    assert main(["verifymessage", address, "positional form", "--signature-file", str(sig_file)]) == 0
    capsys.readouterr()
    with pytest.raises(SystemExit):  # the address is a required positional
        main(["verifymessage", "--signature-file", str(sig_file)])
    assert main(["verifymessage", address, sig]) == 2  # message missing


def test_cli_engines_reports_versions(capsys):
    assert main(["engines"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert "btclib" in out["engines"] and out["versions"]["btclib"][:4].isdigit()
    if "kernel" in out["engines"]:
        assert out["versions"]["kernel"]["bitcoin-core"].startswith("v") and out["versions"]["kernel"]["py-bitcoinkernel"]


def test_cli_p2wpkh_flow(tmp_path, capsys):
    assert dev_main(["keygen", "--seed", "single key", "--origin", "84h/0h/0h"]) == 0
    key_file = tmp_path / "k.json"
    key_file.write_text(capsys.readouterr().out)
    wallet_file = tmp_path / "w.desc"
    assert dev_main(["makewallet", "--wpkh", str(key_file), "-o", str(wallet_file)]) == 0
    capsys.readouterr()
    assert wallet_file.read_text().startswith("wpkh([")
    assert dev_main(["makewallet", "--wpkh", str(key_file), str(key_file)]) == 2
    assert dev_main(["makewallet", str(key_file)]) == 2
    capsys.readouterr()
    assert main(["-w", str(wallet_file), "deriveaddresses", "1"]) == 0
    address = capsys.readouterr().out.strip()
    assert address.startswith("bc1q") and len(address) == 42
    assert main(["-w", str(wallet_file), "getaddressinfo", address]) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["ismine"] and "pubkey" in info and "sigsrequired" not in info
    unsigned, signed = tmp_path / "u.psbt", tmp_path / "s.psbt"
    assert main(["-w", str(wallet_file), "createpsbt", address, MESSAGE, "-o", str(unsigned)]) == 0
    assert dev_main(["signpsbt", str(unsigned), str(key_file), "-o", str(signed)]) == 0
    assert main(["finalizepsbt", str(signed)]) == 0
    sig = capsys.readouterr().out.strip().splitlines()[0]
    assert main(["verifymessage", address, sig, MESSAGE]) == 0
    assert main(["verifymessage", address, sig, MESSAGE + "!"]) == 1


def test_cli_stdout_carries_only_the_artifact(tmp_path, wallet, signer_expressions, capsys):
    """Every producing command: artifact on stdout (so > works) or in -o with stdout empty; chatter on stderr."""
    cfg = tmp_path / "w.desc"
    cfg.write_text(wallet.to_descriptor() + "\n")
    address = wallet.derive(0).address
    assert main(["-w", str(cfg), "createpsbt", address, MESSAGE]) == 0
    out, err = capsys.readouterr()
    assert out.startswith("cHNidP8") and out.strip().count("\n") == 0 and "to_spend_txid" in err
    unsigned = tmp_path / "u.psbt"
    unsigned.write_text(out)
    assert main(["-w", str(cfg), "createpsbt", address, MESSAGE, "-o", str(tmp_path / "u2.psbt")]) == 0
    assert capsys.readouterr().out == ""
    assert dev_main(["signpsbt", str(unsigned), signer_expressions[0]]) == 0
    out, err = capsys.readouterr()
    assert out.startswith("cHNidP8") and "added 1 signature" in err
    a = tmp_path / "a.psbt"
    a.write_text(out)
    assert dev_main(["signpsbt", str(a), signer_expressions[1], "-o", str(tmp_path / "ab.psbt")]) == 0
    assert capsys.readouterr().out == ""
    assert main(["combinepsbt", str(a), str(tmp_path / "ab.psbt")]) == 0
    out, err = capsys.readouterr()
    assert out.startswith("cHNidP8") and "partial signature" in err
    ab = tmp_path / "ab2.psbt"
    ab.write_text(out)
    assert main(["finalizepsbt", str(ab)]) == 0
    out, err = capsys.readouterr()
    assert out.startswith("smp") and out.strip().count("\n") == 0 and err == ""
    assert main(["finalizepsbt", str(ab), "-o", str(tmp_path / "p.sig"), "--output-psbt", str(tmp_path / "final.psbt")]) == 0
    assert capsys.readouterr().out == "" and (tmp_path / "p.sig").read_text().strip() == out.strip()
    assert (tmp_path / "final.psbt").read_text().startswith("cHNidP8")
    assert dev_main(["keygen", "--seed", "x", "-o", str(tmp_path / "k.json")]) == 0
    assert capsys.readouterr().out == "" and json.loads((tmp_path / "k.json").read_text())["fingerprint"]
    assert dev_main(["makewallet", "--wpkh", str(tmp_path / "k.json")]) == 0
    out, err = capsys.readouterr()
    assert out.startswith("wpkh(") and "first_address" in err


def test_cli_help_command(capsys):
    assert main(["help"]) == 0
    out = capsys.readouterr().out
    assert "== Wallet ==" in out and "== PSBT ==" in out and "== Verification ==" in out
    assert 'createpsbt "address" ( "message" )' in out and 'verifymessage "address" ( "signature" "message" )' in out
    assert 'deriveaddresses ( "index" | "start" "end" )' in out
    assert 'combinepsbt "psbt"...' in out and "help <command>" in out
    assert main(["help", "verifymessage"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("verifymessage ") and "Arguments:" in out and "1. address" in out and "Options:" in out
    assert "--signature-file" in out and "Examples:" in out and "> bip322 verifymessage" in out
    assert main(["help", "nope"]) == 2
    assert "unknown command" in capsys.readouterr().err
    assert dev_main(["help"]) == 0
    out = capsys.readouterr().out
    assert 'signpsbt "psbt" "key"...' in out
    assert dev_main(["help", "signpsbt"]) == 0
    assert "> bip322-dev signpsbt" in capsys.readouterr().out


def test_cli_decodesignature(wallet, signer_expressions, capsys):
    from bip322.core import disassemble
    from bip322.psbt import signature_from_psbt
    from tests.helpers import finalized_psbt

    psbt = finalized_psbt(wallet, signer_expressions[:2], b"decode me", index=2)
    derived = wallet.derive(2)
    assert main(["decodesignature", signature_from_psbt(psbt)]) == 0
    out = json.loads(capsys.readouterr().out)
    roles = [w["role"] for w in out["witness"]]
    assert out["variant"] == "smp" and roles[0].startswith("empty") and roles[1:3] == ["ECDSA signature (DER + sighash byte)"] * 2
    assert out["witness"][1]["sighash"] == 1 and out["witness"][3]["role"] == "witness script"
    asm = out["witness"][3]["asm"]
    assert asm.startswith("OP_2 ") and asm.endswith(" OP_3 OP_CHECKMULTISIG") and all(pk.hex() in asm for pk in derived.pubkeys)
    assert disassemble(b"\x76\xa9\x14" + b"\x11" * 20 + b"\x88\xac") == "OP_DUP OP_HASH160 " + "11" * 20 + " OP_EQUALVERIFY OP_CHECKSIG"
    assert main(["decodesignature", signature_from_psbt(psbt, "ful")]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["variant"] == "ful" and out["to_sign"]["version"] == 0 and out["to_sign"]["outputs"] == [{"value": 0, "scriptPubKey": "6a"}]
    assert out["to_sign"]["inputs"][0]["witness"][3]["role"] == "witness script"
    assert main(["decodesignature", signature_from_psbt(psbt, "pof")]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["variant"] == "pof" and out["psbt"]["message_utf8"] == "decode me" and out["psbt"]["inputs"][0]["finalized"]
    assert main(["decodesignature", "smp!!"]) == 2
