import json

from bip322.cli import main

MESSAGE = "cli roundtrip message"


def test_cli_roundtrip(tmp_path, wallet, signer_expressions, capsys):
    cfg = tmp_path / "wallet.desc"
    cfg.write_text(wallet.to_descriptor() + "\n")
    address = wallet.derive(3).address
    unsigned = tmp_path / "unsigned.psbt"
    assert main(["createpsbt", "-w", str(cfg), "-a", address, "-m", MESSAGE, "-o", str(unsigned)]) == 0
    assert unsigned.read_text().startswith("cHNidP8")
    assert main(["analyzepsbt", str(unsigned)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["is_bip322"] and out["address"] == address and out["message_utf8"] == MESSAGE
    parts = []
    for i, key in enumerate(signer_expressions[:2]):
        part = tmp_path / f"part{i}.psbt"
        assert main(["signpsbt", str(unsigned), "-k", key, "-o", str(part)]) == 0
        parts.append(str(part))
    combined = tmp_path / "combined.psbt"
    assert main(["combinepsbt", *parts, "-o", str(combined)]) == 0
    sig_file = tmp_path / "sig.txt"
    assert main(["finalizepsbt", str(combined), "--signature-file", str(sig_file), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    signature = sig_file.read_text().strip()
    assert out["signature"] == signature and signature.startswith("smp") and "self_verification" not in out
    assert main(["verifymessage", "-a", address, "-s", signature, "-m", MESSAGE]) == 0
    assert "VALID" in capsys.readouterr().out
    assert main(["verifymessage", "-a", address, "-s", signature, "-m", MESSAGE + "!"]) == 1
    assert "INVALID" in capsys.readouterr().out
    assert main(["verifymessage", "-a", address, "-s", signature, "-m", MESSAGE, "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["state"] == "valid"
    assert all(e["version"] for e in out["engines"])
    assert any(e["engine"] == "kernel" and e["bindings"].startswith("py-bitcoinkernel") for e in out["engines"]) or "kernel" not in out["engines"]


def test_cli_rejects_one_signature(tmp_path, wallet, descriptor_text, signer_expressions, capsys):
    unsigned = tmp_path / "u.psbt"
    assert main(["createpsbt", "-d", descriptor_text, "--index", "0", "-m", MESSAGE, "-o", str(unsigned)]) == 0
    part = tmp_path / "p.psbt"
    assert main(["signpsbt", str(unsigned), "-k", signer_expressions[0], "-o", str(part)]) == 0
    assert main(["finalizepsbt", str(part)]) == 2
    assert "need 2 valid signatures" in capsys.readouterr().err


def test_cli_lint(capsys):
    assert main(["lint-message", "-m", "ok message"]) == 0
    assert main(["lint-message", "-m", " leading"]) == 1
    assert main(["lint-message", "-m", "x"]) == 1
    assert main(["lint-message", "-m", "a" * 331]) == 1
    assert main(["lint-message", "-m", "tab\tand\nnewline are fine"]) == 0


def test_cli_keygen_is_deterministic_and_usable(capsys, tmp_path):
    assert main(["keygen", "--label", "A", "--seed", "demo cosigner A"]) == 0
    first = json.loads(capsys.readouterr().out)
    assert main(["keygen", "--seed", "demo cosigner A"]) == 0
    second = json.loads(capsys.readouterr().out)
    assert first["xpub_expression"] == second["xpub_expression"]
    assert first["fingerprint"] == "ea34d476" and first["origin"] == "m/48h/0h/0h/2h"
    assert first["xprv_expression"].startswith("[ea34d476/48h/0h/0h/2h]xprv") and first["xprv_expression"].endswith("/<0;1>/*")
    from bip322.wallet import MultisigWallet

    keys = []
    for label in "ABC":
        assert main(["keygen", "--seed", f"demo cosigner {label}"]) == 0
        keys.append(json.loads(capsys.readouterr().out)["xpub_expression"])
    wallet = MultisigWallet.from_descriptor("wsh(sortedmulti(2," + ",".join(keys) + "))")
    assert wallet.derive(0).address == "bc1qw7ysc083rxm7094nm68hhqa2zlvfqu92xzejuwqcvcfah6gavyrs3fucvy"
    assert main(["keygen", "--network", "regtest", "--seed", "x"]) == 0
    assert json.loads(capsys.readouterr().out)["xpub_expression"].split("]")[1].startswith("tpub")


def test_cli_makewallet_and_sign_from_keygen_files(tmp_path, capsys):
    files = []
    for label in "ABC":
        assert main(["keygen", "--seed", f"demo cosigner {label}"]) == 0
        f = tmp_path / f"cosigner-{label}.json"
        f.write_text(capsys.readouterr().out)
        files.append(str(f))
    wallet_file = tmp_path / "wallet.desc"
    assert main(["makewallet", "-t", "2", *files, "--name", "demo", "-o", str(wallet_file)]) == 0
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
    assert main(["makewallet", "-t", "2", files[0], expr, str(kfile)]) == 0
    assert capsys.readouterr().out.strip() == text
    # duplicate cosigner and bad threshold are refused
    assert main(["makewallet", "-t", "2", files[0], files[0], files[1]]) == 2
    assert main(["makewallet", "-t", "4", *files]) == 2
    capsys.readouterr()
    # sign with -k pointing at the keygen JSON files, sequentially, then finalize
    address = info["first_address"]
    unsigned = tmp_path / "u.psbt"
    assert main(["createpsbt", "-w", str(wallet_file), "-a", address, "-m", MESSAGE, "-o", str(unsigned)]) == 0
    a = tmp_path / "a.psbt"
    ab = tmp_path / "ab.psbt"
    assert main(["signpsbt", str(unsigned), "-k", files[0], "-o", str(a)]) == 0
    assert main(["signpsbt", str(a), "-k", files[1], "-o", str(ab)]) == 0
    assert main(["finalizepsbt", str(ab)]) == 0
    sig = capsys.readouterr().out.strip().splitlines()[0]
    assert main(["verifymessage", "-a", address, "-s", sig, "-m", MESSAGE]) == 0


def test_cli_deriveaddresses_and_getaddressinfo(tmp_path, wallet, capsys):
    cfg = tmp_path / "wallet.desc"
    cfg.write_text(wallet.to_descriptor() + "\n")
    assert main(["deriveaddresses", "-w", str(cfg), "--range", "0", "2"]) == 0
    lines = capsys.readouterr().out.split()
    assert lines == [wallet.derive(i).address for i in range(3)]
    assert main(["deriveaddresses", "-w", str(cfg), "--index", "4", "--change", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows == [{"branch": 1, "index": 4, "address": wallet.derive(4, 1).address}]
    assert main(["deriveaddresses", "-w", str(cfg), "--range", "3", "1"]) == 2
    capsys.readouterr()
    target = wallet.derive(4, 1)
    assert main(["getaddressinfo", "-w", str(cfg), target.address]) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["ismine"] and info["branch"] == 1 and info["index"] == 4
    assert info["scriptPubKey"] == target.script_pubkey.hex() and info["hex"] == target.witness_script.hex()
    assert info["sigsrequired"] == 2 and info["pubkeys"] == [pk.hex() for pk in target.pubkeys]
    assert info["witness_program"] == target.script_pubkey[2:].hex() and info["script"] == "multisig"
    assert list(info["hdkeypaths"]) == info["pubkeys"] and all(v.endswith(":m/48h/0h/0h/2h/1/4") for v in info["hdkeypaths"].values())
    from bip322.wallet import MultisigWallet
    from embit.descriptor import Descriptor

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
    assert main(["-w", str(cfg), "deriveaddresses", "--index", "2"]) == 0
    assert capsys.readouterr().out.strip() == addr
    assert main(["-d", wallet.to_descriptor(), "--network", "regtest", "deriveaddresses", "--index", "2"]) == 0
    assert capsys.readouterr().out.strip().startswith("bcrt1q")
    # the subcommand position still works and wins when both are given
    other = tmp_path / "other.desc"
    other.write_text(wallet.to_descriptor() + "\n")
    assert main(["-w", str(tmp_path / "missing.desc"), "deriveaddresses", "-w", str(other), "--index", "2"]) == 0
    assert capsys.readouterr().out.strip() == addr
    assert main(["deriveaddresses", "--index", "2"]) == 2


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
    assert main(["verifymessage", address, "--signature-file", str(sig_file), "-m", "positional form"]) == 0
    capsys.readouterr()
    assert main(["verifymessage", "--signature", sig, "-m", "positional form"]) == 2


def test_cli_engines_reports_versions(capsys):
    assert main(["engines"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert "btclib" in out["engines"] and out["versions"]["btclib"][:4].isdigit()
    if "kernel" in out["engines"]:
        assert out["versions"]["kernel"]["bitcoin-core"].startswith("v") and out["versions"]["kernel"]["py-bitcoinkernel"]


def test_cli_p2wpkh_flow(tmp_path, capsys):
    assert main(["keygen", "--seed", "single key", "--origin", "84h/0h/0h"]) == 0
    key_file = tmp_path / "k.json"
    key_file.write_text(capsys.readouterr().out)
    wallet_file = tmp_path / "w.desc"
    assert main(["makewallet", "--wpkh", str(key_file), "-o", str(wallet_file)]) == 0
    capsys.readouterr()
    assert wallet_file.read_text().startswith("wpkh([")
    assert main(["makewallet", "--wpkh", str(key_file), str(key_file)]) == 2
    assert main(["makewallet", str(key_file)]) == 2
    capsys.readouterr()
    assert main(["-w", str(wallet_file), "deriveaddresses", "--index", "1"]) == 0
    address = capsys.readouterr().out.strip()
    assert address.startswith("bc1q") and len(address) == 42
    assert main(["-w", str(wallet_file), "getaddressinfo", address]) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["ismine"] and "pubkey" in info and "sigsrequired" not in info
    unsigned, signed = tmp_path / "u.psbt", tmp_path / "s.psbt"
    assert main(["-w", str(wallet_file), "createpsbt", "-a", address, "-m", MESSAGE, "-o", str(unsigned)]) == 0
    assert main(["signpsbt", str(unsigned), "-k", str(key_file), "-o", str(signed)]) == 0
    assert main(["finalizepsbt", str(signed)]) == 0
    sig = capsys.readouterr().out.strip().splitlines()[0]
    assert main(["verifymessage", address, sig, MESSAGE]) == 0
    assert main(["verifymessage", address, sig, MESSAGE + "!"]) == 1
