import json

from bip322ms.cli import main

MESSAGE = "cli roundtrip message"


def test_cli_roundtrip(tmp_path, wallet, coldcard_config, signer_expressions, capsys):
    cfg = tmp_path / "wallet.txt"
    cfg.write_text(coldcard_config)
    address = wallet.derive(3).address
    unsigned = tmp_path / "unsigned.psbt"
    assert main(["create", "-w", str(cfg), "-a", address, "-m", MESSAGE, "-o", str(unsigned)]) == 0
    assert unsigned.read_text().startswith("cHNidP8")
    assert main(["inspect", str(unsigned)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["is_bip322"] and out["address"] == address and out["message_utf8"] == MESSAGE
    parts = []
    for i, key in enumerate(signer_expressions[:2]):
        part = tmp_path / f"part{i}.psbt"
        assert main(["sign", str(unsigned), "-k", key, "-o", str(part)]) == 0
        parts.append(str(part))
    combined = tmp_path / "combined.psbt"
    assert main(["combine", *parts, "-o", str(combined)]) == 0
    sig_file = tmp_path / "sig.txt"
    assert main(["finalize", str(combined), "--signature-file", str(sig_file), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    signature = sig_file.read_text().strip()
    assert out["signature"] == signature and signature.startswith("smp") and out["self_verification"]["state"] == "valid"
    assert main(["verify", "-a", address, "-s", signature, "-m", MESSAGE]) == 0
    assert "VALID" in capsys.readouterr().out
    assert main(["verify", "-a", address, "-s", signature, "-m", MESSAGE + "!"]) == 1
    assert "INVALID" in capsys.readouterr().out
    assert main(["verify", "-a", address, "-s", signature, "-m", MESSAGE, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "valid"


def test_cli_rejects_one_signature(tmp_path, wallet, descriptor_text, signer_expressions, capsys):
    unsigned = tmp_path / "u.psbt"
    assert main(["create", "-d", descriptor_text, "--index", "0", "-m", MESSAGE, "-o", str(unsigned)]) == 0
    part = tmp_path / "p.psbt"
    assert main(["sign", str(unsigned), "-k", signer_expressions[0], "-o", str(part)]) == 0
    assert main(["finalize", str(part)]) == 2
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
    assert first["coldcard_line"].startswith("EA34D476: xpub")
    from bip322ms.wallet import MultisigWallet

    keys = []
    for label in "ABC":
        assert main(["keygen", "--seed", f"demo cosigner {label}"]) == 0
        keys.append(json.loads(capsys.readouterr().out)["xpub_expression"])
    wallet = MultisigWallet.from_descriptor("wsh(sortedmulti(2," + ",".join(keys) + "))")
    assert wallet.derive(0).address == "bc1qw7ysc083rxm7094nm68hhqa2zlvfqu92xzejuwqcvcfah6gavyrs3fucvy"
    assert main(["keygen", "--network", "regtest", "--seed", "x"]) == 0
    assert json.loads(capsys.readouterr().out)["xpub_expression"].split("]")[1].startswith("tpub")
