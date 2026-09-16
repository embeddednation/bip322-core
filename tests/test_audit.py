"""bip322-audit with a fake node: stamp, snapshot, finalize, verify, report."""

import json
from pathlib import Path

import pytest

from bip322.dev.signing import sign_psbt
from bip322.psbt import parse_psbt
from bip322audit.audit import AuditError, collect_psbts, collect_spends, finalize_bundle, format_report, load_proofs, verify_proofs
from bip322audit.rpc import BitcoinCli, RpcError, to_sat
from bip322audit.snapshot import coins_from_listunspent, coins_from_scantxoutset, take_snapshot, write_bundle
from bip322audit.stamp import Stamp, check_stamp, compose_message, fetch_stamp, iso_utc, parse_stamp

T0 = 1_700_000_000


def fake_hash(height: int) -> str:
    return f"{height:064x}"


class FakeCli(BitcoinCli):
    """Answers the handful of RPCs the audit tool uses, from in-memory state."""

    def __init__(self, wallet, funded: dict[str, list[tuple[int, int]]], chain="main", tip=1000, rpcwallet=True, spent=()):
        super().__init__(["bitcoin-cli"] + (["-rpcwallet=watch"] if rpcwallet else []))
        self.chain_name, self.tip_height, self.wallet = chain, tip, wallet
        self.funded = funded  # address -> [(amount_sat, created_height)]
        # spent outpoints: {(txid, vout): spend_height}; a bare iterable of outpoints means "spent at the tip"
        self.spent = dict(spent) if isinstance(spent, dict) else {k: tip for k in spent}
        self.calls: list[tuple] = []

    @staticmethod
    def spend_txid(txid, vout):
        return "5d" + txid[2:-2] + f"{vout:02x}"

    def _spends(self):
        """(spend txid, height, spent outpoint) per spent output."""
        return [(self.spend_txid(t, v), h, (t, v)) for (t, v), h in self.spent.items()]

    def _utxos(self):
        rows = []
        for address, coins in self.funded.items():
            for n, (amount, height) in enumerate(coins):
                txid = f"{hash(address) & 0xFFFFFFFF:08x}{n:056x}"
                rows.append((address, txid, n, amount, height))
        return rows

    def call(self, method, *params):  # noqa: C901
        self.calls.append((method, *params))
        if method == "getblockchaininfo":
            return {"chain": self.chain_name, "blocks": self.tip_height, "bestblockhash": fake_hash(self.tip_height)}
        if method == "getwalletinfo":
            if "-rpcwallet=watch" not in self.argv:
                raise RpcError("Wallet file not specified (must request wallet RPC through /wallet/<filename> uri-path)")
            return {"walletname": "watch"}
        if method == "listdescriptors":
            if "-rpcwallet=watch" not in self.argv:
                raise RpcError("Wallet file not specified")
            from embit.descriptor.checksum import add_checksum

            base = self.wallet.to_descriptor(checksum=False)
            return {
                "wallet_name": "watch",
                "descriptors": [
                    {"desc": add_checksum(base.replace("/<0;1>/*", "/0/*")), "active": True, "internal": False, "range": [0, 999]},
                    {"desc": add_checksum(base.replace("/<0;1>/*", "/1/*")), "active": True, "internal": True, "range": [0, 999]},
                ],
            }
        if method == "getblockhash":
            return fake_hash(int(params[0]))
        if method == "getblockheader":
            h = params[0]
            if not h.startswith("0" * 40):
                raise RpcError("Block not found")
            height = int(h, 16)
            return {"height": height, "time": T0 + height * 600, "confirmations": self.tip_height - height + 1}
        if method == "listunspent":
            minconf = int(params[0])
            out = []
            for address, txid, vout, amount, height in self._utxos():
                conf = self.tip_height - height + 1
                if conf < minconf or (txid, vout) in self.spent:
                    continue
                d = self.wallet.find_address(address, max_index=20)
                desc = (
                    f"wsh(sortedmulti(2,[ea34d476/48h/0h/0h/2h/{d.branch}/{d.index}]02aa,[6cb0f623/48h/0h/0h/2h/{d.branch}/{d.index}]02bb))#abcdefgh"
                    if d
                    else "addr(x)"
                )
                out.append(
                    {
                        "txid": txid,
                        "vout": vout,
                        "address": address,
                        "amount": f"{amount / 1e8:.8f}",
                        "confirmations": conf,
                        "desc": desc,
                        "spendable": False,
                        "solvable": True,
                    }
                )
            out.append(
                {
                    "txid": "ff" * 32,
                    "vout": 0,
                    "address": "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
                    "amount": "1.00000000",
                    "confirmations": 999,
                }
            )
            out.append({"txid": "ee" * 32, "vout": 0, "address": "not-an-address", "amount": "1.00000000", "confirmations": 999})
            return out
        if method == "scantxoutset":
            objects = params[1] if len(params) > 1 else []
            wanted = {o["desc"][5:-1] for o in objects if str(o.get("desc", "")).startswith("addr(")}
            unspents = []
            for address, txid, vout, amount, height in self._utxos():
                if (txid, vout) in self.spent or (wanted and address not in wanted):
                    continue
                d = self.wallet.find_address(address, max_index=20)
                unspents.append(
                    {
                        "txid": txid,
                        "vout": vout,
                        "scriptPubKey": d.script_pubkey.hex(),
                        "amount": f"{amount / 1e8:.8f}",
                        "height": height,
                        "desc": "",
                    }
                )
            return {"success": True, "height": self.tip_height, "bestblock": fake_hash(self.tip_height), "unspents": unspents}
        if method == "gettxout":
            txid, vout = params[0], int(params[1])
            for address, t, v, amount, height in self._utxos():
                if (t, v) == (txid, vout) and (t, v) not in self.spent:
                    return {
                        "value": f"{amount / 1e8:.8f}",
                        "confirmations": self.tip_height - height + 1,
                        "scriptPubKey": {"address": address},
                    }
            return None
        if method == "getrawtransaction":
            txid, blockhash = params[0], params[2] if len(params) > 2 else None
            if blockhash is None:
                raise RpcError("No such mempool transaction. Use -txindex or provide a block hash")
            for address, t, v, amount, height in self._utxos():
                if t == txid:
                    if blockhash != fake_hash(height):
                        raise RpcError("No such transaction found in the provided block")
                    vout = [{"value": "0.00000001", "n": i, "scriptPubKey": {"address": "bc1qother"}} for i in range(v)]
                    vout.append({"value": f"{amount / 1e8:.8f}", "n": v, "scriptPubKey": {"address": address}})
                    return {"txid": t, "blockhash": blockhash, "vin": [{"txid": "aa" * 32, "vout": 0}], "vout": vout}
            for stxid, height, (t, v) in self._spends():
                if stxid == txid:
                    if blockhash != fake_hash(height):
                        raise RpcError("No such transaction found in the provided block")
                    return {"txid": stxid, "blockhash": blockhash, "vin": [{"txid": t, "vout": v}], "vout": []}
            raise RpcError("No such transaction found in the provided block")
        if method == "listsinceblock":
            since = int(params[0], 16)
            rows = []
            for stxid, height, _ in self._spends():
                if height > since:
                    row = {
                        "txid": stxid,
                        "category": "send",
                        "confirmations": self.tip_height - height + 1,
                        "blockhash": fake_hash(height),
                        "blockheight": height,
                    }
                    rows += [row, {**row, "category": "receive"}]  # Core lists a tx once per affected address
            return {"transactions": rows, "lastblock": fake_hash(self.tip_height)}
        if method == "gettransaction":
            for stxid, height, (t, v) in self._spends():
                if stxid == params[0]:
                    return {
                        "txid": stxid,
                        "blockhash": fake_hash(height),
                        "blockheight": height,
                        "confirmations": self.tip_height - height + 1,
                        "decoded": {"vin": [{"txid": t, "vout": v}], "vout": []},
                    }
            raise RpcError("Invalid or non-wallet transaction id")
        raise RpcError(f"fake node: unsupported {method}")


@pytest.fixture
def funded(wallet):
    a0, a1 = wallet.derive(0).address, wallet.derive(1, 1).address
    return {a0: [(50_000_000, 990), (25_000_000, 993)], a1: [(10_000_000, 980)]}


def test_to_sat_is_exact():
    from bip322audit.rpc import btc

    assert to_sat("0.50000000") == 50_000_000 and to_sat("0.00000001") == 1 and to_sat(1) == 100_000_000
    assert btc(50_000_000) == "0.50000000" and btc(1) == "0.00000001" and btc(0) == "0.00000000" and to_sat(btc(123456789)) == 123456789
    with pytest.raises(RpcError):
        to_sat("0.000000001")


def test_stamp_fetch_parse_compose_check(wallet, funded):
    cli = FakeCli(wallet, funded, tip=1000)
    stamp = fetch_stamp(cli, 6)
    when = iso_utc(T0 + 994 * 600)
    assert stamp == Stamp(994, fake_hash(994), when) and when.endswith("Z") and len(when) == 20
    line = stamp.line()
    assert line == f"block: 994 {fake_hash(994)} {when}"
    assert parse_stamp("hello\n" + line) == stamp and parse_stamp(("x\n" + line).encode()) == stamp
    assert parse_stamp("no stamp here") is None and parse_stamp(line + "\nafter") is None
    msg = compose_message("Audit {date} at height {height}", stamp)
    assert msg == f"Audit {when[:10]} at height 994\n{line}"
    assert compose_message("", stamp) == line
    assert check_stamp(cli, stamp)["ok"]
    assert not check_stamp(cli, Stamp(995, fake_hash(994), stamp.time))["ok"]
    assert not check_stamp(cli, Stamp(994, "ab" * 32, stamp.time))["ok"]
    with pytest.raises(ValueError):
        fetch_stamp(cli, 2000)


def test_coins_from_listunspent_filters_by_snapshot_block_and_wallet(wallet, funded):
    cli = FakeCli(wallet, funded, tip=1000)
    stamp = fetch_stamp(cli, 6)  # height 994: the 993 output is in, the 980 one too
    coins = coins_from_listunspent(cli, wallet, stamp, 1000, max_index=20)
    assert ("listunspent", 7, 9999999) in cli.calls and all(u.blockhash == fake_hash(u.height) for c in coins for u in c.utxos)
    assert [(c.derived.branch, c.derived.index, c.total_sat) for c in coins] == [(0, 0, 75_000_000), (1, 1, 10_000_000)]
    stamp = fetch_stamp(cli, 9)  # height 991: the 993 output is not yet confirmed
    coins = coins_from_listunspent(cli, wallet, stamp, 1000, max_index=20)
    assert [c.total_sat for c in coins] == [50_000_000, 10_000_000]
    scan = coins_from_scantxoutset(cli, wallet, fetch_stamp(cli, 6), scan_range=20)
    assert [(c.derived.index, c.total_sat) for c in scan] == [(0, 75_000_000), (1, 10_000_000)]


def test_take_snapshot_checks_chain_and_coldcard_rules(wallet, funded):
    with pytest.raises(RpcError, match="chain"):
        take_snapshot(FakeCli(wallet, funded, chain="test"), wallet, "x")
    with pytest.raises(ValueError, match="Coldcard"):
        take_snapshot(FakeCli(wallet, funded), wallet, " leading space {date}")
    snapshot, psbts = take_snapshot(FakeCli(wallet, funded), wallet, " leading space {date}", coldcard_strict=False)
    assert snapshot.message.startswith(" leading space " + iso_utc(T0 + 994 * 600)[:10] + "\nblock: 994 ")
    assert set(psbts) == set(funded) and snapshot.total_sat == 85_000_000 and snapshot.source == "listunspent"
    snapshot2, _ = take_snapshot(FakeCli(wallet, funded, rpcwallet=False), wallet, "x")
    assert snapshot2.source == "scantxoutset" and snapshot2.total_sat == 85_000_000
    with pytest.raises(RpcError, match="no coins"):
        take_snapshot(FakeCli(wallet, {}), wallet, "x")


def _signed_bundle(tmp_path, wallet, funded, signer_expressions, cli=None) -> Path:
    cli = cli or FakeCli(wallet, funded)
    snapshot, psbts = take_snapshot(cli, wallet, "Annual audit {date}")
    directory = tmp_path / "bundle"
    written = write_bundle(directory, snapshot, psbts)
    assert (directory / "snapshot.json").exists() and (directory / "message.txt").read_bytes() == snapshot.message.encode()
    assert len([p for p in written if p.suffix == ".psbt"]) == 2 and (directory / "signed").is_dir() and (directory / "to_sign").is_dir()
    files = {a["address"]: a["file"] for a in snapshot.addresses}
    assert sorted(files.values()) == ["to_sign/to_sign-01.psbt", "to_sign/to_sign-02.psbt"]
    assert sorted(p.name for p in (directory / "to_sign").iterdir()) == ["to_sign-01.psbt", "to_sign-02.psbt"]
    assert snapshot.node_wallet == "watch" and json.loads((directory / "snapshot.json").read_text())["node_wallet"] == "watch"
    for address in funded:
        for i, signer in enumerate(signer_expressions[:2]):  # two cosigners, parallel signing
            psbt = parse_psbt((directory / files[address]).read_text())
            assert sign_psbt(psbt, signer) == 1
            (directory / "signed" / Path(files[address]).name.replace(".psbt", f"-cc{i}-part.psbt")).write_text(psbt.to_string() + "\n")
    return directory


def test_finalize_and_verify_with_fake_node(tmp_path, wallet, funded, signer_expressions):
    directory = _signed_bundle(tmp_path, wallet, funded, signer_expressions)
    groups = collect_psbts(directory)
    assert len(groups) == 2 and all(len(g) == 3 for g in groups.values())  # unsigned + 2 signed each
    document = finalize_bundle(directory)
    assert len(document["proofs"]) == 2 and all(p["signature"].startswith("smp") for p in document["proofs"])
    (directory / "proofs.json").write_text(json.dumps(document))
    assert load_proofs(directory)["message_hex"] == document["message_hex"]

    cli = FakeCli(wallet, funded, tip=1200)
    report = verify_proofs(document, cli, engines=["btclib"])
    assert report["ok"] and report["summary"]["proofs_valid"] and report["stamp"]["ok"]
    assert report["summary"]["utxos_verified_at_snapshot"] == "3/3" and report["summary"]["all_utxos_still_unspent"]
    assert report["totals"] == {
        "claimed_sat": 85_000_000,
        "claimed_btc": "0.85000000",
        "verified_unspent_sat": 85_000_000,
        "verified_unspent_btc": "0.85000000",
    }
    text = format_report(report)
    assert "RESULT: OK" in text and "3/3" in text and "0.85000000 BTC" in text and " sat" not in text

    # one output spent since the snapshot: reported, not a failure. The recorded block hash lets the
    # creating tx be fetched without -txindex, so existence at the snapshot is still verified.
    utxo = document["proofs"][0]["utxos"][0]
    assert utxo["blockhash"] == fake_hash(utxo["height"])
    outpoint = (utxo["txid"], utxo["vout"])
    cli = FakeCli(wallet, funded, tip=1200, spent={outpoint: 1150})
    report = verify_proofs(document, cli, engines=["btclib"])
    assert report["ok"] and report["summary"]["utxos_verified_at_snapshot"] == "3/3" and not report["summary"]["all_utxos_still_unspent"]
    row = report["proofs"][0]["utxos"][0]
    assert row["status"] == "spent_after_snapshot" and row["verified"] and "unspent_at_snapshot" not in row and "finalize" in row["note"]
    assert document["spends"] is None  # finalized without a node
    assert report["summary"]["utxos_shown_unspent_at_snapshot"] == "2/3" and report["totals"]["verified_unspent_sat"] == 35_000_000
    # spends.json from the owner's wallet: the spend is confirmed after the stamp block, so it was unspent at the snapshot
    spends_doc = collect_spends(cli, document)
    assert list(spends_doc["spends"]) == [f"{utxo['txid']}:{utxo['vout']}"]
    assert spends_doc["spends"][f"{utxo['txid']}:{utxo['vout']}"] == {
        "spent_by": cli.spend_txid(*outpoint),
        "blockhash": fake_hash(1150),
        "height": 1150,
    }
    refreshed = finalize_bundle(directory, cli=cli)  # re-run on the owner's node: the spend goes into proofs.json
    assert refreshed["spends"] == spends_doc["spends"] and refreshed["spends_utc"] and refreshed["proofs"] == document["proofs"]
    report = verify_proofs(refreshed, cli, engines=["btclib"])
    assert report["spends_recorded_utc"] == refreshed["spends_utc"]
    row = report["proofs"][0]["utxos"][0]
    assert (
        report["ok"]
        and row["unspent_at_snapshot"]
        and row["spent_height"] == 1150
        and report["summary"]["utxos_shown_unspent_at_snapshot"] == "3/3"
    )
    assert "unspent at snapshot" in format_report(report)
    # a spend at or before the stamp block contradicts the claim
    early = FakeCli(wallet, funded, tip=1200, spent={outpoint: 990})
    assert collect_spends(early, document)["spends"] == {}  # listsinceblock(stamp) never lists it; a forged spends.json might
    forged = dict(
        document,
        spends={f"{utxo['txid']}:{utxo['vout']}": {"spent_by": early.spend_txid(*outpoint), "blockhash": fake_hash(990), "height": 990}},
    )
    report = verify_proofs(forged, early, engines=["btclib"])
    assert not report["ok"] and report["proofs"][0]["utxos"][0]["contradiction"] and report["summary"]["contradictions"] == 1
    # a recorded spend that does not spend the output proves nothing
    wrong = dict(
        document,
        spends={f"{utxo['txid']}:{utxo['vout']}": {"spent_by": cli.spend_txid("ab" * 32, 0), "blockhash": fake_hash(1150), "height": 1150}},
    )
    report = verify_proofs(wrong, cli, engines=["btclib"])
    assert report["ok"] and "unspent_at_snapshot" not in report["proofs"][0]["utxos"][0]
    # an older document without block hashes, on a node without -txindex: spent or unknown
    old = json.loads(json.dumps(document))
    del old["proofs"][0]["utxos"][0]["blockhash"]
    report = verify_proofs(old, cli, engines=["btclib"])
    assert (
        report["ok"]
        and report["proofs"][0]["utxos"][0]["status"] == "spent_or_unknown"
        and report["summary"]["utxos_verified_at_snapshot"] == "2/3"
    )

    # a contradiction: the node reports a different amount
    cli = FakeCli(wallet, {a: [(amt + 1, h) for amt, h in coins] for a, coins in funded.items()}, tip=1200)
    report = verify_proofs(document, cli, engines=["btclib"])
    assert not report["ok"] and report["summary"]["contradictions"] == 3 and "RESULT: FAILED" in format_report(report)

    # tampered signature or message: proofs invalid
    bad = json.loads(json.dumps(document))
    bad["message"] = bad["message"] + "!"
    bad["message_hex"] = bad["message"].encode().hex()
    assert not verify_proofs(bad, FakeCli(wallet, funded, tip=1200), engines=["btclib"])["summary"]["proofs_valid"]

    # offline: signatures only
    report = verify_proofs(document, None, engines=["btclib"])
    assert report["ok"] and report["stamp"]["ok"] is None and report["summary"]["stamp_ok"] is None
    assert "not checked" in format_report(report)


def test_finalize_reports_missing_signatures(tmp_path, wallet, funded, signer_expressions):
    directory = _signed_bundle(tmp_path, wallet, funded, signer_expressions)
    for path in (directory / "signed").iterdir():
        if path.name.endswith("-cc1-part.psbt"):
            path.unlink()
    with pytest.raises(AuditError, match="need 2 valid signatures"):
        finalize_bundle(directory)


def test_cli_end_to_end_with_fake_node(tmp_path, wallet, funded, signer_expressions, monkeypatch, capsys):
    import bip322audit.cli as audit_cli

    fake = FakeCli(wallet, funded, tip=1000)
    monkeypatch.setattr(audit_cli, "BitcoinCli", lambda command: fake)
    cfg = tmp_path / "w.desc"
    cfg.write_text(wallet.to_descriptor() + "\n")
    out_dir = tmp_path / "bundle"
    assert audit_cli.main(["stamp", "--depth", "6"]) == 0
    assert capsys.readouterr().out.strip() == fetch_stamp(fake, 6).line()
    assert (
        audit_cli.main(["snapshot", "-w", "watch", "--text", "Audit {date}", "-o", str(out_dir)]) == 0
    )  # descriptor from the node, -w after the command
    out, err = capsys.readouterr()
    assert out.strip() == str(out_dir) and json.loads(err)["total_sat"] == 85_000_000
    assert audit_cli.main(["-w", "watch", "snapshot", "-d", str(cfg), "-o", str(out_dir)]) == 2  # not empty
    capsys.readouterr()
    other = tmp_path / "other.desc"
    other.write_text(wallet.to_descriptor().replace("sortedmulti(2,", "sortedmulti(1,").split("#")[0] + "\n")
    assert audit_cli.main(["-w", "watch", "snapshot", "-d", str(other), "-o", str(tmp_path / "x")]) == 2  # not the node's descriptor
    assert "not one of the node wallet" in capsys.readouterr().err
    capsys.readouterr()
    files = {a["address"]: a["file"] for a in json.loads((out_dir / "snapshot.json").read_text())["addresses"]}
    for address in funded:
        psbt = parse_psbt((out_dir / files[address]).read_text())
        for signer in signer_expressions[:2]:
            sign_psbt(psbt, signer)
        (out_dir / "signed" / Path(files[address]).name.replace(".psbt", "-signed.psbt")).write_text(psbt.to_string())
    assert audit_cli.main(["finalize", str(out_dir)]) == 0
    assert capsys.readouterr().out.strip() == str(out_dir / "proofs.json")
    assert audit_cli.main(["verify", str(out_dir), "--report", str(tmp_path / "r.json")]) == 0
    text = capsys.readouterr().out
    assert "RESULT: OK" in text and json.loads((tmp_path / "r.json").read_text())["ok"]
    assert audit_cli.main(["verify", str(out_dir / "proofs.json"), "--json", "--offline"]) == 0
    assert json.loads(capsys.readouterr().out)["stamp"]["ok"] is None
    assert audit_cli.main(["help", "snapshot"]) == 0
    assert "Examples:" in capsys.readouterr().out


def test_core_package_stays_pure():
    """bip322/ never imports the audit tool, subprocesses, sockets or HTTP."""
    import re

    forbidden = re.compile(r"^\s*(?:from|import)\s+(bip322audit|subprocess|socket|http|urllib|requests|refcheck)\b", re.M)
    for path in Path("bip322").rglob("*.py"):
        assert not forbidden.search(path.read_text()), f"{path} imports chain-facing or audit code"


def test_proofs_document_names_addresses_not_a_wallet(tmp_path, wallet, funded, signer_expressions):
    """The auditor's document carries no descriptor, no xpub, no derivation path and no node wallet name."""
    directory = _signed_bundle(tmp_path, wallet, funded, signer_expressions)
    document = finalize_bundle(directory)
    text = json.dumps(document)
    assert "wallet" not in document and "node_wallet" not in document and "source" not in document
    assert wallet.to_descriptor() not in text and all(str(c.xpub) not in text for c in wallet.cosigners)
    assert all("branch" not in p and "index" not in p for p in document["proofs"])
    assert document["policy"] == "2 of 3" and {p["address"] for p in document["proofs"]} == set(funded)
    owner = json.loads((directory / "snapshot.json").read_text())  # the owner's copy keeps everything
    assert owner["wallet"]["descriptor"] == wallet.to_descriptor() and owner["addresses"][0]["index"] == 0
    report = verify_proofs(document, FakeCli(wallet, funded, tip=1200), engines=["btclib"])
    assert report["ok"] and "address_in_wallet" not in report["proofs"][0] and "wallet_descriptor_shared" not in report
    assert "descriptor" not in format_report(report)


def test_verify_checks_document_consistency(tmp_path, wallet, funded, signer_expressions):
    directory = _signed_bundle(tmp_path, wallet, funded, signer_expressions)
    document = finalize_bundle(directory)
    cli = FakeCli(wallet, funded, tip=1200)
    good = verify_proofs(document, cli, engines=["btclib"])
    assert good["ok"] and good["summary"]["document_consistent"]
    # a stamp in the document that disagrees with the signed message
    bad = json.loads(json.dumps(document))
    bad["stamp"]["height"] += 1
    report = verify_proofs(bad, cli, engines=["btclib"])
    assert not report["ok"] and "stamp recorded" in report["document_problems"][0]
    assert "1 problem(s), listed above" in format_report(report)
    # message and message_hex disagreeing is refused outright
    bad = json.loads(json.dumps(document))
    bad["message"] = bad["message"] + "!"
    with pytest.raises(AuditError, match="inconsistent"):
        verify_proofs(bad, cli, engines=["btclib"])


def test_verify_scan_reports_what_the_proven_addresses_hold_now(tmp_path, wallet, funded, signer_expressions):
    directory = _signed_bundle(tmp_path, wallet, funded, signer_expressions)
    document = finalize_bundle(directory)
    extra = dict(funded)
    extra[wallet.derive(3).address] = [(7_000_000, 995)]  # another address of the same wallet: not proven, not scanned
    cli = FakeCli(wallet, extra, tip=1200)
    report = verify_proofs(document, cli, engines=["btclib"], scan=True)
    scanned = [c for c in cli.calls if c[0] == "scantxoutset"][-1]
    assert [o["desc"] for o in scanned[2]] == [f"addr({p['address']})" for p in document["proofs"]]
    holdings = report["current_holdings"]
    assert holdings["total_sat"] == 85_000_000 and wallet.derive(3).address not in holdings["by_address_sat"]
    assert holdings["by_address_sat"] == {a: sum(v for v, _ in coins) for a, coins in funded.items()}
    assert "proven addresses hold now" in format_report(report) and report["ok"]


def test_wallet_from_node(wallet, funded):
    from bip322audit.snapshot import check_wallet_against_node, wallet_from_node

    cli = FakeCli(wallet, funded)
    node_wallet = wallet_from_node(cli)
    assert node_wallet.to_descriptor() == wallet.to_descriptor() and node_wallet.network == "main"
    check_wallet_against_node(cli, wallet)
    with pytest.raises(RpcError, match="pass --descriptor"):
        wallet_from_node(FakeCli(wallet, funded, rpcwallet=False))
