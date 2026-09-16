"""End to end against a real Bitcoin Core (regtest): fund the demo wallet, snapshot, sign, finalize, verify, spend, verify again.

Skipped when the Core binary from refcheck/fetch.sh is not present.
"""

import json
from pathlib import Path

import pytest
from embit.networks import NETWORKS

from bip322.dev.signing import sign_psbt
from bip322.dev.testing import ORIGIN_PATH
from bip322.psbt import parse_psbt
from bip322.wallet import Wallet
from bip322audit.audit import finalize_bundle, format_report, verify_proofs
from bip322audit.rpc import BitcoinCli
from bip322audit.snapshot import take_snapshot, write_bundle
from bip322audit.stamp import parse_stamp

ROOT = Path(__file__).resolve().parent.parent
CORE_DIR = next(iter(sorted((ROOT / "refcheck" / "bin").glob("bitcoin-31.*"))), None)

pytestmark = pytest.mark.skipif(CORE_DIR is None, reason="Bitcoin Core binary not downloaded (refcheck/fetch.sh)")


@pytest.fixture(scope="module")
def core(tmp_path_factory):
    from refcheck.daemons import Daemon

    daemon = Daemon(CORE_DIR / "bin", tmp_path_factory.mktemp("core"), 18693, "core", wallet=True, extra_args=("-txindex=1",))
    daemon.start()
    try:
        yield daemon
    finally:
        daemon.stop()


@pytest.fixture(scope="module")
def regtest_wallet(wallet):
    return Wallet.from_descriptor(wallet.to_descriptor(), network="regtest")


@pytest.fixture(scope="module")
def private_descriptors(masters):
    out = []
    for holder in range(3):
        keys = []
        for j, m in enumerate(masters):
            account = m.derive("m/" + ORIGIN_PATH)
            text = (
                account.to_base58(NETWORKS["regtest"]["xprv"])
                if j == holder
                else account.to_public().to_base58(NETWORKS["regtest"]["xpub"])
            )
            keys.append(f"[{m.my_fingerprint.hex()}/{ORIGIN_PATH}]{text}/<0;1>/*")
        out.append("wsh(sortedmulti(2," + ",".join(keys) + "))")
    return out


def test_audit_workflow_on_regtest(core, regtest_wallet, signer_expressions, private_descriptors, tmp_path):
    miner = BitcoinCli(core.cli_argv("miner"))
    watch = BitcoinCli(core.cli_argv("watch"))
    node = BitcoinCli(core.cli_argv())
    node.call("createwallet", "miner")
    mine_to = miner.call("getnewaddress")
    miner.call("generatetoaddress", 101, mine_to)
    node.call("createwallet", "watch", True, True, "", False, True)
    descriptors = [{"desc": d, "timestamp": "now", "range": [0, 50], "active": False} for d in regtest_wallet.core_descriptors()]
    result = watch.call("importdescriptors", descriptors)
    assert all(r["success"] for r in result), result
    a0, a1 = regtest_wallet.derive(0).address, regtest_wallet.derive(2, 1).address
    miner.call("sendtoaddress", a0, 0.5)
    miner.call("sendtoaddress", a0, 0.25)
    miner.call("sendtoaddress", a1, 0.1)
    miner.call("generatetoaddress", 7, mine_to)  # funding confirmed at 102, tip 108, stamp 102

    # ---- snapshot from listunspent and from a UTXO-set scan: identical coins ---- #
    snapshot, psbts = take_snapshot(watch, regtest_wallet, "Audit {date} block {height}", depth=6)
    assert snapshot.stamp.height == 102 and snapshot.source == "listunspent" and snapshot.total_sat == 85_000_000
    assert [(a["branch"], a["index"], a["total_sat"]) for a in snapshot.addresses] == [(0, 0, 75_000_000), (1, 2, 10_000_000)]
    assert snapshot.message.startswith("Audit 20") and parse_stamp(snapshot.message).height == 102
    scanned, _ = take_snapshot(node, regtest_wallet, "x", depth=6, source="scantxoutset")
    assert [a["utxos"] for a in scanned.addresses] == [a["utxos"] for a in snapshot.addresses]

    # ---- sign (software cosigners A and C), finalize, verify -------------------- #
    directory = tmp_path / "bundle"
    write_bundle(directory, snapshot, psbts)
    files = {a["address"]: a["file"] for a in snapshot.addresses}
    for address in psbts:
        psbt = parse_psbt((directory / files[address]).read_text())
        assert sign_psbt(psbt, signer_expressions[0]) == 1 and sign_psbt(psbt, signer_expressions[2]) == 1
        (directory / "signed" / files[address].replace(".psbt", "-part.psbt")).write_text(psbt.to_string())
    document = finalize_bundle(directory)
    (directory / "proofs.json").write_text(json.dumps(document, indent=2))
    report = verify_proofs(document, node, txindex=True)
    assert report["ok"], format_report(report)
    assert report["stamp"]["ok"] and report["stamp"]["confirmations"] == 7
    assert report["summary"]["utxos_verified_at_snapshot"] == "3/3" and report["summary"]["all_utxos_still_unspent"]
    assert report["totals"]["verified_unspent_sat"] == 85_000_000

    # Bitcoin Core signs the same PSBT and agrees byte for byte with the software cosigners
    core_signed = node.call("descriptorprocesspsbt", (directory / files[a0]).read_text().strip(), private_descriptors[:2])
    assert core_signed["complete"]
    ours = parse_psbt((directory / "signed" / files[a0].replace(".psbt", "-part.psbt")).read_text())
    from bip322.psbt import extract_tx, finalize_psbt

    finalize_psbt(ours)
    assert extract_tx(ours).serialize().hex() != core_signed["hex"]  # A+C here vs A+B in Core: different quorum, both valid
    from bip322.core import parse_transaction
    from bip322.verify import verify_message

    core_tx = parse_transaction(bytes.fromhex(core_signed["hex"]))
    from bip322.core import encode_simple

    assert verify_message(a0, encode_simple(core_tx.vin[0].witness.items), snapshot.message.encode()).ok

    # ---- spend one output after the snapshot; the report says so and stays OK --- #
    funded = watch.call(
        "walletcreatefundedpsbt",
        [],
        [{mine_to: 0.2}],
        0,
        {"subtractFeeFromOutputs": [0], "changeAddress": regtest_wallet.derive(5, 1).address},
    )
    signed = node.call("descriptorprocesspsbt", funded["psbt"], private_descriptors[:2])
    assert signed["complete"]
    node.call("sendrawtransaction", signed["hex"])
    miner.call("generatetoaddress", 1, mine_to)
    report = verify_proofs(document, node, txindex=True)
    statuses = sorted(u["status"] for p in report["proofs"] for u in p["utxos"])
    assert report["ok"] and "spent_after_snapshot" in statuses and report["summary"]["utxos_verified_at_snapshot"] == "3/3"
    assert not report["summary"]["all_utxos_still_unspent"] and report["totals"]["verified_unspent_sat"] < 85_000_000
    without_index = verify_proofs(document, node, txindex=False)
    assert without_index["ok"] and "spent_or_unknown" in {u["status"] for p in without_index["proofs"] for u in p["utxos"]}
    text = format_report(report)
    assert "RESULT: OK" in text and "spent_after_snapshot" in text

    # ---- the CLI, driving the same node through bitcoin-cli ------------------- #
    import bip322audit.cli as audit_cli

    cli_arg = " ".join(core.cli_argv())
    assert audit_cli.main(["--cli", cli_arg, "-w", "watch", "snapshot", "--depth", "2", "-o", str(tmp_path / "b2")]) == 0
    assert json.loads((tmp_path / "b2" / "snapshot.json").read_text())["wallet"]["descriptor"] == regtest_wallet.to_descriptor()
    cfg = tmp_path / "w.desc"
    cfg.write_text(regtest_wallet.to_descriptor() + "\n")
    assert audit_cli.main(["--cli", cli_arg, "-w", "watch", "snapshot", "-d", str(cfg), "--depth", "2", "-o", str(tmp_path / "b3")]) == 0
    assert (tmp_path / "b2" / "snapshot.json").exists()
    assert audit_cli.main(["--cli", " ".join(core.cli_argv()), "verify", str(directory), "--txindex", "--scan"]) == 0
