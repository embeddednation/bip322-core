import pytest

from bip322ms.wallet import MultisigWallet, WalletError, parse_coldcard_config, path_from_str, path_to_str


def test_paths():
    assert path_from_str("m/48h/0'/0H/2h/0/5") == [0x80000030, 0x80000000, 0x80000000, 0x80000002, 0, 5]
    assert path_to_str([0x80000030, 0, 5]) == "m/48h/0/5"
    with pytest.raises(WalletError):
        path_from_str("m/48x")


def test_wallet_policy_and_descriptor_roundtrip(wallet, descriptor_text):
    assert wallet.threshold == 2 and len(wallet.cosigners) == 3 and wallet.sorted
    assert wallet.num_branches == 2
    desc = wallet.to_descriptor()
    assert desc.startswith("wsh(sortedmulti(2,") and "#" in desc
    again = MultisigWallet.from_descriptor(desc)
    assert again.to_descriptor() == desc
    assert MultisigWallet.from_descriptor(descriptor_text).to_descriptor() == desc
    with pytest.raises(WalletError):
        MultisigWallet.from_descriptor(desc[:-1] + ("a" if desc[-1] != "a" else "b"))


def test_coldcard_config_gives_same_wallet(coldcard_config, wallet):
    cfg = parse_coldcard_config(coldcard_config)
    assert cfg.threshold == 2 and cfg.total == 3 and cfg.format == "P2WSH" and cfg.name == "test-2of3"
    cc = MultisigWallet.from_coldcard_config(coldcard_config)
    assert cc.to_descriptor() == wallet.to_descriptor()
    assert cc.network == "main"
    assert cc.derive(0).address == wallet.derive(0).address


def test_derivation_is_sorted_and_complete(wallet):
    d = wallet.derive(3)
    assert d.address.startswith("bc1q") and len(d.address) == 62
    assert d.script_pubkey[:2] == b"\x00\x20"
    assert d.threshold == 2 and len(d.pubkeys) == 3
    assert list(d.pubkeys) == sorted(d.pubkeys)  # BIP-67
    assert set(d.pubkeys) == set(d.derivations)
    for sec, (fp, path) in d.derivations.items():
        assert len(fp) == 4 and path[-2:] == (0, 3) and path[:4] == (0x80000030, 0x80000000, 0x80000000, 0x80000002)
    change = wallet.derive(3, branch=1)
    assert change.address != d.address
    with pytest.raises(WalletError):
        wallet.derive(0, branch=2)


def test_find_address_across_networks(wallet):
    d = wallet.derive(7, branch=1)
    found = wallet.find_address(d.address, max_index=10)
    assert found is not None and (found.branch, found.index) == (1, 7)
    regtest = MultisigWallet.from_descriptor(wallet.to_descriptor(), network="regtest").derive(7, branch=1)
    assert regtest.address.startswith("bcrt1q")
    found = wallet.find_address(regtest.address, max_index=10)
    assert found is not None and found.address == d.address
    assert wallet.find_address(wallet.derive(50).address, max_index=10) is None


def test_rejects_unsupported_descriptors(masters):
    from tests.conftest import key_expression

    keys = ",".join(key_expression(m) for m in masters)
    with pytest.raises(WalletError):
        MultisigWallet.from_descriptor(f"sh(wsh(sortedmulti(2,{keys})))")
    with pytest.raises(WalletError):
        MultisigWallet.from_descriptor(f"wpkh({key_expression(masters[0])})")
    with pytest.raises(WalletError):
        MultisigWallet.from_descriptor("wsh(sortedmulti(2," + ",".join(key_expression(m).split("]")[1] for m in masters) + "))")
