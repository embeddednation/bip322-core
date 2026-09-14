"""Signature corpus for the reference checks: valid, invalid and inconclusive cases.

Everything is produced with the same deterministic 2-of-3 test wallet the unit
tests use (tests/conftest.py), on the regtest network so Bitcoin Knots can be
asked about the addresses.  The message and script commit to the *script*, so
the mainnet encoding of each address is carried along for verifiers that only
speak mainnet.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from embit.networks import NETWORKS
from embit.transaction import SIGHASH

from bip322.core import build_to_sign, build_to_spend, encode_full, encode_simple
from bip322.psbt import BIP322PSBT, create_psbt, finalize_psbt, sign_psbt, signature_from_psbt
from bip322.wallet import MultisigWallet
from tests.conftest import key_expression, master_key
from tests.helpers import high_s, sign_with_sighash

MESSAGES = {
    "hello": b"Hello World",
    "empty": b"",
    "quorum": b"bip322: the 2-of-3 quorum controls this address",
    "utf8": "UTF-8 support: öäüéàè 测试文本 \U0001f604".encode("utf-8"),
    "max330": b"m" * 330,
    "multiline": b"line one\nline two\ttabbed",
}
PAIRS = [(0, 1), (0, 2), (1, 2)]


@dataclass
class Case:
    id: str
    kind: str  # valid | invalid | inconclusive
    message: bytes
    address_regtest: str
    address_main: str
    signature: str
    note: str = ""
    extra: dict = field(default_factory=dict)
    #: implementation name -> reason the case cannot be expressed for it
    skip: dict = field(default_factory=dict)
    #: implementation name -> documented deviation from the BIP (verdict differs on purpose)
    known: dict = field(default_factory=dict)


class Fixture:
    def __init__(self):
        self.masters = [master_key(label) for label in "ABC"]
        desc = "wsh(sortedmulti(2," + ",".join(key_expression(m) for m in self.masters) + "))"
        self.wallet = MultisigWallet.from_descriptor(desc, network="regtest", name="refcheck-2of3")
        self.wallet_main = MultisigWallet.from_descriptor(desc, network="main")
        self.signers = [key_expression(m, private=True) for m in self.masters]
        # a single-key P2WPKH wallet on cosigner B's seed
        b = self.masters[1]
        account = b.derive("m/84h/0h/0h")
        self.wpkh_signer = f"[{b.my_fingerprint.hex()}/84h/0h/0h]{account.to_base58()}/<0;1>/*"
        wpkh_desc = f"wpkh([{b.my_fingerprint.hex()}/84h/0h/0h]{account.to_public().to_base58()}/<0;1>/*)"
        self.wpkh = MultisigWallet.from_descriptor(wpkh_desc, network="regtest", name="refcheck-wpkh")
        self.wpkh_main = MultisigWallet.from_descriptor(wpkh_desc, network="main")
        # one descriptor per cosigner holding only that cosigner's private key,
        # in regtest (tprv/tpub) encoding for Bitcoin Core's regtest RPCs
        self.private_descriptors = [self._private_descriptor(i) for i in range(3)]

    def _private_descriptor(self, holder: int, branch: int = 0) -> str:
        keys = []
        for j, m in enumerate(self.masters):
            account = m.derive("m/48h/0h/0h/2h")
            if j == holder:
                text = account.to_base58(NETWORKS["regtest"]["xprv"])
            else:
                text = account.to_public().to_base58(NETWORKS["regtest"]["xpub"])
            keys.append(f"[{m.my_fingerprint.hex()}/48h/0h/0h/2h]{text}/{branch}/*")
        return "wsh(sortedmulti(2," + ",".join(keys) + "))"

    def addresses(self, index: int, branch: int = 0) -> tuple[str, str]:
        return self.wallet.derive(index, branch).address, self.wallet_main.derive(index, branch).address

    def unsigned(self, message: bytes, index: int = 0, branch: int = 0, **kwargs) -> BIP322PSBT:
        return create_psbt(self.wallet.derive(index, branch), message, xpubs=self.wallet.global_xpubs(), **kwargs)

    def signed(self, message: bytes, pair, index: int = 0, branch: int = 0, **kwargs) -> BIP322PSBT:
        psbt = self.unsigned(message, index, branch, **kwargs)
        for i in pair:
            assert sign_psbt(psbt, self.signers[i]) == 1
        return psbt

    def finalized(self, message: bytes, pair, index: int = 0, branch: int = 0, **kwargs) -> BIP322PSBT:
        return finalize_psbt(self.signed(message, pair, index, branch, **kwargs))


def build_corpus(fx: Fixture) -> list[Case]:
    cases: list[Case] = []
    index = 0
    for name, message in MESSAGES.items():
        for pair in PAIRS:
            index = (index + 1) % 6
            branch = index % 2
            psbt = fx.finalized(message, pair, index, branch)
            reg, main = fx.addresses(index, branch)
            pair_id = "".join("ABC"[i] for i in pair)
            cases.append(Case(f"smp-{name}-{pair_id}", "valid", message, reg, main, signature_from_psbt(psbt, "smp"), f"index {index} branch {branch}"))
            if pair == (0, 2):
                cases.append(Case(f"ful-{name}-{pair_id}", "valid", message, reg, main, signature_from_psbt(psbt, "ful"), "same witness, full encoding"))
    msg = MESSAGES["quorum"]
    reg, main = fx.addresses(3)
    psbt = fx.finalized(msg, (0, 1, 2), 3)
    cases.append(Case("smp-three-sigs", "valid", msg, reg, main, signature_from_psbt(psbt), "3 partial sigs, finalizer keeps 2"))
    psbt = fx.finalized(msg, (1, 2), 3, version=2)
    cases.append(Case("ful-version2", "valid", msg, reg, main, signature_from_psbt(psbt), "to_sign version 2"))
    psbt = fx.finalized(msg, (1, 2), 3, version=2, locktime=500000, sequence=5)
    cases.append(Case("ful-timelock", "valid", msg, reg, main, signature_from_psbt(psbt), "version 2, locktime 500000, sequence 5", {"locktime": 500000, "sequence": 5}))
    cases.append(Case("pof-single-input", "valid", msg, reg, main, signature_from_psbt(fx.finalized(msg, (0, 1), 3), "pof"), "pof encoding without extra inputs"))
    psbt = fx.finalized(msg, (0, 1), 3, version=1)
    cases.append(Case("ful-version1", "inconclusive", msg, reg, main, signature_from_psbt(psbt, "ful"), "to_sign version 1 is neither 0 nor 2"))

    # ---- P2WPKH ------------------------------------------------------------ #
    wd = fx.wpkh.derive(1)
    wreg, wmain = wd.address, fx.wpkh_main.derive(1).address
    wpsbt = create_psbt(wd, msg, xpubs=fx.wpkh.global_xpubs())
    assert sign_psbt(wpsbt, fx.wpkh_signer) == 1
    finalize_psbt(wpsbt)
    wsig = signature_from_psbt(wpsbt, "smp")
    cases.append(Case("smp-p2wpkh", "valid", msg, wreg, wmain, wsig, "single-key wpkh wallet"))
    cases.append(Case("ful-p2wpkh", "valid", msg, wreg, wmain, signature_from_psbt(wpsbt, "ful"), "same witness, full encoding"))
    cases.append(Case("bad-p2wpkh-wrong-message", "invalid", msg + b"?", wreg, wmain, wsig, "message differs"))
    cases.append(Case("bad-p2wpkh-wrong-address", "invalid", msg, fx.wpkh.derive(2).address, fx.wpkh_main.derive(2).address, wsig, "another key's address"))

    # ---- invalid ----------------------------------------------------------- #
    derived = fx.wallet.derive(3)
    good = fx.finalized(msg, (0, 1), 3)
    witness = list(good.inputs[0].final_scriptwitness.items)
    smp = signature_from_psbt(good, "smp")
    cases.append(Case("bad-wrong-message", "invalid", msg + b"!", reg, main, smp, "message differs"))
    other_reg, other_main = fx.addresses(4)
    cases.append(Case("bad-wrong-address", "invalid", msg, other_reg, other_main, smp, "signature for index 3 checked against index 4"))
    tampered = list(witness)
    tampered[1] = high_s(tampered[1])
    cases.append(Case("bad-high-s", "invalid", msg, reg, main, encode_simple(tampered), "one signature re-encoded with high S (consensus-valid, policy-invalid)"))
    cases.append(Case("bad-swapped-order", "invalid", msg, reg, main, encode_simple([witness[0], witness[2], witness[1], witness[3]]), "signatures not in key order"))
    cases.append(Case("bad-one-signature", "invalid", msg, reg, main, encode_simple([witness[0], witness[1], witness[3]]), "only one of two required signatures"))
    cases.append(Case("bad-nonempty-dummy", "invalid", msg, reg, main, encode_simple([b"\x00"] + witness[1:]), "NULLDUMMY violated",
                      known={"knots": "Knots' BIP322_REQUIRED_FLAGS omit SCRIPT_VERIFY_NULLDUMMY (BIP147, consensus since segwit), so it accepts a non-empty CHECKMULTISIG dummy"}))
    cases.append(Case("bad-extra-element", "invalid", msg, reg, main, encode_simple([b""] + witness), "extra witness element (CLEANSTACK)"))
    unsigned = fx.unsigned(msg, 3)
    sigs = {}
    for master in fx.masters[:2]:
        sig, pub = sign_with_sighash(unsigned, master, SIGHASH.NONE)
        sigs[pub.sec()] = sig
    ordered = [sigs[pk] for pk in derived.pubkeys if pk in sigs]
    cases.append(Case("bad-sighash-none", "invalid", msg, reg, main, encode_simple([b""] + ordered + [derived.witness_script]), "valid script, but SIGHASH_NONE"))
    txid = build_to_spend(msg, derived.script_pubkey).txid()
    tx = build_to_sign(txid, witness=witness)
    tx.vout[0].value = 1
    cases.append(Case("bad-output-value", "invalid", msg, reg, main, encode_full(tx), "to_sign output value 1"))
    no_prefix = {"knots": "Knots predates the smp/ful/pof prefixes and auto-detects the payload, so a variant mismatch cannot be expressed"}
    cases.append(Case("bad-witness-as-ful", "invalid", msg, reg, main, "ful" + smp[3:], "witness stack with ful prefix", skip=no_prefix))
    cases.append(Case("bad-witness-as-pof", "invalid", msg, reg, main, "pof" + smp[3:], "witness stack with pof prefix", skip=no_prefix))
    cases.append(Case("bad-garbage", "invalid", msg, reg, main, "smp!!!not base64", "not base64"))
    cases.append(Case("bad-empty-witness", "invalid", msg, reg, main, "smpAA==", "empty witness stack"))
    return cases
