import hashlib
import json
import pathlib

import pytest
from embit.bip32 import HDKey

from bip322.wallet import MultisigWallet

VECTORS = pathlib.Path(__file__).parent / "vectors"
ORIGIN_PATH = "48h/0h/0h/2h"


def master_key(label: str) -> HDKey:
    seed = hashlib.sha256(f"bip322-test-cosigner-{label}".encode()).digest()
    seed += hashlib.sha256(label.encode()).digest()
    return HDKey.from_seed(seed)


def key_expression(master: HDKey, private: bool = False, branches: str = "<0;1>") -> str:
    account = master.derive("m/" + ORIGIN_PATH)
    key = account if private else account.to_public()
    return f"[{master.my_fingerprint.hex()}/{ORIGIN_PATH}]{key.to_base58()}/{branches}/*"


def load_vectors(name: str) -> dict:
    return json.loads((VECTORS / name).read_text())


@pytest.fixture(scope="session")
def masters() -> list[HDKey]:
    return [master_key(label) for label in "ABC"]


@pytest.fixture(scope="session")
def descriptor_text(masters) -> str:
    return "wsh(sortedmulti(2," + ",".join(key_expression(m) for m in masters) + "))"


@pytest.fixture(scope="session")
def wallet(descriptor_text) -> MultisigWallet:
    return MultisigWallet.from_descriptor(descriptor_text, network="main", name="test-2of3")


@pytest.fixture(scope="session")
def signer_expressions(masters) -> list[str]:
    """``[fp/48h/0h/0h/2h]xprv.../<0;1>/*`` for each cosigner (account-level private keys)."""
    return [key_expression(m, private=True) for m in masters]


@pytest.fixture(scope="session")
def kernel_engines() -> tuple[str, ...]:
    from bip322.engines import kernel_available

    return ("btclib", "kernel") if kernel_available() else ("btclib",)
