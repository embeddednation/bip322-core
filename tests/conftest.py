import json
import pathlib

import pytest
from embit.bip32 import HDKey

from bip322core.dev.testing import ORIGIN_PATH, key_expression, master_key  # noqa: F401 - re-exported for tests
from bip322core.wallet import MultisigWallet

VECTORS = pathlib.Path(__file__).parent / "vectors"


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
    from bip322core.engines import kernel_available

    return ("btclib", "kernel") if kernel_available() else ("btclib",)
