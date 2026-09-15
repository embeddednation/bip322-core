"""bip322-audit: proof of control of a wallet's coins at a point in time.

Everything that talks to a node lives here (through ``bitcoin-cli``); the
``bip322`` package stays pure and is used as a library:

* ``snapshot``  stamp block, funded addresses, message, one BIP-322 PSBT per address
* ``finalize``  collect the signed PSBTs, finalize, write ``proofs.json``
* ``verify``    BIP-322 verdicts, stamp check, UTXO checks, totals, report
"""

from bip322._version import __version__

TOOL = f"bip322-audit {__version__}"
