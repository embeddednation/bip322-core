# Changelog

## 0.11.1 (2026-10-06)

First public release.

- BIP-322 (v2.0.0) message signing and verification for descriptor wallets:
  `wsh(sortedmulti(...))` / `wsh(multi(...))` quorums and `wpkh(...)`.
- `bip322 createpsbt`, `combinepsbt`, `finalizepsbt`: the `to_sign` PSBT for
  hardware signers and the finalized proof (`smp`, or `ful` when the BIP
  requires it).
- `bip322 verifymessage`: valid, invalid or inconclusive, for an address or
  a scriptPubKey, with btclib and optionally Bitcoin Core's consensus
  library as script engines.
- `analyzepsbt`, `checksigners`, `decodesignature`, `validateaddress`,
  `deriveaddresses`, `getaddressinfo`, `lint-message`.
- `bip322 NAME ...` runs `bip322-NAME` (git-style extensions).
- `bip322-dev`: test keys and software signing, kept apart from the rest.
- `refcheck/` in the repository cross-checks a corpus against btcd, Bitcoin
  Knots, Bitcoin Core and btclib.
