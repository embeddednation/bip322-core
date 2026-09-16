# Changelog

## 0.3.1 (2026-09-16)

- `bip322-audit finalize`: `proofs.json` no longer carries the wallet
  descriptor (xpubs); `--with-descriptor` includes it. Without it `verify`
  skips the membership check and `--scan` covers the proven addresses only.
- `bip322-audit snapshot` records each output's creating block hash, so
  `verify` confirms spent outputs existed at the snapshot on any node, no
  `-txindex` needed.
- `bip322-audit spends`: the owner records, from the node wallet's history,
  the transaction that spent each snapshot output since; `verify` uses
  `spends.json` to show those outputs were unspent at the snapshot (a spend
  confirmed after the stamp block) and flags a spend at or before it.
- `verify` summary gains `utxos_shown_unspent_at_snapshot`.

## 0.3.0 (2026-09-15)

- `bip322-audit`: the audit workflow (`snapshot`, `finalize`, `verify`, `stamp`).
  Block stamp in the message, coins as of the stamp block from `listunspent`
  or `scantxoutset`, one PSBT per funded address, `proofs.json`, and the
  auditor's verification: signatures, stamp, every output via `gettxout`,
  document consistency, wallet membership, completeness scan (`--scan`).
- `bip322 checksigners`: script chain, every cosigner's signature, every
  threshold combination finalized and verified, from the devices' files.
- `bip322 decodesignature`: a proof opened into its parts, taproot-aware.
- `bip322 finalizepsbt --signers`, `analyzepsbt` per-signer report.
- Confirmed with real Coldcards on a 2-of-3 wallet.
- CI workflow; refcheck no longer imports the test suite.

## 0.2.0 (2026-09-14)

- Descriptor-only wallets (`wsh(multi/sortedmulti)` and `wpkh`), network
  inferred from key versions; `makewallet`, `deriveaddresses`,
  `getaddressinfo`; Bitcoin Core command names and positional arguments.
- Two review passes: canonical-encoding checks, strict DER, PSBT field
  consistency, fail-closed engines, engine versions in reports, exit codes
  0/1/3/2, `requirements.lock` with hashes, `docs/DESIGN.md`.
- Private-key tooling split into `bip322-dev`; reference harness
  `bip322-refcheck` (btcd, Knots, Core, btclib).

## 0.1.0 (2026-09-11)

- First version: BIP-322 v2.0.0 framing, PSBT creation with the 0x09 message
  field, finalizer, verifier with btclib and libbitcoinkernel engines, official
  vectors, 2-of-3 round trips.
