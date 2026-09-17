# Changelog

## 0.6.0 (2026-09-17)

- `bip322 NAME ...` runs `bip322-NAME ...`, git style: `bip322 audit verify`,
  `bip322 reports report`, `bip322 dev keygen`. The core looks the program
  up next to itself or on PATH and hands the process over; nothing comes
  back, so it still never reads another program's output. `bip322 help`
  lists the extensions it finds; `bip322 help NAME` forwards to them.

## 0.5.1 (2026-09-17)

- `help COMMAND` expands argparse placeholders such as `%(default)s` in option help.

## 0.5.0 (2026-09-16)

- The audit workflow moved to its own repository and distribution,
  `bip322-audit` (https://github.com/embeddednation/bip322-audit), which
  depends on this package. `bip322-core` no longer ships the `bip322audit`
  package or the `bip322-audit` command. Its changelog continues there.

## 0.4.0 (2026-09-16)

- The import package is now `bip322core` and the distribution `bip322-core`;
  the PyPI name `bip322` belongs to an unrelated verify-only wrapper of the
  Rust crate. Commands are unchanged: `bip322`, `bip322-dev`, `bip322-audit`,
  `bip322-refcheck`. Tool strings in JSON output read `bip322-core <version>`
  and `bip322-audit <version>`.
- MIT licence.
- `bip322-audit`: `proofs.json` names addresses, not a wallet. The descriptor
  (xpubs), derivation paths, node wallet name and coin source stay in the
  owner's `snapshot.json`; the `--with-descriptor` flag is gone. `verify` has
  no membership check; `--scan` and the holdings block are gone (`gettxout`
  already covers every listed output, and the verifier needs no wallet).
- `bip322-audit finalize` records, from the node wallet's history (the wallet
  is remembered in `snapshot.json`), the transaction that spent each snapshot
  output since; `verify` uses it to show those outputs were unspent at the
  snapshot (a spend confirmed after the stamp block) and flags a spend at or
  before it. Re-run `finalize` to refresh; `--offline` skips the node. The
  separate `spends` command and `spends.json` are gone.
- Bundle layout: the PSBTs to sign live in `to_sign/`, signed ones in `signed/`.
- `verify` ends with an aligned checklist instead of one long line.
- `bip322core.cli.emit` is public (used by the audit CLI and `bip322-dev`).

## 0.3.1 (2026-09-16)

- `bip322-audit finalize`: `proofs.json` no longer carries the wallet
  descriptor (xpubs) unless `--with-descriptor` is given.
- `bip322-audit snapshot` records each output's creating block hash, so
  `verify` confirms spent outputs existed at the snapshot on any node, no
  `-txindex` needed.
- `bip322-audit spends`: the owner records, from the node wallet's history,
  the transaction that spent each snapshot output since; `verify` reads
  `spends.json` to show those outputs were unspent at the snapshot.
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
