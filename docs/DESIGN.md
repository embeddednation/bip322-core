# bip322 — design notes for reviewers

This document is the map an auditor needs: what the tool trusts, what it
checks, where the rules come from, and where it knowingly differs from other
implementations.

## 1. Scope and trust boundaries

* **Purpose.** Produce and verify BIP-322 proofs ("this quorum controls this
  address") for native-segwit wallets: `wsh(multi/sortedmulti(k, ...))` and
  `wpkh(...)`. Proofs are *not* transactions: `to_spend` has an unspendable
  input, so nothing produced here can move funds.
* **Private keys never enter `bip322core/`.** The `bip322` command only ever sees
  public data: a descriptor (xpubs), an address, a message, PSBTs carrying
  public keys and signatures. Signing happens on the hardware devices, or in
  `bip322core/dev/` (`bip322-dev`), which exists for tests and demos.
* **What a verifier trusts.** The address string, the message bytes and the
  signature string; nothing else. `to_spend` is recomputed from address and
  message, so a proof cannot claim a different message or address than the
  one it was checked against. The verifier has no chain access; for the `pof`
  variant it can verify the signatures over the extra inputs but not that
  those outputs exist or are unspent, and it says so in the result.
* **Third-party code on the verification path.** The script interpreters
  (btclib, and optionally Bitcoin Core's through libbitcoinkernel), the
  address decoder and transaction/PSBT (de)serializers (embit). The BIP-322
  framing itself (`bip322core/core.py`, `bip322core/verify.py`) is this project's
  code and is what the official vectors exercise.

## 2. Data flow

```
descriptor + address + message
        │ createpsbt
        ▼
to_sign PSBT  = tx(version 0, in: to_spend:0 seq 0, out: 0 sat OP_RETURN)
              + witness_utxo (to_spend's output), [non_witness_utxo = to_spend]
              + witness_script (P2WSH), BIP32 derivations, sighash ALL,
              + global xpubs, global 0x09 = message
        │ signers (Coldcards, or bip322-dev signpsbt)   → partial signatures
        │ combinepsbt (only if signed in parallel)
        │ finalizepsbt: check each partial sig, build witness, drop sig metadata
        ▼
signature string:  smp + base64(witness stack)            (native segwit, defaults)
                   ful + base64(to_sign transaction)      (otherwise, one input)
                   pof + base64(finalized PSBT)           (extra inputs)
        │ verifymessage(address, signature, message)
        ▼
valid | invalid | inconclusive  (+ per-engine report)
```

`createpsbt` is BIP-174's *creator* and *updater* in one step; the descriptor
is required only for the updater half (witness script and key paths, which a
P2WSH address does not reveal).

## 3. Verification rules

`verify_message` implements the BIP's "Verification Process" literally:

1. Decode: prefix → variant; no prefix → *simple* (65-byte payload → legacy
   BIP-137, P2PKH only). Payloads must be canonical: a witness stack or
   transaction that re-serializes to different bytes (non-minimal compact
   sizes, superfluous witness marker) is rejected.
2. Shape: input 0 spends `to_spend:0`; exactly one output, 0 sat, `OP_RETURN`;
   `ful` has exactly one input; `pof` is a finalized PSBT with a UTXO for every
   input (same-txid `non_witness_utxo` reuse allowed); no duplicate inputs;
   `smp` only for native segwit addresses.
3. **Required rules** (fail → *invalid*), run with btclib:
   consensus (`P2SH DERSIG NULLDUMMY CLTV CSV WITNESS TAPROOT`) plus
   `STRICTENC LOW_S NULLFAIL MINIMALDATA CLEANSTACK MINIMALIF CONST_SCRIPTCODE`;
   every consumed signature must use `SIGHASH_ALL` (or `DEFAULT` for
   taproot). If the kernel engine is enabled it runs with all consensus flags
   and can only add a rejection.
4. **Upgradeable rules** (fail → *inconclusive*): `to_sign` version 0 or 2;
   btclib again with `DISCOURAGE_UPGRADABLE_NOPS`, `_WITNESS_PROGRAM`,
   `_PUBKEYTYPE`, `_OP_SUCCESS`, `_TAPROOT_VERSION` added.
5. Otherwise *valid*, reporting `nLockTime` and input-0 `nSequence`.

Engines fail closed: an exception inside an interpreter is reported as that
engine failing. Requesting an engine that is not installed is an error, not a
verdict. Every requested engine runs even after the verdict is known so the
report shows the *kind* of failure (e.g. consensus-valid but policy-invalid).

## 4. Finalizer rules

`finalizepsbt` (BIP-174 input finalizer) accepts a partial signature only if
it is strictly DER (BIP-66), low-S, ends in `SIGHASH_ALL`, and verifies
against the input's sighash for the claimed public key. P2WSH witnesses are
built in witness-script key order with the empty `CHECKMULTISIG` dummy; P2WPKH
witnesses are `[signature, pubkey]`. Signature metadata is removed, unknown
(proprietary) fields are kept. It does not verify the proof; that is
`verifymessage`'s job.

## 5. Known divergences between implementations

| Implementation | Divergence from the BIP text | Effect |
|---|---|---|
| Bitcoin Knots `verifymessage` (Core PR #24058 code) | `BIP322_REQUIRED_FLAGS` omit `NULLDUMMY` | accepts a non-empty CHECKMULTISIG dummy; this tool, btcd and btclib reject it |
| Bitcoin Knots | predates the `smp`/`ful`/`pof` prefixes; no `pof` | prefix must be stripped; variant mismatches cannot be expressed |
| btcd `bip322` (reference, vector source) | uses `StandardVerifyFlags`, which include `WITNESS_PUBKEYTYPE` (Core standardness) | an uncompressed key in a segwit script is *invalid* for btcd, *valid* per the BIP and this tool |
| this tool | none intended | follows the BIP's rule list exactly |

## 6. Exit codes and report format

`verifymessage`: 0 valid, 1 invalid, 3 inconclusive, 2 usage or I/O error.
`--json` emits a self-contained report: tool and spec version, address,
message (UTF-8 and hex), signature, variant, `to_spend`/`to_sign` txids,
version/locktime/sequence, sighash types seen, and one entry per engine with
its version and outcome.

## 7. Messages, addresses, networks

* The message is a byte string; the exact bytes matter. `-m` encodes UTF-8,
  `--message-file` uses the file's bytes. No normalisation is applied.
* A proof commits to the scriptPubKey, not to the address encoding: the same
  signature verifies for `bc1q...` and `bcrt1q...` of the same script. The
  wallet's network only selects how addresses are printed; it is inferred from
  the key versions (xpub → main, tpub → test) unless `--network` is given.
* Coldcard displays only 2–330 printable ASCII characters (newline and tab
  allowed, no leading/trailing space, no run of three spaces);
  `createpsbt --strict-coldcard` and `lint-message` enforce that.

## 8. Dependencies and reproducibility

Runtime: embit (descriptors, PSBT, transactions), btclib (script interpreter),
optionally py-bitcoinkernel (Bitcoin Core interpreter). `requirements.lock`
pins exact versions with sha256 hashes; install with
`pip install --require-hashes -r requirements.lock`. embit's stock PSBT class
mangles transaction version 0 and sequence 0 (`or`-defaults); `BIP322PSBT`
overrides both, and a test guards it.

## 9. The audit tool (`bip322audit/`)

Everything chain-facing lives in a separate package with its own command,
`bip322-audit`; a test asserts that `bip322core/` never imports it, nor
`subprocess`, sockets or HTTP. The node is reached only through `bitcoin-cli`,
so the user's node, chain and credentials are what is trusted and the tool
holds none.

* **Stamp.** `block: HEIGHT HASH TIME`, all three from the block `depth`
  behind the tip (default 6). The hash is a *not before* bound; height and
  header time make it readable and checkable with one `getblockheader`. It is
  part of the signed message, never PSBT metadata. It is not replay
  protection: a counterparty wanting freshness supplies a nonce.
* **Snapshot semantics.** The stamp block is the snapshot block; only outputs
  confirmed at or before it are listed, so a bundle means "these coins, at
  that block". Coins come from `listunspent` (a Core wallet with the
  descriptor; its `desc` field gives branch and index) or `scantxoutset`.
* **Proof of funds without `pof`.** One `smp` proof per funded address; the
  auditor establishes the coins from the chain. Nothing signed references a
  real output, so the safety of `pof`'s bogus-input construction is never
  relied on. Outpoints are not repeated in the message (control of the script
  covers every output paying to it).
* **Verdict.** `verify` is OK when every signature is valid, the stamp block
  is in the node's main chain with the claimed height and time, the document
  is consistent (its recorded stamp equals the one inside the signed message,
  `message` and `message_hex` agree), and no listed output is contradicted by
  the node (different amount, address or creation height).
  Outputs no longer in the UTXO set are fetched by the block hash the snapshot
  recorded for their creating transaction (`getrawtransaction TXID true HASH`
  works on any node), which confirms they existed at the snapshot block with
  the claimed amount and address. "Unspent at the snapshot" is then shown by
  the spending transaction: `finalize` records it on the owner's side
  (`listsinceblock` from the stamp block on the node wallet named in
  `snapshot.json`, so no address index anywhere), and `verify` checks that it
  spends the output and was confirmed after the stamp block. Re-running
  `finalize` refreshes the record; the proofs are unchanged. Without it the
  report says existence is shown and unspent-at-snapshot is not; a spend at
  or before the stamp is a contradiction.
* **Addresses, not a wallet.** `proofs.json` carries no descriptor, xpub,
  derivation path or node wallet name. The claim under audit is about control
  of listed coins at a block, and the signatures plus the chain settle it per
  address; that the addresses share a parent key is bookkeeping, and the
  policy is visible in each witness anyway. The xpubs would let the auditor
  derive every address of the wallet, past and future, and a scan of one
  descriptor would suggest a completeness that it cannot establish (nothing
  rules out a second wallet). Completeness comes from the audited party's
  representation and from reconciling spends between snapshots, which the
  recorded spends support. The owner's `snapshot.json` keeps the descriptor
  and the derivation paths.
* **Device health check.** `bip322 checksigners` takes the devices' PSBT files,
  shows the script behind the input and its mapping back to the address,
  verifies each cosigner's signature alone, and finalizes and verifies one
  proof per threshold-sized combination. `decodesignature` opens any proof
  string into labelled witness elements (taproot-aware).

## 10. Test evidence

* `tests/`: 150+ cases including every official BIP-322 vector (basic and
  generated: P2WPKH, P2WSH 2-of-2/3-of-3, P2TR, P2SH-wrapped, time locks,
  proof of funds, 36 error vectors), 2-of-3 round trips for every signer pair,
  P2WPKH round trips that reproduce the BIP's vector signatures byte for byte,
  negatives (wrong message/address, high-S, order, sighash, dummy, extra
  elements, non-canonical encodings, malformed DER), and CLI behaviour.
* `bip322-refcheck corpus`: 46 signatures judged by this tool, btclib, btcd
  and Bitcoin Knots, plus Bitcoin Core 31.1 as an independent producer
  (`deriveaddresses`, `decodepsbt`, `descriptorprocesspsbt`, `finalizepsbt`,
  `signrawtransactionwithkey`); Core's finalized `to_sign` is byte-identical
  to this tool's.
* `tests/test_audit.py` runs the audit workflow against a fake node;
  `tests/test_audit_regtest.py` runs it against a real regtest Bitcoin Core:
  fund the wallet, snapshot from `listunspent` and from `scantxoutset`, sign,
  finalize, verify, spend a coin, verify again.
