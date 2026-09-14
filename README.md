# bip322 — BIP-322 message signing for a P2WSH multisig quorum

Tooling and tests for producing and verifying **BIP-322** signatures (spec v2.0.0,
2026-06-04) for a native-segwit `wsh(sortedmulti(k, ...))` wallet, with Coldcards as
the cosigners; single-key `wpkh(...)` wallets are supported by the same commands.
It emits the *simple* (`smp`) variant by default, falls back to *full* (`ful`)
when the BIP requires it, and verifies all three variants (`smp`, `ful`, `pof`)
for any address type the interpreters understand (the verifier is not limited
to multisig).

Three independent things live here:

| Part | What it is |
|---|---|
| `bip322/` | The tool: build the BIP-322 PSBT from a wallet descriptor, sign with software keys (tests), combine cosigner PSBTs, finalize, encode, verify. |
| `tests/` | 120 pytest cases: the official BIP-322 vectors, a full 2-of-3 roundtrip for every signer pair, negatives, CLI. |
| `refcheck/` | Cross-checks against the reference implementations: btcd's `bip322` package, Bitcoin Knots' `verifymessage`, Bitcoin Core 31.1 as signer/finalizer, and btclib. |

## Install

```sh
python3 -m venv .venv            # on Ubuntu without python3-venv: python3 -m venv --without-pip .venv && curl -sL https://bootstrap.pypa.io/get-pip.py | .venv/bin/python
.venv/bin/pip install -e '.[kernel,dev]'
.venv/bin/python -m pytest        # 120 tests
```

Dependencies: [embit](https://github.com/diybitcoinhardware/embit) (descriptors, PSBT, keys),
[btclib](https://btclib.org) (script interpreter with the policy flags BIP-322 lists),
optionally [py-bitcoinkernel](https://github.com/stickies-v/py-bitcoinkernel) for a
second, consensus-only pass with Bitcoin Core's own interpreter.

## Signing with the Coldcards

1. **Describe the wallet.** Put the wallet's output descriptor in a file:
   `wsh(sortedmulti(2,[fp/48h/0h/0h/2h]xpub/<0;1>/*,...))#checksum`.
   A Coldcard exports it from the multisig wallet's Export menu, Sparrow shows
   it under wallet settings, and Bitcoin Core's `listdescriptors` prints it.
   Check it: `bip322 wallet -w wallet.desc` (policy, cosigners) and
   `bip322 deriveaddresses -w wallet.desc --range 0 5` (compare with Sparrow).
   `bip322 getaddressinfo -w wallet.desc bc1q...` shows how a given address
   is built (branch/index, witness script, pubkeys, key paths), in the shape of
   Bitcoin Core's RPC of the same name.

2. **Create the PSBT** for the address and message:

   ```sh
   bip322 createpsbt -w wallet.desc -a bc1q... -m "Proof of control, 2026-09-11" -o proof.psbt --strict-coldcard
   ```

   The PSBT is the BIP-322 `to_sign` transaction (version 0, one input with
   sequence 0 spending `to_spend:0`, one zero-value `OP_RETURN` output) plus
   everything a Coldcard needs: `witness_utxo`, `witness_script`, BIP32
   derivations for all cosigners, `PSBT_IN_SIGHASH_TYPE = ALL`, the global
   xpubs, and `PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE` (0x09) carrying the message.
   `--strict-coldcard` enforces Coldcard's display rules (2–330 printable
   ASCII characters, newline/tab allowed, no leading/trailing space, no run of
   three spaces). `--utxo both` additionally embeds `to_spend` as
   `non_witness_utxo`, which Coldcard also accepts.

3. **Sign on two Coldcards** (SD card or USB). Firmware 5.5.1 / 1.4.1Q or later
   recognises the PSBT as a *BIP-322 Message*, shows the message and the
   challenge address, and returns a signed PSBT (never a finalized
   transaction). The multisig wallet must be enrolled on each Coldcard, or
   *Trust PSBT* enabled so it can be imported from the global xpubs.

4. **Combine and finalize:**

   ```sh
   bip322 combinepsbt proof-ccA.psbt proof-ccB.psbt -o proof-combined.psbt
   bip322 finalizepsbt proof-combined.psbt --signature-file proof.sig
   ```

   `finalizepsbt` is the BIP-174 finalizer: it checks every partial signature
   (DER, low-S, SIGHASH_ALL, verifies against the sighash), builds the witness
   in script order and prints `smp...`. Use `--variant ful` to force the full
   encoding. It does not verify the proof; that is `verifymessage`'s job.

5. **Verify** (anyone, anywhere):

   ```sh
   bip322 verifymessage bc1q... smp... "Proof of control, 2026-09-11"
   ```

   Same argument order as Bitcoin Core's RPC (`-a/-s/-m` flags work too).
   Every installed script engine runs by default (btclib, plus Bitcoin Core's
   interpreter through libbitcoinkernel when `py-bitcoinkernel` is installed;
   `--engines` restricts). Exit code 0 = *valid*, 1 = *invalid* or
   *inconclusive*; `--json` gives the details (variant, `to_spend`/`to_sign`
   txids, locktime/sequence, sighash types, per-engine results).

`bip322 analyzepsbt proof.psbt` applies the BIP's *PSBT signer* detection rules
and shows the message, address, partial signatures and any problems.

To check one real signature against every reference implementation at once
(after `refcheck/fetch.sh` and `refcheck/btcd/build.sh`):

```sh
.venv/bin/python -m refcheck.verify_one -a bc1q... -m "message" --signature-file proof.sig
```

## Walkthrough with dummy keys

`examples/walkthrough.sh` runs the whole flow with three software cosigners
standing in for the Coldcards. By hand it is:

```sh
for L in A B C; do bip322 keygen --label $L --seed "demo cosigner $L" > cosigner-$L.json; done
bip322 makewallet -t 2 --name demo-2of3 cosigner-A.json cosigner-B.json cosigner-C.json -o wallet.desc
bip322 deriveaddresses -w wallet.desc --range 0 2        # pick an address
bip322 getaddressinfo -w wallet.desc bc1q...               # see how it is built
bip322 createpsbt -w wallet.desc -a bc1q... -m "demo proof" --strict-coldcard -o proof.psbt
bip322 signpsbt proof.psbt   -k cosigner-A.json -o proof-A.psbt   # "Coldcard A"
bip322 signpsbt proof-A.psbt -k cosigner-B.json -o proof-AB.psbt  # "Coldcard B" (or sign proof.psbt separately and `combinepsbt`)
bip322 finalizepsbt proof-AB.psbt --signature-file proof.sig
bip322 verifymessage bc1q... "$(cat proof.sig)" "demo proof"
```

`makewallet` accepts keygen JSON files and `[fp/path]xpub` expressions in any
mix and writes the checksummed descriptor. `signpsbt -k` accepts a keygen JSON
file, a file containing the key, or the key text itself.
The script also runs three negative checks and `refcheck.verify_one`, which
ends with five independent verifiers agreeing. Artifacts land in `examples/out/`.

## Verification semantics

`verify_message()` implements the BIP's verification process:

* rebuild `to_spend` from (message, address); decode the signature by prefix
  (a prefix-less payload is read as *simple*, a 65-byte one as legacy BIP-137,
  P2PKH only);
* `smp` is accepted only for native segwit addresses; `ful` must have exactly
  one input; `pof` must be a finalized PSBT and supplies the extra prevouts;
* shape checks (input 0 spends `to_spend:0`, exactly one zero-value `OP_RETURN`
  output);
* **required rules** — consensus plus `LOW_S`, `STRICTENC`, `NULLFAIL`,
  `MINIMALDATA`, `CLEANSTACK`, `MINIMALIF`, `CONST_SCRIPTCODE`, run with the
  btclib interpreter; every consumed signature must use `SIGHASH_ALL`
  (or `DEFAULT` for taproot); optionally Bitcoin Core's interpreter via
  libbitcoinkernel with all consensus flags → *invalid* on failure;
* **upgradeable rules** — version must be 0 or 2, and the `DISCOURAGE_*`
  flags → *inconclusive* on failure;
* otherwise *valid*, reporting `nLockTime` and input 0 `nSequence`.

The framing is our own code; only the script interpreters are shared with
third parties. The official vectors (`tests/vectors/`) cover P2WSH 2-of-2 and
3-of-3 in simple and full form plus 36 error cases, all of which pass.

## Reference checks (`refcheck/`)

```sh
refcheck/fetch.sh                      # Core 31.1, Knots 29.4.1, Go 1.27, btcd bip-322 branch → refcheck/bin (gitignored)
refcheck/btcd/build.sh                 # builds refcheck/btcd/btcd-bip322
.venv/bin/python -m refcheck.run_refcheck
```

The corpus is 42 signatures from a deterministic 2-of-3 test wallet on regtest
(every signer pair × 6 messages including empty, UTF-8 and 330-char, `ful`,
version 2, time-locked, `pof`, and 13 invalid/inconclusive cases). Each one is
judged by four verifiers, and Bitcoin Core is used as an independent producer:

| Verifier | Origin |
|---|---|
| ours | `bip322.verify` with btclib + libbitcoinkernel |
| btclib | `btclib.bip322` — independent framing and interpreter |
| btcd | `github.com/btcsuite/btcd/bip322` (PR #2521; the BIP's "complete" reference and vector source) |
| knots | Bitcoin Knots `verifymessage` — the Bitcoin Core PR #24058 code, Core's interpreter |

Bitcoin Core 31.1 checks: descriptor checksum and `deriveaddresses` match our
derivation; `decodepsbt` sees version 0, sequence 0 and the 0x09 global field;
`descriptorprocesspsbt` signs our PSBT and its finalized `to_sign` is
byte-identical to ours; `finalizepsbt` accepts our partial signatures;
`signrawtransactionwithkey` with no keys accepts our witness and rejects a
high-S one.

Result of the last run (2026-09-11): all verifiers agree on every case, with
two documented exceptions for Knots:

* **Knots accepts a non-empty CHECKMULTISIG dummy element.** Its
  `BIP322_REQUIRED_FLAGS` omit `SCRIPT_VERIFY_NULLDUMMY` (BIP147, consensus
  since segwit). btcd, btclib and this tool reject it.
* Knots predates the `smp`/`ful`/`pof` prefixes, so prefix/payload mismatches
  cannot be expressed to it (the prefix is stripped before calling it), and it
  has no proof-of-funds support.

## Notes on the libraries

* embit's stock `PSBT` rebuilds the unsigned transaction with `version or 2`
  and `sequence or 0xffffffff`, which silently corrupts the BIP-322 zeros;
  `bip322.psbt.BIP322PSBT` overrides both. Do not round-trip these PSBTs
  through plain `embit.psbt.PSBT`.
* libbitcoinkernel exposes consensus flags only, so it cannot enforce the
  policy rules BIP-322 requires; it is used as an *additional* check.
* `rust-bitcoin/bip322` was evaluated and not used: it emulates
  `CHECKMULTISIG` instead of running an interpreter and had a critical
  verification bug (GHSA-5chw-87w3-j9cv) until August 2026.

## Layout

```
bip322/core.py      message hash, to_spend/to_sign, smp/ful/pof encoding
bip322/engines.py   btclib + libbitcoinkernel runners and the BIP-322 flag sets
bip322/wallet.py    descriptor parsing, derivation, address lookup, makewallet helpers
bip322/psbt.py      PSBT creation, software signing, combine, finalize, extract
bip322/verify.py    the verifier
bip322/coldcard.py  Coldcard message lint
bip322/cli.py       bip322 command
tests/                pytest suite and official vectors
refcheck/             reference harness (fetch.sh, btcd/, run_refcheck.py)
```
