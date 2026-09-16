# bip322 — BIP-322 message signing for a P2WSH multisig quorum (and P2WPKH)

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
| `bip322/` | The tool: build the BIP-322 PSBT from a wallet descriptor, combine cosigner PSBTs, finalize, encode, verify. Command `bip322`. No private keys pass through it. |
| `bip322/dev/` | Scaffolding that handles private keys: dummy cosigners, wallet assembly, software signing. Command `bip322-dev`. Not needed with hardware cosigners; kept apart so the audited surface stays small. |
| `tests/` | 120 pytest cases: the official BIP-322 vectors, a full 2-of-3 roundtrip for every signer pair, negatives, CLI. |
| `bip322audit/` | The audit workflow: proof of control of a wallet's coins at a point in time. Stamp block, coins from the node, one PSBT per funded address, finalize, and the auditor's verification (signatures, stamp, every output). Command `bip322-audit`; the only package that talks to a node, through `bitcoin-cli`. |
| `refcheck/` | Cross-checks against the reference implementations: btcd's `bip322` package, Bitcoin Knots' `verifymessage`, Bitcoin Core 31.1 as signer/finalizer, and btclib. Command `bip322-refcheck` (needs the downloaded binaries). |

## Install

```sh
git clone git@github.com:embeddednation/bip322.git && cd bip322
./setup.sh                      # venv, hash-pinned dependencies, editable install, tests
export PATH="$PWD/.venv/bin:$PATH"
```

`setup.sh --with-refcheck` also downloads Bitcoin Core, Bitcoin Knots and Go
and builds the btcd wrapper for `bip322-refcheck` (about 200 MB, gitignored).
The script handles a `python3` without `ensurepip` (Debian/Ubuntu) and
installs without the libbitcoinkernel engine on platforms the pinned wheel is
not built for.

Dependencies: [embit](https://github.com/diybitcoinhardware/embit) (descriptors, PSBT, keys),
[btclib](https://btclib.org) (script interpreter with the policy flags BIP-322 lists),
optionally [py-bitcoinkernel](https://github.com/stickies-v/py-bitcoinkernel) for a
second, consensus-only pass with Bitcoin Core's own interpreter. `requirements.lock`
pins them with sha256 hashes to the versions the test suite and reference checks
were run against. `docs/DESIGN.md` is the reviewer's map: trust boundaries, data
flow, the exact rule sets, known divergences between implementations, exit codes.

## Signing with the Coldcards

1. **Describe the wallet.** Put the wallet's output descriptor in a file:
   `wsh(sortedmulti(2,[fp/48h/0h/0h/2h]xpub/<0;1>/*,...))#checksum`.
   A Coldcard exports it from the multisig wallet's Export menu, Sparrow shows
   it under wallet settings, and Bitcoin Core's `listdescriptors` prints it.
   Check it: `bip322 wallet -w wallet.desc` (policy, cosigners) and
   `bip322 -w wallet.desc deriveaddresses 0 5` (compare with Sparrow).
   The address network follows the key encoding (xpub → mainnet, tpub →
   testnet); `--network regtest` overrides.
   `bip322 getaddressinfo -w wallet.desc bc1q...` shows how a given address
   is built (branch/index, witness script, pubkeys, key paths), in the shape of
   Bitcoin Core's RPC of the same name.

2. **Create the PSBT** for the address and message:

   ```sh
   bip322 -w wallet.desc createpsbt bc1q... "Proof of control, 2026-09-11" --strict-coldcard -o proof.psbt
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
   The PSBT carries the wallet's global xpubs so a device with *Trust PSBT*
   can import the wallet; with that setting on, only sign PSBTs you produced
   yourself, since a foreign PSBT could enrol a foreign wallet.
   Confirmed with real devices (2026-09-15). Once a PSBT holds enough
   signatures for the threshold, a further Coldcard reports "not our key"
   and adds nothing: sign the original (or a once-signed copy) instead, and
   `combinepsbt` merges whatever came back; the finalizer uses the first
   valid signatures in script order and ignores extras.

4. **Combine and finalize:**

   ```sh
   bip322 combinepsbt proof-ccA.psbt proof-ccB.psbt -o proof-combined.psbt
   bip322 finalizepsbt proof-combined.psbt -o proof.sig
   ```

   `finalizepsbt` is the BIP-174 finalizer: it checks every partial signature
   (DER, low-S, SIGHASH_ALL, verifies against the sighash), builds the witness
   in script order and prints `smp...`. Use `--variant ful` to force the full
   encoding. It does not verify the proof; that is `verifymessage`'s job.

5. **Verify** (anyone, anywhere):

   ```sh
   bip322 verifymessage bc1q... smp... "Proof of control, 2026-09-11"
   ```

   Same argument order as Bitcoin Core's RPC; `--signature-file` /
   `--message-file` replace the corresponding positional value.
   Every installed script engine runs by default (btclib, plus Bitcoin Core's
   interpreter through libbitcoinkernel when `py-bitcoinkernel` is installed;
   `--engines` restricts). Exit codes: 0 *valid*, 1 *invalid*, 3
   *inconclusive*, 2 error. `--json` gives a self-contained report (tool and
   spec version, address, message, signature, variant, `to_spend`/`to_sign`
   txids, locktime/sequence, sighash types, per-engine results with versions).

`bip322 analyzepsbt proof.psbt` applies the BIP's *PSBT signer* detection rules
and shows the message, address, partial signatures and any problems; it also
warns about metadata a hardware signer needs (witness script, key paths) and
flags any sighash type other than ALL.

`bip322 checksigners ccA.psbt ccB.psbt ccC.psbt` is the yearly device health
check and the full explanation of a signed PSBT in one: it combines the
devices' files, rebuilds the script behind the input and shows how it hashes
back to the scriptPubKey and address, verifies each cosigner's signature on its
own, then finalizes and verifies one proof per threshold-sized combination (all
three pairs of a 2-of-3), showing the witness each assembled;
`finalizepsbt --signers A,B` does one chosen combination by hand.

`bip322 help` lists every command with its argument signature, grouped as in
`bitcoin-cli help`; `bip322 help <command>` shows the arguments, options and
examples of one command (`bip322-dev help` likewise).

Output convention for every command: stdout carries exactly the artifact (a
PSBT, a signature, a descriptor, a JSON report), so `> file` always works;
`-o FILE` writes the same artifact to a file and leaves stdout empty; progress
and summaries go to stderr.

To check one real signature against every reference implementation at once
(after `refcheck/fetch.sh` and `refcheck/btcd/build.sh`):

```sh
bip322-refcheck bc1q... "message" --signature-file proof.sig
```

## Walkthrough with dummy keys

`examples/walkthrough.sh` runs the whole flow with three software cosigners
standing in for the Coldcards. Everything that touches a private key is a
`bip322-dev` command; the `bip322` commands are the ones you use for real.
By hand it is:

```sh
for L in A B C; do bip322-dev keygen --label $L --seed "demo cosigner $L" > cosigner-$L.json; done
bip322-dev makewallet -t 2 --name demo-2of3 cosigner-A.json cosigner-B.json cosigner-C.json -o wallet.desc
bip322 -w wallet.desc deriveaddresses 0 2        # pick an address
bip322 -w wallet.desc getaddressinfo bc1q...      # see how it is built
bip322 -w wallet.desc createpsbt bc1q... "demo proof" --strict-coldcard -o proof.psbt
bip322-dev signpsbt proof.psbt   cosigner-A.json -o proof-A.psbt   # "Coldcard A"
bip322-dev signpsbt proof-A.psbt cosigner-B.json -o proof-AB.psbt  # "Coldcard B" (or sign proof.psbt separately and `combinepsbt`)
bip322 finalizepsbt proof-AB.psbt -o proof.sig
bip322 verifymessage bc1q... "$(cat proof.sig)" "demo proof"
```

`makewallet` accepts keygen JSON files and `[fp/path]xpub` expressions in any
mix and writes the checksummed descriptor. `bip322-dev signpsbt PSBT KEY...` accepts
keygen JSON files, files containing a key, or key text.
The script also runs three negative checks and `refcheck.verify_one`, which
ends with five independent verifiers agreeing. Artifacts land in `examples/out/`.

## Audit workflow (`bip322-audit`)

For "we controlled these coins as of block N", repeatable whenever coins move:

```sh
bip322-audit -w treasury snapshot --text "Annual audit {date}"      # the node wallet's own descriptor
#   -> snapshot-2026-09-14-912345/: snapshot.json, message.txt, to_sign/to_sign-01.psbt ... one per funded address
#   sign every PSBT on two Coldcards, put the results into snapshot-.../signed/
bip322-audit finalize snapshot-2026-09-14-912345           # -> proofs.json (hand this to the auditor)
bip322-audit verify snapshot-2026-09-14-912345 --report audit-report.json
```

`finalize` also asks the node wallet the coins came from (recorded in
`snapshot.json`) which listed outputs have been spent since, and records the
spending transactions in `proofs.json`. If coins move between the snapshot and
the audit, re-run `finalize` before handing `proofs.json` over; the proofs
themselves do not change. `--offline` skips that step.

`snapshot` reads the wallet's descriptor from the node wallet (`-w NAME`,
`listdescriptors`; `--descriptor FILE` overrides and is cross-checked against
the node), takes the block six behind the tip (`--depth`) as the stamp *and*
the snapshot height: the message ends with `block: HEIGHT HASH TIME` taken
from that block, and only outputs confirmed at that block are listed. Coins
come from `listunspent` on the node wallet (the only one loaded, or `-w NAME`)
or, when the node has no wallet, from a
`scantxoutset` of the descriptor (minutes on mainnet; the command says so
before it starts; `--source` forces either). The template accepts
`{date}`, `{time}`, `{height}`, `{hash}`, and is checked against Coldcard's
message rules.

`proofs.json` names addresses, not a wallet: the message, the stamp, and per
address the proof and its outputs, plus the policy string (`2 of 3`). No
descriptor, no xpubs, no derivation paths and no node wallet name go in. The
proofs stand per address, and the xpubs would let the auditor derive every
address of the wallet, past and future, which no check of the claim needs.
`snapshot.json`, the owner's copy, keeps all of it.

`verify` re-checks everything on the auditor's node: each BIP-322 signature,
the stamp block (`getblockheader`: height, time, in main chain), that the
document is consistent with the signed message, and each listed output.
An output still unspent is checked with `gettxout` (amount, address,
creation height at or before the stamp), which also shows it was unspent at
the stamp. An output spent since is fetched by the block hash the snapshot
recorded (no `-txindex` needed): that shows it existed at the stamp with the
claimed amount and address. Whether it was still *unspent* at the stamp needs
the spending transaction, which only an address index or the owner's wallet
knows; `finalize` records it in `proofs.json` from the node wallet's history
(`listsinceblock` from the stamp block), and `verify` checks that it really
spends the output and was confirmed after the stamp block. A spend at or
before the stamp is a contradiction. The result is OK
when the signatures and the stamp check out, the document is consistent, and
the node contradicts nothing; coins spent since the snapshot are reported,
not failures. `--offline` verifies signatures only.

Completeness (that the listed addresses are all the holdings in scope) is not
something a key or a scan can establish, since nothing rules out a second
wallet. It comes from the audited party's representation and from
reconciling one year's spends to the next year's proofs, which the recorded
spends make possible.

`examples/audit_walkthrough.sh` runs the whole thing on a throwaway regtest
node, including spending a coin after the snapshot.

## Verification semantics

`verify_message()` implements the BIP's verification process:

* rebuild `to_spend` from (message, address); decode the signature by prefix
  (a prefix-less payload is read as *simple*, a 65-byte one as legacy BIP-137,
  P2PKH only); payloads must be canonically encoded (non-minimal compact sizes
  or a superfluous witness marker are rejected, as Core does);
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

Engines fail closed: an exception inside an interpreter is reported as that
engine failing, never as a pass, and asking for an engine that is not installed
is an error rather than a verdict.

The framing is our own code; only the script interpreters are shared with
third parties. The official vectors (`tests/vectors/`) cover P2WSH 2-of-2 and
3-of-3 in simple and full form plus 36 error cases, all of which pass.

## Reference checks (`refcheck/`)

```sh
refcheck/fetch.sh                      # Core 31.1, Knots 29.4.1, Go 1.27, btcd bip-322 branch → refcheck/bin (gitignored)
refcheck/btcd/build.sh                 # builds refcheck/btcd/btcd-bip322
bip322-refcheck corpus                 # = python -m refcheck.run_refcheck
bip322-refcheck ADDR SIG MSG            # one signature, five verifiers
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
bip322/core.py        message hash, to_spend/to_sign, smp/ful/pof encoding
bip322/engines.py     btclib + libbitcoinkernel runners and the BIP-322 flag sets
bip322/wallet.py      descriptor parsing, derivation, address lookup
bip322/psbt.py        PSBT creation, combine, finalize, extract
bip322/verify.py      the verifier
bip322/coldcard.py    Coldcard message lint
bip322/cli.py         bip322 command
bip322/dev/signing.py software signing (tests, non-hardware cosigners)
bip322/dev/keys.py    dummy cosigner generation, wallet assembly from keys
bip322/dev/cli.py     bip322-dev command (keygen, makewallet, signpsbt)
bip322/dev/testing.py deterministic test cosigners and tampering helpers (tests and refcheck)
bip322audit/          bip322-audit: rpc.py (bitcoin-cli), stamp.py, snapshot.py, audit.py, cli.py
tests/                pytest suite and official vectors
refcheck/             reference harness (fetch.sh, btcd/, run_refcheck.py)
```
