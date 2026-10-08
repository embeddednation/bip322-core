# bip322 — BIP-322 message signing for a P2WSH multisig quorum (and P2WPKH)

Tooling and tests for producing and verifying **BIP-322** signatures (spec v2.0.0,
2026-06-04) for a native-segwit `wsh(sortedmulti(k, ...))` wallet whose cosigners are
hardware signers; single-key `wpkh(...)` wallets are supported by the same commands.
It emits the *simple* (`smp`) variant by default, falls back to *full* (`ful`)
when the BIP requires it, and verifies all three variants (`smp`, `ful`, `pof`)
for any address type the interpreters understand (the verifier is not limited
to multisig).

What lives here:

| Part | What it is |
|---|---|
| `bip322core/` | The tool: build the BIP-322 PSBT from a wallet descriptor, combine cosigner PSBTs, finalize, encode, verify. Command `bip322`; distribution `bip322-core`, import `bip322core`. No private keys pass through it. |
| `bip322core/dev/` | Scaffolding that handles private keys: dummy cosigners, wallet assembly, software signing. Command `bip322-dev`. Not needed with hardware cosigners; kept apart so the audited surface stays small. |
| `tests/` | The pytest suite: the official BIP-322 vectors, a full 2-of-3 roundtrip for every signer pair, negatives, CLI. |
| `bip322 NAME ...` | Runs `bip322-NAME ...` found next to the program or on PATH, git style, so the family below is one command: `bip322 audit verify`, `bip322 report --year 2026`, `bip322 dev keygen`. |
| [bip322-audit](https://github.com/embeddednation/bip322-audit) | The proof-of-control workflow (snapshot, finalize, verify) that talks to a node. Its own repository and distribution; depends on this package. |
| [bip322-report](https://github.com/embeddednation/bip322-report) | Balance reports for a period in which every coin is backed by a verified proof from an archive of bip322-audit bundles. Depends on bip322-audit. |
| `refcheck/` | Cross-checks against the reference implementations: btcd's `bip322` package, Bitcoin Knots' `verifymessage`, Bitcoin Core 31.1 as signer/finalizer, and btclib. Command `python -m refcheck.verify_one` (needs the downloaded binaries). |

How the three packages are used together over a year, by the holder and by the auditor, is in bip322-report's [handbook](https://github.com/embeddednation/bip322-report/blob/main/bip322report/handbook.md).

## Install

```sh
git clone https://github.com/embeddednation/bip322-core.git && cd bip322-core
./setup.sh                      # venv, hash-pinned dependencies, editable install, tests
export PATH="$PWD/.venv/bin:$PATH"
```

`setup.sh --with-refcheck` also downloads Bitcoin Core, Bitcoin Knots and Go
and builds the btcd wrapper for the reference checks (about 200 MB, gitignored);
they run from this checkout and are not part of the installed package.
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

## Signing with hardware signers

1. **Describe the wallet.** Put the wallet's output descriptor in a file:
   `wsh(sortedmulti(2,[fp/48h/0h/0h/2h]xpub/<0;1>/*,...))#checksum`.
   Signing devices and wallet software export it for a multisig wallet, and
   Bitcoin Core's `listdescriptors` prints it.
   Check it: `bip322 wallet -w wallet.desc` (policy, cosigners) and
   `bip322 -w wallet.desc deriveaddresses 0 5` (compare with your wallet software).
   The address network follows the key encoding (xpub → mainnet, tpub →
   testnet); `--network regtest` overrides.
   `bip322 getaddressinfo -w wallet.desc bc1q...` shows how a given address
   is built (branch/index, witness script, pubkeys, key paths), in the shape of
   Bitcoin Core's RPC of the same name.

2. **Create the PSBT** for the address and message:

   ```sh
   bip322 -w wallet.desc createpsbt bc1q... "Proof of control, 2026-09-11" --strict-message -o proof.psbt
   ```

   The PSBT is the BIP-322 `to_sign` transaction (version 0, one input with
   sequence 0 spending `to_spend:0`, one zero-value `OP_RETURN` output) plus
   everything a signing device needs: `witness_utxo`, `witness_script`, BIP32
   derivations for all cosigners, `PSBT_IN_SIGHASH_TYPE = ALL`, the global
   xpubs, and `PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE` (0x09) carrying the message.
   `--strict-message` enforces the display rules of hardware signers (2–330 printable
   ASCII characters, newline/tab allowed, no leading/trailing space, no run of
   three spaces). `--utxo both` additionally embeds `to_spend` as
   `non_witness_utxo`, for devices that ask for it.

3. **Sign on as many devices as the threshold asks** (two of a 2-of-3). A
   device that implements BIP-322's *PSBT signer* role recognises the PSBT
   as a message to sign, shows the message and the address it is for, and
   returns a signed PSBT (never a finalized transaction). The multisig
   wallet must be registered on each device; the PSBT carries the wallet's
   global xpubs for devices that can register a wallet from them, and with
   such a setting on, only sign PSBTs you produced yourself, since a
   foreign PSBT could register a foreign wallet.
   Confirmed with real devices. Once a PSBT holds enough
   signatures for the threshold, a further device may refuse it and add
   nothing: sign the original (or a once-signed copy) instead, and
   `combinepsbt` merges whatever came back; the finalizer checks every
   signature present, refuses the PSBT if one of them is bad (`--lenient`
   skips it instead), and uses the first valid ones in script order.

4. **Combine and finalize:**

   ```sh
   bip322 combinepsbt proof-A.psbt proof-B.psbt -o proof-combined.psbt
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
   `--message-file` replace the corresponding positional value. Options may
   stand before, between or after the arguments. A message that starts with
   a dash goes after `--` (`verifymessage ADDR SIG -- "-h"`) or comes from
   `--message-file`; the commands that take a message have no `-h`
   (`bip322 help verifymessage` shows their help), so no message text can
   turn a verdict into "help, exit 0".
   Every installed script engine runs by default (btclib, plus Bitcoin Core's
   interpreter through libbitcoinkernel when `py-bitcoinkernel` is installed;
   `--engines` restricts). Exit codes: 0 *valid*, 1 *invalid*, 3
   *inconclusive*, 2 error; an address that cannot be decoded, an unreadable
   file or any unexpected failure is an error (2), never a verdict.
   A signature string over 100,000 characters or a proof with more than 100
   inputs is *invalid* without being evaluated (`max_signature_bytes` and
   `max_inputs` of `verify_message()` raise the limits). `--json` gives a self-contained report (tool and
   spec version, address, message, signature, variant, `to_spend`/`to_sign`
   txids, locktime/sequence, sighash types, per-engine results with versions).

`bip322 analyzepsbt proof.psbt` applies the BIP's *PSBT signer* detection rules
and shows the message, address, partial signatures and any problems; it also
warns about metadata a hardware signer needs (witness script, key paths) and
flags any sighash type other than ALL.

`bip322 checksigners proof-A.psbt proof-B.psbt proof-C.psbt` is the yearly device health
check and the full explanation of a signed PSBT in one: it combines the
devices' files, rebuilds the script behind the input and shows how it hashes
back to the scriptPubKey and address, verifies each cosigner's signature on its
own, then finalizes and verifies one proof per threshold-sized combination (all
three pairs of a 2-of-3), showing the witness each assembled;
`finalizepsbt --signers ea34d476,7d5dc65a` (master fingerprints) does one chosen
combination by hand.

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
python -m refcheck.verify_one bc1q... "message" --signature-file proof.sig
```

## Walkthrough with dummy keys

`examples/walkthrough.sh` runs the whole flow with three software cosigners
standing in for the hardware signers. Everything that touches a private key is a
`bip322-dev` command; the `bip322` commands are the ones you use for real.
By hand it is:

```sh
for L in A B C; do bip322-dev keygen --label $L --seed "demo cosigner $L" > cosigner-$L.json; done
bip322-dev makewallet -t 2 --name demo-2of3 cosigner-A.json cosigner-B.json cosigner-C.json -o wallet.desc
alias bip322='bip322 --network regtest'          # the demo keys are regtest keys (tpub)
bip322 -w wallet.desc deriveaddresses 0 2        # pick an address
bip322 -w wallet.desc getaddressinfo bcrt1q...    # see how it is built
bip322 -w wallet.desc createpsbt bcrt1q... "demo proof" --strict-message -o proof.psbt
bip322-dev signpsbt proof.psbt   cosigner-A.json -o proof-A.psbt   # signer A
bip322-dev signpsbt proof-A.psbt cosigner-B.json -o proof-AB.psbt  # signer B (or sign proof.psbt separately and `combinepsbt`)
bip322 finalizepsbt proof-AB.psbt -o proof.sig
bip322 verifymessage bcrt1q... "$(cat proof.sig)" "demo proof"
```

`bip322-dev keygen` and `makewallet` work on regtest unless `--network` says
otherwise, and `keygen --seed` refuses `--network main`: a key derived from a
seed text belongs to everyone who knows the text, and the texts above are
published here. The keygen JSON says which kind it is (`"deterministic"`),
and a key file written with `-o` gets mode 0600.

`makewallet` accepts keygen JSON files and `[fp/path]xpub` expressions in any
mix and writes the checksummed descriptor. `bip322-dev signpsbt PSBT KEY...` accepts
keygen JSON files, files containing a key, or key text.
The script also runs three negative checks and `refcheck.verify_one`, which
ends with the verifiers that are installed agreeing (all of them after
`refcheck/fetch.sh` and `refcheck/btcd/build.sh`; the others show as `n/a`).
Artifacts land in a fresh temporary directory, or in the directory you name,
which must not exist yet or be empty: the script never deletes anything.

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
python -m refcheck.verify_one corpus   # the whole corpus (= python -m refcheck.run_refcheck)
python -m refcheck.verify_one ADDR SIG MSG   # one signature, every verifier
```

The corpus is a set of signatures from a deterministic 2-of-3 test wallet on regtest
(every signer pair × 6 messages including empty, UTF-8 and 330-char, `ful`,
version 2, time-locked, `pof`, and invalid and inconclusive cases). Each one is
judged by four verifiers, and Bitcoin Core is used as an independent producer:

| Verifier | Origin |
|---|---|
| ours | `bip322core.verify` with btclib + libbitcoinkernel |
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
  `bip322core.psbt.BIP322PSBT` overrides both. Do not round-trip these PSBTs
  through plain `embit.psbt.PSBT`.
* libbitcoinkernel exposes consensus flags only, so it cannot enforce the
  policy rules BIP-322 requires; it is used as an *additional* check.
* `rust-bitcoin/bip322` was evaluated and not used: it emulates
  `CHECKMULTISIG` instead of running an interpreter and had a critical
  verification bug (GHSA-5chw-87w3-j9cv) until August 2026.

## Layout

```
bip322core/core.py        message hash, to_spend/to_sign, smp/ful/pof encoding
bip322core/engines.py     btclib + libbitcoinkernel runners and the BIP-322 flag sets
bip322core/wallet.py      descriptor parsing, derivation, address lookup
bip322core/psbt.py        PSBT creation, combine, finalize, extract
bip322core/verify.py      the verifier
bip322core/signers.py     signer health: every cosigner, every threshold combination (checksigners)
bip322core/report.py      what the commands print: result dicts and their text form
bip322core/msglint.py     message lint for hardware signers
bip322core/cli.py         bip322 command: the commands and the entry point
bip322core/cli_parser.py  its arguments, options, descriptions and examples
bip322core/cli_help.py    help and help CMD; git-style extensions (bip322 NAME runs bip322-NAME)
bip322core/cli_common.py  shared by both commands: error handling, PSBT and file output, common options
bip322core/dev/signing.py software signing (tests, non-hardware cosigners)
bip322core/dev/keys.py    dummy cosigner generation, wallet assembly from keys
bip322core/dev/cli.py     bip322-dev command (keygen, makewallet, signpsbt)
bip322core/dev/testing.py deterministic test cosigners and tampering helpers (tests and refcheck)
tests/                pytest suite and official vectors
refcheck/             reference harness (fetch.sh, btcd/, run_refcheck.py)
```
