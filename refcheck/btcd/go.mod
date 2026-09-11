module bip322check

go 1.25.0

require (
	github.com/btcsuite/btcd/address/v2 v2.0.0
	github.com/btcsuite/btcd/bip322 v0.0.0-00010101000000-000000000000
	github.com/btcsuite/btcd/chaincfg/v2 v2.0.0
)

require (
	github.com/btcsuite/btcd/btcec/v2 v2.5.0 // indirect
	github.com/btcsuite/btcd/btcutil/v2 v2.0.0 // indirect
	github.com/btcsuite/btcd/chainhash/v2 v2.0.0 // indirect
	github.com/btcsuite/btcd/psbt/v2 v2.0.0 // indirect
	github.com/btcsuite/btcd/txscript/v2 v2.0.0 // indirect
	github.com/btcsuite/btcd/wire/v2 v2.0.0 // indirect
	github.com/btcsuite/btclog v1.0.0 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/kcalvinalvin/anet v0.0.0-20251112173137-d8ddc1f6dbee // indirect
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
)

// The BIP-322 package lives on an unmerged btcd branch (PR #2521) which also
// patches psbt and txscript; refcheck/fetch.sh clones it into refcheck/bin.
replace (
	github.com/btcsuite/btcd/bip322 => ../bin/btcd-src/bip322
	github.com/btcsuite/btcd/psbt/v2 => ../bin/btcd-src/psbt
	github.com/btcsuite/btcd/txscript/v2 => ../bin/btcd-src/txscript
)
