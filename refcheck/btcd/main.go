// btcd-bip322: thin CLI over the btcd BIP-322 reference package (btcsuite/btcd PR #2521).
//
// Reads JSON lines on stdin:
//   {"id":"case-1","network":"regtest","address":"bcrt1q...","message_hex":"...","signature":"smp..."}
// and writes one JSON line per request:
//   {"id":"case-1","valid":true,"error":"","constrained":false,"valid_at_time":0,"valid_at_age":0}
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/bip322"
	"github.com/btcsuite/btcd/chaincfg/v2"
)

type request struct {
	ID         string `json:"id"`
	Network    string `json:"network"`
	Address    string `json:"address"`
	MessageHex string `json:"message_hex"`
	Signature  string `json:"signature"`
}

type response struct {
	ID          string `json:"id"`
	Valid       bool   `json:"valid"`
	Error       string `json:"error,omitempty"`
	Constrained bool   `json:"constrained"`
	ValidAtTime uint32 `json:"valid_at_time"`
	ValidAtAge  uint32 `json:"valid_at_age"`
}

func params(name string) *chaincfg.Params {
	switch name {
	case "regtest":
		return &chaincfg.RegressionNetParams
	case "signet":
		return &chaincfg.SigNetParams
	case "test", "testnet", "testnet3":
		return &chaincfg.TestNet3Params
	default:
		return &chaincfg.MainNetParams
	}
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1<<20), 1<<26)
	enc := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			_ = enc.Encode(response{Error: "bad request: " + err.Error()})
			continue
		}
		resp := response{ID: req.ID}
		msg, err := hex.DecodeString(req.MessageHex)
		if err != nil {
			resp.Error = "bad message hex: " + err.Error()
			_ = enc.Encode(resp)
			continue
		}
		addr, err := address.DecodeAddress(req.Address, params(req.Network))
		if err != nil {
			resp.Error = "address: " + err.Error()
			_ = enc.Encode(resp)
			continue
		}
		valid, tc, err := bip322.VerifyMessage(string(msg), addr, req.Signature)
		resp.Valid = valid
		if err != nil {
			resp.Error = err.Error()
		}
		resp.Constrained = tc.Constrained
		resp.ValidAtTime = tc.ValidAtTime
		resp.ValidAtAge = tc.ValidAtAge
		_ = enc.Encode(resp)
	}
}
