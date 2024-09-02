package signers

import (
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	secp256k1VValue = 27
)

type Secp256k1Signer struct {
	walletKey string
}

func NewSecp256k1Signer(walletKey string) (*Secp256k1Signer, error) {
	globalStateSigner := &Secp256k1Signer{
		walletKey: walletKey,
	}

	return globalStateSigner, nil
}

func (s *Secp256k1Signer) Sign(payload []byte) ([]byte, error) {
	privateKey, err := crypto.HexToECDSA(s.walletKey)
	if err != nil {
		return nil, err
	}

	signature, err := crypto.Sign(payload, privateKey)
	if err != nil {
		return nil, err
	}

	if signature[64] < secp256k1VValue { // Invalid Ethereum signature (V is not 27 or 28)
		signature[64] += secp256k1VValue // Transform yellow paper V from 0/1 to 27/28
	}
	return signature, nil
}
