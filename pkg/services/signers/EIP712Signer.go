package signers

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/iden3/driver-did-iden3/pkg/document"
)

const (
	secp256k1VValue = 27
)

type EIP712Signer struct {
	walletKey string
}

func NewEIP712Signer(walletKey string) (*EIP712Signer, error) {
	globalStateSigner := &EIP712Signer{
		walletKey: walletKey,
	}

	return globalStateSigner, nil
}

func (s *EIP712Signer) getWalletAddress() (string, error) {
	if s.walletKey == "" {
		return "", errors.New("wallet key is not set")
	}

	privateKey, err := crypto.HexToECDSA(s.walletKey)
	if err != nil {
		return "", err
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("error casting public key to ECDSA")
	}

	walletAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	return walletAddress.String(), nil
}

func (s *EIP712Signer) Sign(typedData apitypes.TypedData) (*document.EthereumEip712SignatureProof2021, error) {
	privateKey, err := crypto.HexToECDSA(s.walletKey)
	if err != nil {
		return nil, err
	}
	walletAddress, err := s.getWalletAddress()
	if err != nil {
		return nil, err
	}
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return nil, errors.New("error hashing EIP712Domain for signing")
	}
	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return nil, errors.New("error hashing PrimaryType message for signing")
	}
	rawData := []byte(fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash)))
	dataHash := crypto.Keccak256(rawData)

	signature, err := crypto.Sign(dataHash, privateKey)
	if err != nil {
		return nil, err
	}

	if signature[64] < secp256k1VValue { // Invalid Ethereum signature (V is not 27 or 28)
		signature[64] += secp256k1VValue // Transform yellow paper V from 0/1 to 27/28
	}

	messageSignature := "0x" + hex.EncodeToString(signature)

	eip712Proof := &document.EthereumEip712SignatureProof2021{
		Type:               document.EthereumEip712SignatureProof2021Type,
		ProofPursopose:     "assertionMethod",
		ProofValue:         messageSignature,
		VerificationMethod: fmt.Sprintf("did:pkh:eip155:0:%s#blockchainAccountId", walletAddress),
		Eip712:             typedData,
		Created:            time.Now(),
	}

	return eip712Proof, nil
}
