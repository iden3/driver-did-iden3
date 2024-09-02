package services

import (
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/iden3/driver-did-iden3/pkg/document"
)

type TypedDataType int32

const (
	IdentityStateType TypedDataType = 0
	GlobalStateType   TypedDataType = 1
)

type EIP712Signer interface {
	Sign(typedData apitypes.TypedData) (*document.EthereumEip712SignatureProof2021, error)
}

type EIP712SignerRegistry map[string]EIP712Signer

func NewChainEIP712Signers() *EIP712SignerRegistry {
	return &EIP712SignerRegistry{}
}

func (ch *EIP712SignerRegistry) Add(prefix string, signer EIP712Signer) {
	(*ch)[prefix] = signer
}

func (ch *EIP712SignerRegistry) Append(prefix string, signer EIP712Signer) error {
	_, ok := (*ch)[prefix]
	if ok {
		return ErrResolverAlreadyExists
	}
	(*ch)[prefix] = signer
	return nil
}

func (ch *EIP712SignerRegistry) GetEIP712SignerByNetwork(chain, networkID string) (EIP712Signer, error) {
	p := resolverPrefix(chain, networkID)
	signer, ok := (*ch)[p]
	if !ok {
		return nil, ErrNetworkIsNotSupported
	}

	return signer, nil
}
