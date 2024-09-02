package services

import (
	"github.com/iden3/driver-did-iden3/pkg/document"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-schema-processor/v2/verifiable"
)

type StateType int32

const (
	IdentityStateType StateType = 0
	GlobalStateType   StateType = 1
)

type DIDResolutionProver interface {
	Prove(did w3c.DID, info IdentityState, dataType StateType) (document.DidResolutionProof, error)
}

type DIDResolutionProverRegistry map[verifiable.ProofType]DIDResolutionProver

func NewDIDResolutionProverRegistry() *DIDResolutionProverRegistry {
	return &DIDResolutionProverRegistry{}
}

func (ch *DIDResolutionProverRegistry) Add(proofType verifiable.ProofType, prover DIDResolutionProver) {
	(*ch)[proofType] = prover
}

func (ch *DIDResolutionProverRegistry) Append(proofType verifiable.ProofType, prover DIDResolutionProver) error {
	_, ok := (*ch)[proofType]
	if ok {
		return ErrResolverAlreadyExists
	}
	(*ch)[proofType] = prover
	return nil
}

func (ch *DIDResolutionProverRegistry) GetDIDResolutionProverByProofType(proofType verifiable.ProofType) (DIDResolutionProver, error) {
	signer, ok := (*ch)[proofType]
	if !ok {
		return nil, ErrProofTypeIsNotSupported
	}

	return signer, nil
}
