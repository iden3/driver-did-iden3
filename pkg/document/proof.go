package document

import (
	"time"

	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/iden3/go-schema-processor/v2/verifiable"
)

type DidResolutionProof interface {
	ProofType() verifiable.ProofType
}

type DidResolutionProofs []DidResolutionProof

type EthereumEip712SignatureProof2021 struct {
	Type               verifiable.ProofType `json:"type"`
	ProofPurpose       string               `json:"proofPurpose"`
	ProofValue         string               `json:"proofValue"`
	VerificationMethod string               `json:"verificationMethod"`
	Created            time.Time            `json:"created"`
	Eip712             apitypes.TypedData   `json:"eip712"`
}

// EthereumEip712SignatureProof2021Type is a proof type for EIP172 signature proofs
// nolint:stylecheck // we need to keep the name as it is
const EthereumEip712SignatureProof2021Type verifiable.ProofType = "EthereumEip712Signature2021"

func (p *EthereumEip712SignatureProof2021) ProofType() verifiable.ProofType {
	return p.Type
}
