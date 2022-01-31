package services

import (
	"context"
	"log"

	"github.com/iden3/driver-did-iden3/pkg/services/blockchain/eth"
	core "github.com/iden3/go-iden3-core"
)

// StateVerificationResult can be the state verification result.
type StateVerificationResult struct {
	State               string `json:"state"`
	Latest              bool   `json:"latest"`
	TransitionTimestamp int64  `json:"transition_timestamp"`
}

type DidDocumentServices struct {
	// TODO(illia-korotia): refactor to interface.
	store *eth.StateContract
}

func NewDidDocumentServices(c *eth.StateContract) *DidDocumentServices {
	return &DidDocumentServices{c}
}

// GetDidDocument return did document by identifier.
func (d *DidDocumentServices) GetDidDocument(ctx context.Context, id core.ID) (StateVerificationResult, error) {
	// Try get state by did from smart contract.
	state, err := d.store.GetStateByID(ctx, nil, id.BigInt())
	if err != nil {
		log.Printf("failed get did document by id '%s' from store", id.String())
		return StateVerificationResult{}, err
	}

	// The smart contract was called successfully, but state was not found.
	if state.Int64() == 0 {
		return StateVerificationResult{}, nil
	}

	return StateVerificationResult{Latest: true, State: state.String()}, nil
}
