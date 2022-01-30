package services

import (
	"context"
	"log"
	"math/big"

	"github.com/iden3/driver-did-iden3/pkg/services/blockchain/eth"
	core "github.com/iden3/go-iden3-core"
)

type DidDocumentServices struct {
	// TODO(illia-korotia): refactor to interface.
	store *eth.StateContract
}

func NewDidDocumentServices(c *eth.StateContract) *DidDocumentServices {
	return &DidDocumentServices{c}
}

// GetDidDocument return did document by identifier.
func (d *DidDocumentServices) GetDidDocument(ctx context.Context, id core.ID) (*big.Int, error) {
	// Try get state by did from eth contract
	state, err := d.store.GetStateByID(nil, id.BigInt())
	if err != nil {
		log.Printf("failed get did document by id '%s' from store", id.String())
		return nil, err
	}

	return state, nil
}
