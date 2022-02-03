package services

import (
	"context"
	"errors"
	"log"
	"net"

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

// ResolveDomain return did document by domain via DNS.
func (d *DidDocumentServices) ResolveDomain(ctx context.Context, domain string) (StateVerificationResult, error) {
	// TODO(illia-korotia): move under interface.
	records, err := net.LookupTXT(domain)
	if err != nil {
		log.Printf("failed resolve domain '%s' to did: %s", domain, err)
		return StateVerificationResult{}, err
	}

	if len(records) == 0 {
		log.Printf("text recornds in domain '%s' not found: %s", domain, err)
		return StateVerificationResult{}, err
	}

	var did *core.DID
	// try to find correct did.
	for _, v := range records {
		did, err = core.ParseDID(v)
		if did != nil && err == nil {
			break
		}
	}

	if did == nil || err != nil {
		log.Print("text records do not contain did")
		return StateVerificationResult{}, errors.New("did not found")
	}

	return d.GetDidDocument(ctx, did.ID)
}
