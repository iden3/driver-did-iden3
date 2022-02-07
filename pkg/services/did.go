package services

import (
	"context"
	"log"
	"net"

	"github.com/iden3/driver-did-iden3/pkg/services/blockchain/eth"
	"github.com/iden3/driver-did-iden3/pkg/services/ens"
	core "github.com/iden3/go-iden3-core"
	"github.com/pkg/errors"
)

const (
	ensResolverKey = "description"
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
	ens   *ens.Registry
}

func NewDidDocumentServices(c *eth.StateContract, registry *ens.Registry) *DidDocumentServices {
	return &DidDocumentServices{c, registry}
}

// GetDidDocument return did document by identifier.
func (d *DidDocumentServices) GetDidDocument(ctx context.Context, id core.ID) (StateVerificationResult, error) {
	// Try get state by did from smart contract.
	state, err := d.store.GetStateByID(ctx, nil, id.BigInt())
	if err != nil {
		return StateVerificationResult{}, errors.Errorf("failed get did document by id '%s' from store: %s", id.String(), err)
	}

	// The smart contract was called successfully, but state was not found.
	if state.Int64() == 0 {
		return StateVerificationResult{}, nil
	}

	return StateVerificationResult{Latest: true, State: state.String()}, nil
}

// ResolveDNSDomain return did document by domain via DNS.
func (d *DidDocumentServices) ResolveDNSDomain(ctx context.Context, domain string) (StateVerificationResult, error) {
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

// ResolveENSDomain return did document via ENS resolver.
func (d *DidDocumentServices) ResolveENSDomain(ctx context.Context, domain string) (StateVerificationResult, error) {
	res, err := d.ens.Resolver(domain)
	if err != nil {
		return StateVerificationResult{}, err
	}

	did, err := res.Text(ensResolverKey)
	if err != nil {
		return StateVerificationResult{}, err
	}

	rawDID, err := core.ParseDID(did)
	if err != nil {
		log.Print("invalid did format", err)
		return StateVerificationResult{}, err
	}

	return d.GetDidDocument(ctx, rawDID.ID)
}
