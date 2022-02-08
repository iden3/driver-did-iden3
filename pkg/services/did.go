package services

import (
	"context"
	"fmt"
	"net"

	"github.com/iden3/driver-did-iden3/pkg/services/blockchain/eth"
	"github.com/iden3/driver-did-iden3/pkg/services/ens"
	core "github.com/iden3/go-iden3-core"
	"github.com/pkg/errors"
)

const (
	ensResolverKey = "description"
)

// DidResolution representation of did document.
// TODO(illia-korotia): create package like 'Did builder'.
type DidResolution struct {
	Context     string `json:"@context"`
	DidDocument struct {
		Context []string `json:"@context"`
		ID      string   `json:"id"`
	} `json:"didDocument"`
	// should exist in responses, but can be empty.
	// https://www.w3.org/TR/did-core/#did-resolution
	DidResolutionMetadata struct {
	} `json:"didResolutionMetadata"`
	DidDocumentMetadata StateVerificationResult `json:"didDocumentMetadata"`
}

// NewDidResolution create did document with default values.
func NewDidResolution(did *core.DID, state StateVerificationResult) *DidResolution {
	return &DidResolution{
		Context: "https://w3id.org/did-resolution/v1",
		DidDocument: struct {
			Context []string `json:"@context"`
			ID      string   `json:"id"`
		}{
			Context: []string{"https://www.w3.org/ns/did/v1"},
			ID:      did.String(),
		},
		DidDocumentMetadata: state,
	}
}

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
func (d *DidDocumentServices) GetDidDocument(ctx context.Context, did string) (*DidResolution, error) {
	rawDID, err := core.ParseDID(did)
	if err != nil {
		return nil, err
	}

	// Try get state by did from smart contract.
	state, err := d.store.GetStateByID(ctx, nil, rawDID.ID.BigInt())
	if err != nil {
		return nil, fmt.Errorf("failed get did document by id '%s' from store: %s", rawDID.ID.String(), err)
	}

	// The smart contract was called successfully, but state was not found.
	if state.Int64() == 0 {
		return NewDidResolution(rawDID, StateVerificationResult{}), nil
	}

	return NewDidResolution(rawDID, StateVerificationResult{Latest: true, State: state.String()}), nil
}

// ResolveDNSDomain return did document by domain via DNS.
func (d *DidDocumentServices) ResolveDNSDomain(ctx context.Context, domain string) (*DidResolution, error) {
	// TODO(illia-korotia): move under interface.
	records, err := net.LookupTXT(domain)
	if err != nil {
		return nil, errors.Wrapf(err, "failed lookup domain '%s'", domain)
	}

	if len(records) == 0 {
		return nil, errors.Errorf("domain '%s' doesn't contain text fields", domain)
	}

	var (
		did *core.DID
		v   string
	)
	// try to find correct did.
	for _, v := range records {
		did, err = core.ParseDID(v)
		if did != nil && err == nil {
			break
		}
	}

	if err != nil {
		return nil, err
	}

	if did == nil {
		return nil, errors.Errorf("did not found for domain '%s'", domain)
	}

	return d.GetDidDocument(ctx, v)
}

// ResolveENSDomain return did document via ENS resolver.
func (d *DidDocumentServices) ResolveENSDomain(ctx context.Context, domain string) (*DidResolution, error) {
	res, err := d.ens.Resolver(domain)
	if err != nil {
		return nil, err
	}

	did, err := res.Text(ensResolverKey)
	if err != nil {
		return nil, err
	}

	return d.GetDidDocument(ctx, did)
}
