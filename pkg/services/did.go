package services

import (
	"context"
	"fmt"
	"net"

	"github.com/iden3/driver-did-iden3/pkg/document"
	"github.com/iden3/driver-did-iden3/pkg/services/ens"
	core "github.com/iden3/go-iden3-core"
	"github.com/pkg/errors"
)

const (
	ensResolverKey = "description"
)

type DidDocumentServices struct {
	resolvers *ChainResolvers
	ens       *ens.Registry
}

func NewDidDocumentServices(resolvers *ChainResolvers, registry *ens.Registry) *DidDocumentServices {
	return &DidDocumentServices{resolvers, registry}
}

// GetDidDocument return did document by identifier.
func (d *DidDocumentServices) GetDidDocument(ctx context.Context, did string) (*document.DidResolution, error) {
	userDID, err := core.ParseDID(did)
	if err != nil {
		return nil, err
	}

	resolver, err := d.resolvers.GetResolverByDID(userDID)
	if err != nil {
		return nil, err
	}

	identityState, err := resolver.Resolve(ctx, &userDID.ID)
	if err != nil {
		return nil, err
	}

	didResolution := document.NewDidResolution()
	didResolution.DidDocument.ID = did
	didResolution.DidDocumentMetadata.IdentityState = *identityState

	return didResolution, nil
}

// ResolveDNSDomain return did document by domain via DNS.
func (d *DidDocumentServices) ResolveDNSDomain(ctx context.Context, domain string) (*document.DidResolution, error) {
	domain = fmt.Sprintf("_did.%s", domain)
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
	for _, v = range records {
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
func (d *DidDocumentServices) ResolveENSDomain(ctx context.Context, domain string) (*document.DidResolution, error) {
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
