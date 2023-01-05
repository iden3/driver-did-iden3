package services

import (
	"context"
	"fmt"

	"github.com/iden3/driver-did-iden3/pkg/document"
	core "github.com/iden3/go-iden3-core"
	"github.com/pkg/errors"
)

var (
	ErrResolverAlreadyExists = errors.New("resolver already exists")
)

type Resolver interface {
	Resolve(ctx context.Context, id *core.ID) (*document.IdentityState, error)
}

type ChainResolvers map[string]Resolver

func NewChainResolvers() *ChainResolvers {
	return &ChainResolvers{}
}

func (ch *ChainResolvers) Add(prefix string, resolver Resolver) {
	(*ch)[prefix] = resolver
}

func (ch *ChainResolvers) Append(prefix string, resolver Resolver) error {
	_, ok := (*ch)[prefix]
	if ok {
		return ErrResolverAlreadyExists
	}
	(*ch)[prefix] = resolver
	return nil
}

func (ch *ChainResolvers) GetResolverByDID(did *core.DID) (Resolver, error) {
	p := resolverPrefixFromDID(did)
	resolver, ok := (*ch)[p]
	if !ok {
		return nil, errors.Errorf("not found resolver for '%s' resolver prefix", p)
	}

	return resolver, nil
}

func resolverPrefixFromDID(did *core.DID) string {
	return resolverPrefix(string(did.Blockchain), string(did.NetworkID))
}

func resolverPrefix(chain, networkID string) string {
	return fmt.Sprintf("%s:%s", chain, networkID)
}
