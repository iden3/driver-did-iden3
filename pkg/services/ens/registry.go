package ens

import (
	"log"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/iden3/driver-did-iden3/pkg/services/ens/contract/namehash"
	"github.com/iden3/driver-did-iden3/pkg/services/ens/contract/registry"
	"github.com/iden3/driver-did-iden3/pkg/services/ens/contract/resolver"
)

type Network string

var ListNetworks = map[string]Network{
	"MainNet": MainNet,
	"Robsten": Robsten,
}

// These addresses hard coded in blockchain.
const (
	MainNet Network = "00000000000C2E074eC69A0dFb2997BA6C7d2e1e"
	Robsten Network = "00000000000C2E074eC69A0dFb2997BA6C7d2e1e"
)

// Registry core contract in ENS.
type Registry struct {
	eth      *ethclient.Client
	contract *registry.Contract
	address  common.Address
}

// NewRegistry create interface for communication with core contract in ENS.
func NewRegistry(eth *ethclient.Client, network Network) (*Registry, error) {
	hexAddr := common.HexToAddress(string(network))
	contract, err := registry.NewContract(hexAddr, eth)
	if err != nil {
		log.Printf("failed create interface to registry '%s': %s", network, err)
		return nil, err
	}

	return &Registry{
		eth:      eth,
		contract: contract,
		address:  hexAddr,
	}, nil
}

// Resolver return resolver for domain.
func (r *Registry) Resolver(domain string) (*Resolver, error) {
	hashedDomain, err := namehash.NameHash(domain)
	if err != nil {
		log.Printf("failed get hash for domain '%s': %s", domain, err)
		return nil, err
	}
	resolverAddr, err := r.contract.Resolver(nil, hashedDomain)
	if err != nil {
		log.Printf("failed ger resolver for domain '%s': %s", domain, err)
		return nil, err
	}

	resolver, err := resolver.NewContract(resolverAddr, r.eth)
	if err != nil {
		log.Printf("failed create registry for contract '%s': %s", domain, err)
		return nil, err
	}

	return &Resolver{
		client:   r.eth,
		contract: resolver,
		address:  resolverAddr,
		domain:   hashedDomain,
	}, nil
}
