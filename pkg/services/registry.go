package services

import (
	"context"
	"fmt"
	"math/big"

	contract "github.com/iden3/contracts-abi/state/go/abi"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/pkg/errors"
)

var (
	ErrNetworkIsNotSupported   = errors.New("network is not supported")
	ErrProofTypeIsNotSupported = errors.New("proof is not supported")

	ErrResolverAlreadyExists = errors.New("resolver already exists")

	ErrNotFound = errors.New("not found")
)

type IdentityState struct {
	StateInfo *StateInfo
	GistInfo  *GistInfo
}

type StateInfo struct {
	ID                  w3c.DID
	State               *big.Int
	ReplacedByState     *big.Int
	CreatedAtTimestamp  *big.Int
	ReplacedAtTimestamp *big.Int
	CreatedAtBlock      *big.Int
	ReplacedAtBlock     *big.Int
}

func (si *StateInfo) ToDidRepresentation() (*verifiable.StateInfo, error) {
	if si == nil {
		return nil, nil
	}
	stateHash, err := merkletree.NewHashFromBigInt(si.State)
	if err != nil {
		return nil, err
	}

	replacedHash, err := merkletree.NewHashFromBigInt(si.ReplacedByState)
	if err != nil {
		return nil, err
	}
	return &verifiable.StateInfo{
		ID:                  si.ID.String(),
		State:               stateHash.Hex(),
		ReplacedByState:     replacedHash.Hex(),
		CreatedAtTimestamp:  si.CreatedAtTimestamp.String(),
		ReplacedAtTimestamp: si.ReplacedAtTimestamp.String(),
		CreatedAtBlock:      si.CreatedAtBlock.String(),
		ReplacedAtBlock:     si.ReplacedAtBlock.String(),
	}, nil
}

type GistInfo struct {
	Root                *big.Int
	ReplacedByRoot      *big.Int
	CreatedAtTimestamp  *big.Int
	ReplacedAtTimestamp *big.Int
	CreatedAtBlock      *big.Int
	ReplacedAtBlock     *big.Int
	Proof               *contract.IStateGistProof
}

func (gi *GistInfo) ToDidRepresentation() (*verifiable.GistInfo, error) {
	if gi == nil {
		return nil, nil
	}

	rootHash, err := merkletree.NewHashFromBigInt(gi.Root)
	if err != nil {
		return nil, err
	}

	replacedHash, err := merkletree.NewHashFromBigInt(gi.ReplacedByRoot)
	if err != nil {
		return nil, err
	}

	gistInfo := &verifiable.GistInfo{
		Root:                rootHash.Hex(),
		ReplacedByRoot:      replacedHash.Hex(),
		CreatedAtTimestamp:  gi.CreatedAtTimestamp.String(),
		ReplacedAtTimestamp: gi.ReplacedAtTimestamp.String(),
		CreatedAtBlock:      gi.CreatedAtBlock.String(),
		ReplacedAtBlock:     gi.ReplacedAtBlock.String(),
	}

	if gi.Proof != nil {
		siblingsStrArr := make([]*merkletree.Hash, len(gi.Proof.Siblings))
		for i, bi := range &gi.Proof.Siblings {
			hash, err := merkletree.NewHashFromBigInt(bi)
			if err != nil {
				return nil, err
			}
			siblingsStrArr[i] = hash
		}

		var nodeAux *merkletree.NodeAux
		if !gi.Proof.Existence && gi.Proof.AuxExistence {
			val, err := merkletree.NewHashFromBigInt(gi.Proof.AuxValue)
			if err != nil {
				return nil, err
			}
			indx, err := merkletree.NewHashFromBigInt(gi.Proof.AuxIndex)
			if err != nil {
				return nil, err
			}
			nodeAux = &merkletree.NodeAux{
				Key:   indx,
				Value: val,
			}
		}
		mkProof, err := merkletree.NewProofFromData(gi.Proof.Existence, siblingsStrArr, nodeAux)
		if err != nil {
			return nil, err
		}

		gistInfo.Proof = &verifiable.GistInfoProof{
			Proof: *mkProof,
			Type:  verifiable.Iden3SparseMerkleTreeProofType,
		}
	}
	return gistInfo, nil
}

type Resolver interface {
	Resolve(ctx context.Context, did w3c.DID, opts *ResolverOpts) (IdentityState, error)
	ResolveGist(ctx context.Context, opts *ResolverOpts) (*GistInfo, error)
	BlockchainID() string
}

type ResolverRegistry map[string]Resolver

func NewChainResolvers() *ResolverRegistry {
	return &ResolverRegistry{}
}

func (ch *ResolverRegistry) Add(prefix string, resolver Resolver) {
	(*ch)[prefix] = resolver
}

func (ch *ResolverRegistry) Append(prefix string, resolver Resolver) error {
	_, ok := (*ch)[prefix]
	if ok {
		return ErrResolverAlreadyExists
	}
	(*ch)[prefix] = resolver
	return nil
}

func (ch *ResolverRegistry) GetResolverByNetwork(chain, networkID string) (Resolver, error) {
	p := resolverPrefix(chain, networkID)
	resolver, ok := (*ch)[p]
	if !ok {
		return nil, ErrNetworkIsNotSupported
	}

	return resolver, nil
}

func resolverPrefix(chain, networkID string) string {
	return fmt.Sprintf("%s:%s", chain, networkID)
}
