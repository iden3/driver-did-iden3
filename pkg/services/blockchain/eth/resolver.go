package eth

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/iden3/driver-did-iden3/pkg/document"
	"github.com/iden3/driver-did-iden3/pkg/services/blockchain/eth/contract"
	core "github.com/iden3/go-iden3-core"
)

type Resolver struct {
	state *contract.State

	contractAddress string
	chainID         int
}

// NewResolver create new ethereum resolver.
func NewResolver(url, address string) (*Resolver, error) {
	c, err := ethclient.Dial(url)
	if err != nil {
		return nil, err
	}
	sc, err := contract.NewState(common.HexToAddress(address), c)
	if err != nil {
		return nil, err
	}

	resolver := &Resolver{
		state:           sc,
		contractAddress: address,
	}
	chainID, err := c.NetworkID(context.Background())
	if err != nil {
		return nil, err
	}
	resolver.chainID = int(chainID.Int64())
	return resolver, nil
}

// Resolve state by user ID.
func (r *Resolver) Resolve(ctx context.Context, id *core.ID) (*document.IdentityState, error) {
	opts := &bind.CallOpts{Context: ctx}
	s, err := r.state.GetStateInfoById(opts, id.BigInt())
	if err != nil && !strings.Contains(err.Error(), "execution reverted: Identity does not exist") {
		return nil, fmt.Errorf("failed get latest state for id '%s': %v", id, err)
	}

	opts = &bind.CallOpts{Context: ctx}
	latestRoot, err := r.state.GetGISTRoot(opts)
	if err != nil {
		return nil, fmt.Errorf("failed get latest gist root: %v", err)
	}

	opts = &bind.CallOpts{Context: ctx}
	latestRootInfo, err := r.state.GetGISTRootInfo(opts, latestRoot)
	if err != nil {
		return nil, fmt.Errorf("failed get info about latest gist root: %v", err)
	}

	identityState := &document.IdentityState{
		BlockchainAccountID: fmt.Sprintf("%d:%s", r.chainID, r.contractAddress),
	}

	if s.State != nil && s.State.Cmp(big.NewInt(0)) != 0 {
		identityState.Published = true
		identityState.Latest = &document.StateInfo{
			ID:                  s.Id.String(),
			State:               s.State.String(),
			ReplacedByState:     s.ReplacedByState.String(),
			CreatedAtTimestamp:  s.CreatedAtTimestamp.String(),
			ReplacedAtTimestamp: s.ReplacedAtTimestamp.String(),
			CreatedAtBlock:      s.CreatedAtBlock.String(),
			ReplacedAtBlock:     s.ReplacedAtBlock.String(),
		}
	}

	identityState.Global = &document.GistInfo{
		Root:                latestRootInfo.Root.String(),
		ReplacedByRoot:      latestRootInfo.ReplacedByRoot.String(),
		CreatedAtTimestamp:  latestRootInfo.CreatedAtTimestamp.String(),
		ReplacedAtTimestamp: latestRootInfo.ReplacedAtTimestamp.String(),
		CreatedAtBlock:      latestRootInfo.CreatedAtBlock.String(),
		ReplacedAtBlock:     latestRootInfo.ReplacedAtBlock.String(),
	}

	return identityState, nil
}
