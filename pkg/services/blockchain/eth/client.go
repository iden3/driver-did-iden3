package eth

import (
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

type StateContract struct {
	bound *bind.BoundContract
}

// NewStateContract create bound between application and smart contract.
func NewStateContract(address string, client *ethclient.Client) (*StateContract, error) {
	parsed, err := abi.JSON(strings.NewReader(StateABI))
	if err != nil {
		return nil, err
	}

	b := bind.NewBoundContract(common.HexToAddress(address), parsed, client, client, client)
	return &StateContract{bound: b}, nil
}

// GetStateByID call `function getState(uint256 id) public view returns (uint256)` from smart contract.
// Check `StateABI` for more details.
func (sc *StateContract) GetStateByID(opts *bind.CallOpts, id *big.Int) (*big.Int, error) {
	var (
		output1 = new(*big.Int)
	)
	outputs := &[]interface{}{
		output1,
	}

	err := sc.bound.Call(opts, outputs, "getState", id)
	return *output1, err
}
