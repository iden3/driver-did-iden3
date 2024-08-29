package eth

import (
	"context"
	"crypto/ecdsa"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	contract "github.com/iden3/contracts-abi/state/go/abi"
	"github.com/iden3/driver-did-iden3/pkg/services"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
)

//go:generate mockgen -destination=contract/mock/contract.go . StateContract
type StateContract interface {
	GetGISTRoot(opts *bind.CallOpts) (*big.Int, error)
	GetGISTRootInfo(opts *bind.CallOpts, root *big.Int) (contract.IStateGistRootInfo, error)
	GetGISTProofByRoot(opts *bind.CallOpts, id *big.Int, root *big.Int) (contract.IStateGistProof, error)

	GetStateInfoById(opts *bind.CallOpts, id *big.Int) (contract.IStateStateInfo, error)
	GetStateInfoByIdAndState(opts *bind.CallOpts, id *big.Int, state *big.Int) (contract.IStateStateInfo, error)
}

type Resolver struct {
	state StateContract

	contractAddress string
	chainID         int
	walletKey       string
}

type AuthData struct {
	TypedData apitypes.TypedData
	Signature string
	Address   string
}

const (
	secp256k1VValue = 27
)

var (
	gistNotFoundException     = "execution reverted: Root does not exist"
	identityNotFoundException = "execution reverted: Identity does not exist"
	stateNotFoundException    = "execution reverted: State does not exist"
)

var IdentityStateAPITypes = apitypes.Types{
	"IdentityState": []apitypes.Type{
		{Name: "timestamp", Type: "uint256"},
		{Name: "id", Type: "uint256"},
		{Name: "state", Type: "uint256"},
		{Name: "replacedAtTimestamp", Type: "uint256"},
	},
	"EIP712Domain": []apitypes.Type{
		{Name: "name", Type: "string"},
		{Name: "version", Type: "string"},
		{Name: "chainId", Type: "uint256"},
		{Name: "verifyingContract", Type: "address"},
	},
}

var GlobalStateAPITypes = apitypes.Types{
	"GlobalState": []apitypes.Type{
		{Name: "timestamp", Type: "uint256"},
		{Name: "idType", Type: "bytes2"},
		{Name: "root", Type: "uint256"},
		{Name: "replacedAtTimestamp", Type: "uint256"},
	},
	"EIP712Domain": []apitypes.Type{
		{Name: "name", Type: "string"},
		{Name: "version", Type: "string"},
		{Name: "chainId", Type: "uint256"},
		{Name: "verifyingContract", Type: "address"},
	},
}

var TimeStamp = TimeStampFn

// NewResolver create new ethereum resolver.
func NewResolver(url, address, walletKey string) (*Resolver, error) {
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
		walletKey:       walletKey,
	}
	chainID, err := c.NetworkID(context.Background())
	if err != nil {
		return nil, err
	}
	resolver.chainID = int(chainID.Int64())
	return resolver, nil
}

func (r *Resolver) BlockchainID() string {
	return fmt.Sprintf("%d:%s", r.chainID, r.contractAddress)
}

func (r *Resolver) GetWalletAddress() (string, error) {
	if r.walletKey == "" {
		return "", errors.New("wallet key is not set")
	}

	privateKey, err := crypto.HexToECDSA(r.walletKey)
	if err != nil {
		return "", err
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("error casting public key to ECDSA")
	}

	walletAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	return walletAddress.String(), nil
}

func (r *Resolver) ResolveGist(
	ctx context.Context,
	opts *services.ResolverOpts,
) (*services.GistInfo, error) {
	var err error

	gistRoot := opts.GistRoot
	if gistRoot == nil {
		gistRoot, err = r.state.GetGISTRoot(&bind.CallOpts{Context: ctx})
		if err != nil {
			return nil, err
		}
	}

	rootInfo, err := r.state.GetGISTRootInfo(&bind.CallOpts{Context: ctx}, gistRoot)
	if err = notFoundErr(err); err != nil {
		return nil, err
	}

	return &services.GistInfo{
		Root:                rootInfo.Root,
		ReplacedByRoot:      rootInfo.ReplacedByRoot,
		CreatedAtTimestamp:  rootInfo.CreatedAtTimestamp,
		ReplacedAtTimestamp: rootInfo.ReplacedAtTimestamp,
		CreatedAtBlock:      rootInfo.CreatedAtBlock,
		ReplacedAtBlock:     rootInfo.ReplacedAtBlock,
	}, nil
}

func (r *Resolver) Resolve(
	ctx context.Context,
	did w3c.DID,
	opts *services.ResolverOpts,
) (services.IdentityState, error) {
	if opts.GistRoot != nil && opts.State != nil {
		return services.IdentityState{},
			errors.New("options GistRoot and State together are not available")
	}

	var (
		stateInfo *contract.IStateStateInfo
		gistInfo  *contract.IStateGistRootInfo
		err       error
	)

	userID, err := core.IDFromDID(did)
	if err != nil {
		return services.IdentityState{},
			fmt.Errorf("invalid did format for did '%s': %v", did, err)
	}

	switch {
	case opts.GistRoot != nil:
		stateInfo, gistInfo, err = r.resolveStateByGistRoot(ctx, userID, opts.GistRoot)
	case opts.State != nil:
		stateInfo, err = r.resolveState(ctx, userID, opts.State)
	default:
		stateInfo, gistInfo, err = r.resolveLatest(ctx, userID)
	}
	// err == http.505
	if err != nil && !errors.Is(err, services.ErrNotFound) {
		return services.IdentityState{}, err
	}

	if opts.State != nil && errors.Is(err, services.ErrNotFound) {
		idGen, err := core.CheckGenesisStateID(userID.BigInt(), opts.State)
		if err != nil {
			return services.IdentityState{}, err
		}
		if !idGen {
			return services.IdentityState{},
				fmt.Errorf("identity '%s' state '%s' is not found and is not genesis", userID.String(), opts.State)
		}
		stateInfo = &contract.IStateStateInfo{
			State:               opts.State,
			ReplacedByState:     big.NewInt(0),
			CreatedAtTimestamp:  big.NewInt(0),
			ReplacedAtTimestamp: big.NewInt(0),
			CreatedAtBlock:      big.NewInt(0),
			ReplacedAtBlock:     big.NewInt(0),
		}
	}

	identityState := services.IdentityState{}
	if stateInfo != nil {
		identityState.StateInfo = &services.StateInfo{
			ID:                  did,
			State:               stateInfo.State,
			ReplacedByState:     stateInfo.ReplacedByState,
			CreatedAtTimestamp:  stateInfo.CreatedAtTimestamp,
			ReplacedAtTimestamp: stateInfo.ReplacedAtTimestamp,
			CreatedAtBlock:      stateInfo.CreatedAtBlock,
			ReplacedAtBlock:     stateInfo.ReplacedAtBlock,
		}
	}
	if gistInfo != nil {
		identityState.GistInfo = &services.GistInfo{
			Root:                gistInfo.Root,
			ReplacedByRoot:      gistInfo.ReplacedByRoot,
			CreatedAtTimestamp:  gistInfo.CreatedAtTimestamp,
			ReplacedAtTimestamp: gistInfo.ReplacedAtTimestamp,
			CreatedAtBlock:      gistInfo.CreatedAtBlock,
			ReplacedAtBlock:     gistInfo.ReplacedAtBlock,
		}
	}

	signature := ""
	if opts.Signature != "" {
		if r.walletKey == "" {
			return services.IdentityState{},
				errors.New("no wallet key found for generating signature")
		}
		primaryType := services.IdentityStateType
		if opts.GistRoot != nil {
			primaryType = services.GlobalStateType
		}
		signature, err = r.signTypedData(primaryType, did, identityState)
		if err != nil {
			return services.IdentityState{}, err
		}
	}

	identityState.Signature = signature

	return identityState, err
}

func (r *Resolver) VerifyState(
	primaryType services.PrimaryType,
	identityState services.IdentityState,
	did w3c.DID,
) (bool, error) {
	walletAddress, err := r.GetWalletAddress()
	if err != nil {
		return false, err
	}

	typedData, err := r.TypedData(primaryType, did, identityState, walletAddress)
	if err != nil {
		return false, err
	}

	authData := AuthData{TypedData: typedData, Signature: identityState.Signature, Address: walletAddress}
	return r.verifyTypedData(authData)
}

func TimeStampFn() string {
	timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	return timestamp
}

func (r *Resolver) TypedData(primaryType services.PrimaryType, did w3c.DID, identityState services.IdentityState, walletAddress string) (apitypes.TypedData, error) {
	id, err := core.IDFromDID(did)
	if err != nil {
		return apitypes.TypedData{},
			fmt.Errorf("invalid did format for did '%s': %v", did, err)
	}
	ID := id.BigInt().String()
	idType := fmt.Sprintf("0x%02X%02X", id.Type()[0], id.Type()[1])

	apiTypes := apitypes.Types{}
	message := apitypes.TypedDataMessage{}
	primaryTypeString := ""
	timestamp := TimeStamp()

	switch primaryType {
	case services.IdentityStateType:
		state := "0"
		replacedAtTimestamp := "0"

		if identityState.StateInfo != nil {
			state = identityState.StateInfo.State.String()
			replacedAtTimestamp = identityState.StateInfo.ReplacedAtTimestamp.String()
		}
		primaryTypeString = "IdentityState"
		apiTypes = IdentityStateAPITypes
		message = apitypes.TypedDataMessage{
			"timestamp":           timestamp,
			"id":                  ID,
			"state":               state,
			"replacedAtTimestamp": replacedAtTimestamp,
		}
	case services.GlobalStateType:
		root := "0"
		replacedAtTimestamp := "0"

		if identityState.GistInfo != nil {
			root = identityState.GistInfo.Root.String()
			replacedAtTimestamp = identityState.GistInfo.ReplacedAtTimestamp.String()
		}
		primaryTypeString = "GlobalState"
		apiTypes = GlobalStateAPITypes
		message = apitypes.TypedDataMessage{
			"timestamp":           timestamp,
			"idType":              idType,
			"root":                root,
			"replacedAtTimestamp": replacedAtTimestamp,
		}
	}

	typedData := apitypes.TypedData{
		Types:       apiTypes,
		PrimaryType: primaryTypeString,
		Domain: apitypes.TypedDataDomain{
			Name:              "StateInfo",
			Version:           "1",
			ChainId:           math.NewHexOrDecimal256(int64(0)),
			VerifyingContract: "0x0000000000000000000000000000000000000000",
		},
		Message: message,
	}

	return typedData, nil
}

func (r *Resolver) signTypedData(primaryType services.PrimaryType, did w3c.DID, identityState services.IdentityState) (string, error) {
	privateKey, err := crypto.HexToECDSA(r.walletKey)
	if err != nil {
		return "", err
	}

	walletAddress, err := r.GetWalletAddress()
	if err != nil {
		return "", err
	}

	typedData, err := r.TypedData(primaryType, did, identityState, walletAddress)
	if err != nil {
		return "", errors.New("error getting typed data for signing")
	}

	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return "", errors.New("error hashing EIP712Domain for signing")
	}
	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return "", errors.New("error hashing PrimaryType message for signing")
	}
	rawData := []byte(fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash)))
	dataHash := crypto.Keccak256(rawData)

	signature, err := crypto.Sign(dataHash, privateKey)
	if err != nil {
		return "", err
	}

	if signature[64] < secp256k1VValue { // Invalid Ethereum signature (V is not 27 or 28)
		signature[64] += secp256k1VValue // Transform yellow paper V from 27/28 to 0/1
	}

	return "0x" + hex.EncodeToString(signature), nil
}

func (r *Resolver) verifyTypedData(authData AuthData) (bool, error) {
	signature, err := hexutil.Decode(authData.Signature)
	if err != nil {
		return false, fmt.Errorf("decode signature: %w", err)
	}

	// EIP-712 typed data marshaling
	domainSeparator, err := authData.TypedData.HashStruct("EIP712Domain", authData.TypedData.Domain.Map())
	if err != nil {
		return false, fmt.Errorf("eip712domain hash struct: %w", err)
	}
	typedDataHash, err := authData.TypedData.HashStruct(authData.TypedData.PrimaryType, authData.TypedData.Message)
	if err != nil {
		return false, fmt.Errorf("primary type hash struct: %w", err)
	}

	// add magic string prefix
	rawData := []byte(fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash)))
	sighash := crypto.Keccak256(rawData)

	// update the recovery id
	// https://github.com/ethereum/go-ethereum/blob/55599ee95d4151a2502465e0afc7c47bd1acba77/internal/ethapi/api.go#L442
	signature[64] -= 27

	// get the pubkey used to sign this signature
	sigPubkey, err := crypto.Ecrecover(sighash, signature)
	if err != nil {
		return false, fmt.Errorf("ecrecover: %w", err)
	}

	// get the address to confirm it's the same one in the auth token
	pubkey, err := crypto.UnmarshalPubkey(sigPubkey)
	if err != nil {
		return false, fmt.Errorf("unmarshal pub key: %w", err)
	}
	address := crypto.PubkeyToAddress(*pubkey)

	// verify the signature (not sure if this is actually required after ecrecover)
	signatureNoRecoverID := signature[:len(signature)-1]
	verified := crypto.VerifySignature(sigPubkey, sighash, signatureNoRecoverID)
	if !verified {
		return false, errors.New("verification failed")
	}

	dataAddress := common.HexToAddress(authData.Address)
	if subtle.ConstantTimeCompare(address.Bytes(), dataAddress.Bytes()) == 0 {
		return false, errors.New("address mismatch")
	}

	return true, nil
}

func (r *Resolver) resolveLatest(
	ctx context.Context,
	id core.ID,
) (*contract.IStateStateInfo, *contract.IStateGistRootInfo, error) {
	latestRootGist, err := r.state.GetGISTRoot(&bind.CallOpts{Context: ctx})
	if err != nil {
		return nil, nil, err
	}
	gistInfo, err := r.state.GetGISTRootInfo(&bind.CallOpts{Context: ctx}, latestRootGist)
	if err != nil {
		return nil, nil, err
	}

	stateInfo, err := r.state.GetStateInfoById(&bind.CallOpts{Context: ctx}, id.BigInt())
	if err = notFoundErr(err); err != nil {
		return nil, &gistInfo, err
	}

	return &stateInfo, &gistInfo, verifyContractState(id, stateInfo)
}

func (r *Resolver) resolveState(
	ctx context.Context,
	id core.ID,
	state *big.Int,
) (*contract.IStateStateInfo, error) {
	stateInfo, err := r.state.GetStateInfoByIdAndState(&bind.CallOpts{Context: ctx}, id.BigInt(), state)
	if err = notFoundErr(err); err != nil {
		return nil, err
	}

	return &stateInfo, verifyContractState(id, stateInfo)
}

func (r *Resolver) resolveStateByGistRoot(
	ctx context.Context,
	id core.ID,
	gistRoot *big.Int,
) (*contract.IStateStateInfo, *contract.IStateGistRootInfo, error) {
	proof, err := r.state.GetGISTProofByRoot(
		&bind.CallOpts{Context: ctx},
		id.BigInt(),
		gistRoot,
	)
	if err := notFoundErr(err); err != nil {
		return nil, nil, err
	}
	gistInfo, err := r.state.GetGISTRootInfo(&bind.CallOpts{Context: ctx}, proof.Root)
	if err = notFoundErr(err); err != nil {
		return nil, nil, err
	}

	if !proof.Existence {
		return nil, &gistInfo, nil
	}

	stateInfo, err := r.state.GetStateInfoByIdAndState(&bind.CallOpts{Context: ctx}, id.BigInt(), proof.Value)
	if err = notFoundErr(err); err != nil {
		return nil, &gistInfo, err
	}

	return &stateInfo, &gistInfo, verifyContractState(id, stateInfo)
}

func verifyContractState(id core.ID, state contract.IStateStateInfo) error {
	if state.Id.Cmp(id.BigInt()) != 0 {
		return fmt.Errorf("expected id '%s' not equal id '%s' from contract",
			id, state.Id)
	}
	return nil
}

func notFoundErr(err error) error {
	if err == nil {
		return nil
	}

	switch err.Error() {
	case gistNotFoundException:
		return fmt.Errorf("gist %w", services.ErrNotFound)
	case identityNotFoundException:
		return fmt.Errorf("identity %w", services.ErrNotFound)
	case stateNotFoundException:
		return fmt.Errorf("state %w", services.ErrNotFound)
	}

	return err
}
