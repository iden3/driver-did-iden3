package services

import (
	"context"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/iden3/driver-did-iden3/pkg/document"
	"github.com/iden3/driver-did-iden3/pkg/services/ens"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/pkg/errors"
)

const (
	ensResolverKey = "description"
)

type DidDocumentServices struct {
	resolvers *ResolverRegistry
	ens       *ens.Registry
	signers   *EIP712SignerRegistry
}

type ResolverOpts struct {
	State     *big.Int
	GistRoot  *big.Int
	Signature string
}

type DidDocumentOption func(*DidDocumentServices)

func WithSigners(signers *EIP712SignerRegistry) DidDocumentOption {
	return func(d *DidDocumentServices) {
		d.signers = signers
	}
}

func NewDidDocumentServices(resolvers *ResolverRegistry, registry *ens.Registry, opts ...DidDocumentOption) *DidDocumentServices {
	didDocumentService := &DidDocumentServices{resolvers, registry, nil}

	for _, opt := range opts {
		opt(didDocumentService)
	}
	return didDocumentService
}

// GetDidDocument return did document by identifier.
func (d *DidDocumentServices) GetDidDocument(ctx context.Context, did string, opts *ResolverOpts) (*document.DidResolution, error) {
	if opts == nil {
		opts = &ResolverOpts{}
	}

	userDID, err := w3c.ParseDID(did)
	errResolution, err := expectedError(err)
	if err != nil {
		return errResolution, err
	}

	userID, err := core.IDFromDID(*userDID)
	errResolution, err = expectedError(err)
	if err != nil {
		return errResolution, err
	}

	b, err := core.BlockchainFromID(userID)
	errResolution, err = expectedError(err)
	if err != nil {
		return errResolution, err
	}

	n, err := core.NetworkIDFromID(userID)
	errResolution, err = expectedError(err)
	if err != nil {
		return errResolution, err
	}

	resolver, err := d.resolvers.GetResolverByNetwork(string(b), string(n))
	errResolution, err = expectedError(err)
	if err != nil {
		return errResolution, err
	}

	identityState, err := resolver.Resolve(ctx, *userDID, opts)
	if errors.Is(err, ErrNotFound) && (opts.State != nil || opts.GistRoot != nil) {
		gen, errr := isGenesis(userID.BigInt(), opts.State)
		if errr != nil {
			return nil, fmt.Errorf("invalid state: %v", errr)
		}
		if !gen {
			return document.NewDidNotFoundResolution(err.Error()), nil
		}
	}

	if err != nil && opts.State != nil {
		return document.NewDidNotFoundResolution(err.Error()), nil
	}

	info, err := identityState.StateInfo.ToDidRepresentation()
	if err != nil {
		return nil, fmt.Errorf("invalid resolver response: %v", err)
	}

	gist, err := identityState.GistInfo.ToDidRepresentation()
	if err != nil {
		return nil, fmt.Errorf("invalid resolver response: %v", err)
	}

	didResolution := document.NewDidResolution()
	didResolution.DidDocument.ID = did

	addr, err := core.EthAddressFromID(userID)

	chainIDStateAddress := resolver.BlockchainID()

	if err == nil {
		didResolution.DidDocument.Context = append(didResolution.DidDocument.Context.([]string), document.EcdsaSecp256k1RecoveryContext)
		addressString := fmt.Sprintf("%x", addr)
		blockchainAccountID := fmt.Sprintf("eip155:%s:0x%s", strings.Split(chainIDStateAddress, ":")[0], addressString)
		didResolution.DidDocument.VerificationMethod = append(
			didResolution.DidDocument.VerificationMethod,
			verifiable.CommonVerificationMethod{
				ID:                  fmt.Sprintf("%s#ethereum-based-id", did),
				Type:                document.EcdsaSecp256k1RecoveryMethod2020Type,
				Controller:          did,
				BlockchainAccountID: blockchainAccountID,
			},
		)
	}

	isPublished := isPublished(identityState.StateInfo)
	didResolution.DidDocument.VerificationMethod = append(
		didResolution.DidDocument.VerificationMethod,
		verifiable.CommonVerificationMethod{
			ID:                   fmt.Sprintf("%s#state-info", did),
			Type:                 document.StateType,
			StateContractAddress: chainIDStateAddress,
			Controller:           did,
			IdentityState: verifiable.IdentityState{
				Published: &isPublished,
				Info:      info,
				Global:    gist,
			},
		},
	)

	if opts.Signature != "" {
		signer, err := d.signers.GetEIP712SignerByNetwork(string(b), string(n))
		errResolution, err = expectedError(err)
		if err != nil {
			return errResolution, err
		}

		eip712TypedData := &apitypes.TypedData{}
		if opts.GistRoot != nil {
			typedData, err := getTypedData(GlobalStateType, *userDID, identityState)
			if err != nil {
				return nil, fmt.Errorf("invalid typed data for global state: %v", err)
			}
			eip712TypedData = &typedData
		} else {
			typedData, err := getTypedData(IdentityStateType, *userDID, identityState)
			if err != nil {
				return nil, fmt.Errorf("invalid typed data for identity state: %v", err)
			}
			eip712TypedData = &typedData
		}
		eip712Proof, err := signer.Sign(*eip712TypedData)
		if err != nil {
			return nil, fmt.Errorf("invalid eip712 typed data: %v", err)
		}

		didResolution.DidResolutionMetadata.Context = document.DidResolutionMetadataSigContext()
		didResolution.DidResolutionMetadata.Proof = append(didResolution.DidResolutionMetadata.Proof, eip712Proof)
	}
	return didResolution, nil
}

func getTypedData(typeDataType TypedDataType, did w3c.DID, identityState IdentityState) (apitypes.TypedData, error) {
	id, err := core.IDFromDID(did)
	if err != nil {
		return apitypes.TypedData{},
			fmt.Errorf("invalid did format for did '%s': %v", did, err)
	}

	timestamp := timeStamp()

	apiTypes := apitypes.Types{}
	message := apitypes.TypedDataMessage{}
	primaryType := ""

	if typeDataType == IdentityStateType {
		primaryType = "IdentityState"
		apiTypes = apitypes.Types{
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
		ID := id.BigInt().String()
		state := identityState.StateInfo.State.String()
		replacedAtTimestamp := identityState.StateInfo.ReplacedAtTimestamp.String()
		message = apitypes.TypedDataMessage{
			"timestamp":           timestamp,
			"id":                  ID,
			"state":               state,
			"replacedAtTimestamp": replacedAtTimestamp,
		}

	} else {
		primaryType = "GlobalState"
		apiTypes = apitypes.Types{
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
		idType := fmt.Sprintf("0x%X", id.Type())
		root := identityState.GistInfo.Root.String()
		replacedAtTimestamp := identityState.GistInfo.ReplacedAtTimestamp.String()
		message = apitypes.TypedDataMessage{
			"timestamp":           timestamp,
			"idType":              idType,
			"root":                root,
			"replacedAtTimestamp": replacedAtTimestamp,
		}
	}

	typedData := apitypes.TypedData{
		Types:       apiTypes,
		PrimaryType: primaryType,
		Domain: apitypes.TypedDataDomain{
			Name:              "StateInfo",
			Version:           "1",
			ChainId:           math.NewHexOrDecimal256(int64(0)),
			VerifyingContract: common.Address{}.String(),
		},
		Message: message,
	}

	return typedData, nil
}

func timeStamp() string {
	timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	return timestamp
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
		did *w3c.DID
		v   string
	)
	// try to find correct did.
	for _, v = range records {
		did, err = w3c.ParseDID(v)
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

	return d.GetDidDocument(ctx, v, nil)
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

	return d.GetDidDocument(ctx, did, nil)
}

func (d *DidDocumentServices) GetGist(ctx context.Context, chain, network string, opts *ResolverOpts) (*verifiable.GistInfo, error) {
	if opts == nil {
		opts = &ResolverOpts{}
	}
	resolver, err := d.resolvers.GetResolverByNetwork(chain, network)
	if err != nil {
		return nil, err
	}

	gistInfo, err := resolver.ResolveGist(ctx, opts)
	if err != nil {
		return nil, err
	}
	return gistInfo.ToDidRepresentation()
}

func isPublished(si *StateInfo) bool {
	if si == nil || si.State == nil {
		return false
	}
	return si.State.Cmp(big.NewInt(0)) != 0
}

func isGenesis(id, state *big.Int) (bool, error) {
	if state == nil {
		return false, nil
	}

	isGenesis, err := core.CheckGenesisStateID(id, state)
	if err != nil {
		return false, err
	}

	return isGenesis, nil
}

func expectedError(err error) (*document.DidResolution, error) {
	if err == nil {
		return nil, nil
	}

	switch {
	case errors.Is(err, core.ErrIncorrectDID):
		return document.NewDidInvalidResolution(err.Error()), err
	case
		errors.Is(err, core.ErrBlockchainNotSupportedForDID),
		errors.Is(err, core.ErrNetworkNotSupportedForDID):

		return document.NewNetworkNotSupportedForDID(err.Error()), err
	case errors.Is(err, core.ErrDIDMethodNotSupported):
		return document.NewDidMethodNotSupportedResolution(err.Error()), err
	}

	return nil, err
}

// after discussion we decided not to include state in verification method id,
// so we can have consistent id for verification
// func getRepresentaionID(did string, state IdentityState) string {
// 	if state.StateInfo != nil && state.StateInfo.State != nil {
// 		h, _ := merkletree.NewHashFromBigInt(state.StateInfo.State)
// 		return fmt.Sprintf("%s?state=%s", did, h.Hex())
// 	}
// 	return did
// }
