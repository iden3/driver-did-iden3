package services

import (
	"context"
	"fmt"
	"math/big"
	"net"
	"strings"

	"github.com/iden3/driver-did-iden3/pkg/document"
	"github.com/iden3/driver-did-iden3/pkg/services/ens"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/iden3/merkletree-proof/resolvers"
	"github.com/pkg/errors"
)

const (
	ensResolverKey = "description"
)

type DidDocumentServices struct {
	resolvers                *ResolverRegistry
	ens                      *ens.Registry
	provers                  *DIDResolutionProverRegistry
	revStatusOnChainResolver *resolvers.OnChainResolver
}

type ResolverOpts struct {
	State     *big.Int
	GistRoot  *big.Int
	Signature string
}

type DidDocumentOption func(*DidDocumentServices)

func WithProvers(provers *DIDResolutionProverRegistry) DidDocumentOption {
	return func(d *DidDocumentServices) {
		d.provers = provers
	}
}

func NewDidDocumentServices(resolverRegistry *ResolverRegistry, registry *ens.Registry, revStatusOnChainResolver *resolvers.OnChainResolver, opts ...DidDocumentOption) *DidDocumentServices {
	didDocumentService := &DidDocumentServices{resolverRegistry, registry, nil, revStatusOnChainResolver}

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
	} else if err != nil && opts.State != nil {
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

	if gist != nil {
		didResolution.DidDocument.Context = append(didResolution.DidDocument.Context.([]string), document.Iden3proofsContext)
	}

	if opts.Signature != "" {
		if d.provers == nil {
			return nil, errors.New("provers are not initialized")
		}
		prover, err := d.provers.GetDIDResolutionProverByProofType(verifiable.ProofType(opts.Signature))
		if err != nil {
			return nil, err
		}
		stateType := IdentityStateType
		if opts.GistRoot != nil {
			stateType = GlobalStateType
		}

		if stateType == IdentityStateType && ((opts.State != nil && identityState.StateInfo == nil) || !isPublished) { // this case is genesis state
			// fill state info for genesis state to be able to prove it

			state := opts.State
			if state == nil {
				state = big.NewInt(0)
			}
			identityState.StateInfo = &StateInfo{
				ID:                  *userDID,
				State:               state,
				ReplacedByState:     big.NewInt(0),
				CreatedAtTimestamp:  big.NewInt(0),
				ReplacedAtTimestamp: big.NewInt(0),
				CreatedAtBlock:      big.NewInt(0),
				ReplacedAtBlock:     big.NewInt(0),
			}
		}

		didResolutionProof, err := prover.Prove(*userDID, identityState, stateType)
		if err != nil {
			return nil, err
		}

		didResolution.DidResolutionMetadata.Context = document.DidResolutionMetadataSigContext()
		didResolution.DidResolutionMetadata.Proof = append(didResolution.DidResolutionMetadata.Proof, didResolutionProof)
	}
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

// ResolveCredentialStatus return revocation status.
func (d *DidDocumentServices) ResolveCredentialStatus(ctx context.Context, issuerDid string, credentialStatus verifiable.CredentialStatus) (verifiable.RevocationStatus, error) {
	did, err := w3c.ParseDID(issuerDid)
	if err != nil {
		return verifiable.RevocationStatus{}, err
	}
	ctx = verifiable.WithIssuerDID(ctx, did)
	return d.revStatusOnChainResolver.Resolve(ctx, credentialStatus)
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
