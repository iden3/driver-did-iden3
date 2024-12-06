package pkh

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/iden3/driver-did-iden3/pkg/document"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-schema-processor/v2/verifiable"
)

const (
	NamespaceTezos  = "tezos"
	NamespaceEIP155 = "eip155"
	NamespaceBIP122 = "bip122"
)

type Resolver struct {
}

type ResolverOption func(*Resolver)

// NewResolver create new pkh resolver.
func NewResolver() (*Resolver, error) {
	return &Resolver{}, nil
}

func (r *Resolver) Resolve(
	ctx context.Context,
	did w3c.DID,
) (*document.DidResolution, error) {
	didString := did.String()
	parts := strings.Split(didString, ":")
	namespace := parts[2]
	vmId := didString + "#blockchainAccountId"

	didResolution := document.NewDidResolution()
	authentication := verifiable.Authentication{}
	authentication.ID = vmId
	authentication.Type = document.EcdsaSecp256k1RecoveryMethod2020Type
	authentication.Controller = didString
	blockchainAccountID, err := getBlockchainAccountID(didString)
	if err != nil {
		return nil, err
	}
	didResolution.DidDocument = &verifiable.DIDDocument{
		Context: []interface{}{
			document.DefaultDidDocContext,
			map[string]string{
				"blockchainAccountId":                         document.BlockchainAccountIdContext,
				document.EcdsaSecp256k1RecoveryMethod2020Type: document.EcdsaSecp256k1RecoveryMethod2020Context,
			},
		},
		ID:                 didString,
		VerificationMethod: []verifiable.CommonVerificationMethod{},
		Authentication:     []verifiable.Authentication{authentication},
		AssertionMethod:    []interface{}{vmId},
	}

	didResolution.DidDocument.VerificationMethod = append(
		didResolution.DidDocument.VerificationMethod,
		verifiable.CommonVerificationMethod{
			ID:                  vmId,
			Type:                document.EcdsaSecp256k1RecoveryMethod2020Type,
			Controller:          didString,
			BlockchainAccountID: blockchainAccountID,
		},
	)

	switch namespace {
	case NamespaceEIP155:
	case NamespaceBIP122:
		break
	case NamespaceTezos:
		didResolution.DidDocument.Context = []interface{}{
			document.DefaultDidDocContext,
			map[string]string{
				"blockchainAccountId":                         document.BlockchainAccountIdContext,
				document.EcdsaSecp256k1RecoveryMethod2020Type: document.EcdsaSecp256k1RecoveryMethod2020Context,
				document.TezosMethod2021Type:                  document.TezosMethod2021Context,
			},
		}

		tzId := fmt.Sprintf("%s#%s", didString, document.TezosMethod2021Type)
		didResolution.DidDocument.VerificationMethod = append(
			didResolution.DidDocument.VerificationMethod,
			verifiable.CommonVerificationMethod{
				ID:                  tzId,
				Type:                document.TezosMethod2021Type,
				Controller:          didString,
				BlockchainAccountID: blockchainAccountID,
			},
		)
		tzAuthentication := verifiable.Authentication{}
		tzAuthentication.ID = tzId
		tzAuthentication.Type = document.TezosMethod2021Type
		tzAuthentication.Controller = didString
		didResolution.DidDocument.Authentication = append(didResolution.DidDocument.Authentication, tzAuthentication)
		didResolution.DidDocument.AssertionMethod = append(didResolution.DidDocument.AssertionMethod, tzId)
	default:
		return nil, fmt.Errorf("chain namespace not supported: %s", namespace)
	}
	return didResolution, nil
}

func getBlockchainAccountID(did string) (string, error) {
	prefix := "did:pkh:"
	if !strings.HasPrefix(did, prefix) {
		return "", errors.New("invalid DID format: must start with 'did:pkh:'")
	}
	blockchainAccountId := strings.TrimPrefix(did, prefix)
	if blockchainAccountId == "" {
		return "", errors.New("invalid DID format: missing blockchainAccountId")
	}
	return blockchainAccountId, nil
}
