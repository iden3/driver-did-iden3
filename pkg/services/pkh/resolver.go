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
	NamespaceSolana = "solana"
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
	if len(parts) < 4 {
		return nil, errors.New("invalid did:pkh format")
	}
	namespace := parts[2]
	vmID := didString + "#blockchainAccountId"

	blockchainAccountID, err := getBlockchainAccountID(didString)
	if err != nil {
		return nil, err
	}

	didResolution := document.NewDidResolution()

	didResolution.DidDocument = &verifiable.DIDDocument{
		Context: []interface{}{
			document.DefaultDidDocContext,
			map[string]string{
				"blockchainAccountId": document.BlockchainAccountIDContext,
			},
		},
		ID:                 didString,
		VerificationMethod: []verifiable.CommonVerificationMethod{},
		Authentication:     []verifiable.Authentication{},
		AssertionMethod:    []verifiable.Authentication{},
	}

	switch namespace {
	case NamespaceEIP155:
		didResolution.DidDocument.Context = []interface{}{
			document.DefaultDidDocContext,
			map[string]string{
				"blockchainAccountId":                         document.BlockchainAccountIDContext,
				document.EcdsaSecp256k1RecoveryMethod2020Type: document.EcdsaSecp256k1RecoveryMethod2020Context,
			},
		}
		didResolution.DidDocument.VerificationMethod = append(
			didResolution.DidDocument.VerificationMethod,
			verifiable.CommonVerificationMethod{
				ID:                  vmID,
				Type:                document.EcdsaSecp256k1RecoveryMethod2020Type,
				Controller:          didString,
				BlockchainAccountID: blockchainAccountID,
			},
		)

		auth := verifiable.Authentication{
			CommonVerificationMethod: verifiable.CommonVerificationMethod{
				ID:         vmID,
				Type:       document.EcdsaSecp256k1RecoveryMethod2020Type,
				Controller: didString,
			},
		}
		didResolution.DidDocument.Authentication = append(didResolution.DidDocument.Authentication, auth)

		var asrt verifiable.Authentication
		if err := asrt.UnmarshalJSON([]byte(fmt.Sprintf("%q", vmID))); err != nil {
			return nil, err
		}
		didResolution.DidDocument.AssertionMethod = append(didResolution.DidDocument.AssertionMethod, asrt)

	case NamespaceBIP122:
		break
	case NamespaceSolana:
		publicKeyMultibase := parts[4]
		didResolution.DidDocument.Context = []interface{}{
			document.DefaultDidDocContext,
			document.Ed25519VerificationKey2020Context,
			map[string]string{
				"blockchainAccountId":         document.BlockchainAccountIDContext,
				document.SolanaMethod2021Type: document.SolanaMethod2021Context,
			},
		}
		didResolution.DidDocument.VerificationMethod = append(
			didResolution.DidDocument.VerificationMethod,
			verifiable.CommonVerificationMethod{
				ID:                 vmID,
				Type:               document.Ed25519VerificationKey2020Type,
				Controller:         didString,
				PublicKeyMultibase: publicKeyMultibase,
			},
		)
		solID := fmt.Sprintf("%s#%s", didString, document.SolanaMethod2021Type)
		didResolution.DidDocument.VerificationMethod = append(
			didResolution.DidDocument.VerificationMethod,
			verifiable.CommonVerificationMethod{
				ID:                  solID,
				Type:                document.SolanaMethod2021Type,
				Controller:          didString,
				BlockchainAccountID: blockchainAccountID,
			},
		)
		didResolution.DidDocument.Authentication = append(
			didResolution.DidDocument.Authentication,
			verifiable.Authentication{
				CommonVerificationMethod: verifiable.CommonVerificationMethod{
					ID:         vmID,
					Type:       document.Ed25519VerificationKey2020Type,
					Controller: didString,
				},
			},
			verifiable.Authentication{
				CommonVerificationMethod: verifiable.CommonVerificationMethod{
					ID:         solID,
					Type:       document.SolanaMethod2021Type,
					Controller: didString,
				},
			},
		)
		var asrt1, asrt2 verifiable.Authentication
		if err := asrt1.UnmarshalJSON([]byte(fmt.Sprintf("%q", vmID))); err != nil {
			return nil, err
		}
		if err := asrt2.UnmarshalJSON([]byte(fmt.Sprintf("%q", solID))); err != nil {
			return nil, err
		}
		didResolution.DidDocument.AssertionMethod = append(
			didResolution.DidDocument.AssertionMethod, asrt1, asrt2,
		)
	case NamespaceTezos:
		didResolution.DidDocument.Context = []interface{}{
			document.DefaultDidDocContext,
			map[string]string{
				"blockchainAccountId":                         document.BlockchainAccountIDContext,
				document.EcdsaSecp256k1RecoveryMethod2020Type: document.EcdsaSecp256k1RecoveryMethod2020Context,
				document.TezosMethod2021Type:                  document.TezosMethod2021Context,
			},
		}

		tzID := fmt.Sprintf("%s#%s", didString, document.TezosMethod2021Type)
		didResolution.DidDocument.VerificationMethod = append(
			didResolution.DidDocument.VerificationMethod,
			verifiable.CommonVerificationMethod{
				ID:                  tzID,
				Type:                document.TezosMethod2021Type,
				Controller:          didString,
				BlockchainAccountID: blockchainAccountID,
			},
		)
		tzAuthentication := verifiable.Authentication{}
		tzAuthentication.ID = tzID
		tzAuthentication.Type = document.TezosMethod2021Type
		tzAuthentication.Controller = didString

		tzAssertionMethod := verifiable.Authentication{}
		err = tzAssertionMethod.UnmarshalJSON([]byte(fmt.Sprintf("%q", tzID)))
		if err != nil {
			return nil, err
		}
		didResolution.DidDocument.Authentication = append(didResolution.DidDocument.Authentication, tzAuthentication)
		didResolution.DidDocument.AssertionMethod = append(didResolution.DidDocument.AssertionMethod, tzAssertionMethod)
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
	blockchainAccountID := strings.TrimPrefix(did, prefix)
	if blockchainAccountID == "" {
		return "", errors.New("invalid DID format: missing blockchainAccountId")
	}
	return blockchainAccountID, nil
}
