package provers

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/iden3/driver-did-iden3/pkg/document"
	"github.com/iden3/driver-did-iden3/pkg/services"
	"github.com/iden3/driver-did-iden3/pkg/services/signers"
	"github.com/iden3/driver-did-iden3/pkg/services/utils"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/pkg/errors"
)

type EIP712Prover struct {
	signer  *signers.Secp256k1Signer
	address common.Address
}

func NewEIP712Prover(walletKey string) (*EIP712Prover, error) {

	s, err := signers.NewSecp256k1Signer(walletKey) // eip712 provers uses ecdsa signer
	if err != nil {
		return nil, err
	}
	addr, err := utils.PrivateKeyToAddress(walletKey)
	if err != nil {
		return nil, err
	}
	globalStateSigner := &EIP712Prover{
		signer:  s,
		address: addr,
	}

	return globalStateSigner, nil
}

func (p *EIP712Prover) Prove(did w3c.DID, state services.IdentityState, stateType services.StateType) (document.DidResolutionProof, error) {

	typedData, err := p.getTypedData(did, state, stateType)
	if err != nil {
		return nil, err
	}
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return nil, errors.New("error hashing EIP712Domain for signing")
	}
	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return nil, errors.New("error hashing PrimaryType message for signing")
	}
	rawData := []byte(fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash)))
	dataHash := crypto.Keccak256(rawData)

	signature, err := p.signer.Sign(dataHash)
	if err != nil {
		return nil, err
	}

	messageSignature := "0x" + hex.EncodeToString(signature)

	eip712Proof := &document.EthereumEip712SignatureProof2021{
		Type:               document.EthereumEip712SignatureProof2021Type,
		ProofPurpose:       "assertionMethod",
		ProofValue:         messageSignature,
		VerificationMethod: fmt.Sprintf("did:pkh:eip155:0:%s#blockchainAccountId", p.address),
		Eip712:             typedData,
		Created:            time.Now(),
	}

	return eip712Proof, nil
}

func (p *EIP712Prover) getTypedData(did w3c.DID, identityState services.IdentityState, stateType services.StateType) (apitypes.TypedData, error) {
	id, err := core.IDFromDID(did)
	if err != nil {
		return apitypes.TypedData{},
			fmt.Errorf("invalid did format for did '%s': %v", did, err)
	}

	timestamp := utils.TimeStamp()

	var apiTypes apitypes.Types
	var message apitypes.TypedDataMessage
	var primaryType string

	switch stateType {
	case services.IdentityStateType:
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

	case services.GlobalStateType:
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
	default:
		return apitypes.TypedData{}, fmt.Errorf("type of state info %d is not supported", stateType)
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
