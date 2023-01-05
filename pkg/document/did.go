package document

import (
	"time"
)

const (
	defaultContext       = "https://w3id.org/did-resolution/v1"
	defaultDidDocContext = "https://www.w3.org/ns/did/v1"
	defaultContentType   = "application/did+ld+json"
)

// DidResolution representation of did resolution.
type DidResolution struct {
	Context     string      `json:"@context"`
	DidDocument DidDocument `json:"didDocument"`
	// should exist in responses, but can be empty.
	// https://www.w3.org/TR/did-core/#did-resolution
	DidResolutionMetadata DidResolutionMetadata `json:"didResolutionMetadata"`
	DidDocumentMetadata   DidDocumentMetadata   `json:"didDocumentMetadata"`
}

// NewDidResolution create did resolution with default values.
func NewDidResolution() *DidResolution {
	return &DidResolution{
		Context: defaultContext,
		DidDocument: DidDocument{
			Context: []string{defaultDidDocContext},
		},
		DidResolutionMetadata: DidResolutionMetadata{
			ContentType: defaultContentType,
			Retrieved:   time.Now(),
		},
	}
}

// DidDocument representation of did document.
type DidDocument struct {
	Context []string `json:"@context"`
	ID      string   `json:"id"`
}

// DidResolutionMetadata representation of resolution metadata.
type DidResolutionMetadata struct {
	ContentType string    `json:"contentType"`
	Retrieved   time.Time `json:"retrieved"`
}

// DidDocumentMetadata metadata of did document.
type DidDocumentMetadata struct {
	IdentityState IdentityState `json:"identityState"`
}

// IdentityState representation all info about identity.
type IdentityState struct {
	BlockchainAccountID string     `json:"blockchainAccountId"`
	Published           bool       `json:"published"`
	Latest              *StateInfo `json:"latest,omitempty"`
	Global              *GistInfo  `json:"global"`
}

// StateInfo representation state of identity.
type StateInfo struct {
	ID                  string `json:"id"`
	State               string `json:"state"`
	ReplacedByState     string `json:"replacedByState"`
	CreatedAtTimestamp  string `json:"createdAtTimestamp"`
	ReplacedAtTimestamp string `json:"replacedAtTimestamp"`
	CreatedAtBlock      string `json:"createdAtBlock"`
	ReplacedAtBlock     string `json:"replacedAtBlock"`
}

// GistInfo representation state of gist root.
type GistInfo struct {
	Root                string `json:"root"`
	ReplacedByRoot      string `json:"replacedByRoot"`
	CreatedAtTimestamp  string `json:"createdAtTimestamp"`
	ReplacedAtTimestamp string `json:"replacedAtTimestamp"`
	CreatedAtBlock      string `json:"createdAtBlock"`
	ReplacedAtBlock     string `json:"replacedAtBlock"`
}
