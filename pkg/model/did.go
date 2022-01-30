package model

import (
	"errors"
	"strings"
)

const didSeparator = ":"

var (
	ErrInvalidDIDFormat = errors.New("invalid format for did")
)

// https://www.w3.org/TR/did-core/#a-simple-example
type Did struct {
	schema     string
	methods    []string
	identifier string
	params     []string
}

// NewDidFromString create a new Did from string.
func NewDidFromString(s string) (Did, error) {
	// TODO (illia-korotia): refactor to Scanf.
	// TODO (illia-korotia): add more validation checks. Write unit test.
	did := Did{}
	raw := strings.Split(strings.TrimSpace(s), didSeparator)

	// check to min len.
	if len(raw) < 3 {
		return did, ErrInvalidDIDFormat
	}

	if raw[0] != "did" {
		return did, ErrInvalidDIDFormat
	}

	did.schema = raw[0]
	did.methods = raw[1 : len(raw)-1]
	did.identifier = raw[len(raw)-1]
	// did.params = split did.identifier by #

	return did, nil
}

// Identifier get identifier part from did.
func (did Did) Identifier() string {
	return did.identifier
}

func (did Did) String() string {
	return strings.Join([]string{did.schema, strings.Join(did.methods, didSeparator), did.identifier}, didSeparator)
}
