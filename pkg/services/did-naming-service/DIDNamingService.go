package additionalsourceresolver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"

	"github.com/iden3/driver-did-iden3/pkg/document"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
)

var ErrDIDMismatch = errors.New("cannot merge DID documents with different IDs")

type DIDNamingService struct {
	client *http.Client
	URL    string
}

// NewDIDNamingService create new DIDNamingService instance.
func NewDIDNamingService(url string, client *http.Client) (*DIDNamingService, error) {
	if url == "" {
		return nil, errors.New("url is empty")
	}
	if client == nil {
		return nil, errors.New("http client is nil")
	}
	return &DIDNamingService{
		URL:    url,
		client: client,
	}, nil
}

// ResolveDIDByAlias resolves a DID by its alias using the DID Naming Service.
// The did parameter must be a zero address Ethereum Identity that matches the
// method and network of the resolved DID. Returns the resolved DID string or
// an error if the naming service is not configured, the did is invalid, or
// resolution fails.
func (d *DIDNamingService) ResolveDIDByAlias(ctx context.Context, alias, did string) (string, error) {
	if d.URL == "" {
		return did, errors.New("missing configuration for DidNamingService URL")
	}

	// Check did param is zero genesis did
	userDID, err := w3c.ParseDID(did)
	if err != nil {
		return did, fmt.Errorf("failed parse did from '%s': %w", did, err)
	}
	userID, err := core.IDFromDID(*userDID)
	if err != nil {
		return did, fmt.Errorf("failed get id from did '%s': %w", did, err)
	}
	genesisZeroDID, err := core.NewDIDFromIdenState(userID.Type(), big.NewInt(0))
	if err != nil {
		return did, fmt.Errorf("failed to create zero genesis did: %w", err)
	}
	if genesisZeroDID.String() != userDID.String() {
		return did, fmt.Errorf("did param should be zero genesis did, got '%s'", did)
	}

	didNamingServiceResolution, err := d.fetchDidNamingServiceResolution(ctx, alias)
	if err != nil {
		return did, fmt.Errorf("error fetching did naming service resolution for '%s': %w", alias, err)
	}
	return didNamingServiceResolution.Did, nil
}

func (d *DIDNamingService) GetURL() string {
	return d.URL
}

func (d *DIDNamingService) fetchDidNamingServiceResolution(ctx context.Context, alias string) (*document.DidNamingServiceResolution, error) {
	fullURL := fmt.Sprintf("%s/%s", d.URL, alias)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	res, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			log.Println("failed to close response body:", err)
		}
	}()

	if res.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch did naming service resolution")
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	bodyString := strings.TrimSpace(string(body))
	if bodyString == "" {
		return nil, errors.New("empty response body")
	}

	var out document.DidNamingServiceResolution
	if err := json.Unmarshal([]byte(bodyString), &out); err != nil {
		return nil, fmt.Errorf("decode did naming service resolution: %w", err)
	}
	return &out, nil
}
