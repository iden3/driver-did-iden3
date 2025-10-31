package additionalsourceresolver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/iden3/driver-did-iden3/pkg/document"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-schema-processor/v2/verifiable"
)

var ErrDIDMismatch = errors.New("cannot merge DID documents with different IDs")

type AdditionalSourceResolver struct {
	client *http.Client
	URL    string
}

// NewAdditionalSourceResolver create new AdditionalSourceResolver instance.
func NewAdditionalSourceResolver(url string, client *http.Client) (*AdditionalSourceResolver, error) {
	if url == "" {
		return nil, errors.New("url is empty")
	}
	if client == nil {
		return nil, errors.New("http client is nil")
	}
	return &AdditionalSourceResolver{
		URL:    url,
		client: client,
	}, nil
}

func (r AdditionalSourceResolver) ResolveAndMerge(ctx context.Context, did w3c.DID, originalResolution *document.DidResolution) (*document.DidResolution, error) {
	fullURL := joinBaseURL(r.URL, did.String())

	additionalResolution, err := r.fetchDidResolution(ctx, fullURL)
	if err != nil {
		return originalResolution, nil
	}
	if originalResolution == nil {
		return additionalResolution, nil
	}

	if additionalResolution == nil {
		return originalResolution, nil
	}

	err = mergeDIDDocument(originalResolution.DidDocument, additionalResolution.DidDocument)
	return originalResolution, err
}

func (r AdditionalSourceResolver) fetchDidResolution(ctx context.Context, fullURL string) (*document.DidResolution, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	res, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			log.Println("failed to close response body:", err)
		}
	}()
	if res.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if res.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch did resolution")
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	bodyString := strings.TrimSpace(string(body))
	if bodyString == "" {
		return nil, errors.New("empty response body")
	}

	var out document.DidResolution
	if err := json.Unmarshal([]byte(bodyString), &out); err != nil {
		return nil, fmt.Errorf("decode did resolution: %w", err)
	}
	return &out, nil
}

func mergeDIDDocument(p, a *verifiable.DIDDocument) error {
	p.Context = mergeContexts(p.Context, a.Context)
	if p.ID != a.ID {
		return ErrDIDMismatch
	}

	p.VerificationMethod = appendByDistinctID(p.VerificationMethod, a.VerificationMethod, func(vm verifiable.CommonVerificationMethod) string { return vm.ID })
	p.AssertionMethod = appendByDistinctJSON(p.AssertionMethod, a.AssertionMethod)
	p.Authentication = appendByDistinctJSON(p.Authentication, a.Authentication)
	p.KeyAgreement = appendByDistinctJSON(p.KeyAgreement, a.KeyAgreement)
	p.Service = appendByDistinctJSON(p.Service, a.Service)
	return nil
}

func mergeContexts(primary, additional interface{}) interface{} {
	if isZero(additional) {
		return primary
	}
	if isZero(primary) {
		return additional
	}

	toSlice := func(v interface{}) []string {
		switch ctx := v.(type) {
		case string:
			return []string{ctx}
		case []string:
			return ctx
		case []interface{}:
			out := make([]string, 0, len(ctx))
			for _, c := range ctx {
				if s, ok := c.(string); ok {
					out = append(out, s)
				}
			}
			return out
		default:
			b, _ := json.Marshal(v)
			var arr []string
			if err := json.Unmarshal(b, &arr); err == nil {
				return arr
			}
			return nil
		}
	}

	pSlice := toSlice(primary)
	aSlice := toSlice(additional)
	if len(aSlice) == 0 {
		return pSlice
	}

	seen := make(map[string]struct{}, len(pSlice))
	for _, c := range pSlice {
		seen[c] = struct{}{}
	}
	for _, c := range aSlice {
		if _, ok := seen[c]; !ok {
			pSlice = append(pSlice, c)
			seen[c] = struct{}{}
		}
	}
	if len(pSlice) == 1 {
		return pSlice[0]
	}
	return pSlice
}

func appendByDistinctID[T any](dst, src []T, idOf func(T) string) []T {
	if len(src) == 0 {
		return dst
	}
	seen := make(map[string]struct{}, len(dst))
	for _, v := range dst {
		if id := idOf(v); id != "" {
			seen[id] = struct{}{}
		}
	}
	for _, v := range src {
		if id := idOf(v); id != "" {
			if _, ok := seen[id]; ok {
				continue
			}
			dst = append(dst, v)
			seen[id] = struct{}{}
		}
	}
	return dst
}

func appendByDistinctJSON[T any](dst, src []T) []T {
	if len(src) == 0 {
		return dst
	}
	seen := make(map[string]struct{}, len(dst)+len(src))
	for _, v := range dst {
		seen[mustJSONKey(v)] = struct{}{}
	}
	for _, v := range src {
		k := mustJSONKey(v)
		if _, ok := seen[k]; ok {
			continue
		}
		dst = append(dst, v)
		seen[k] = struct{}{}
	}
	return dst
}

func mustJSONKey(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func isZero(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	default:
		b, _ := json.Marshal(v)
		s := strings.TrimSpace(string(b))
		return s == "null" || s == "{}" || s == "[]"
	}
}

func joinBaseURL(base, did string) string {
	base = strings.TrimRight(base, "/")
	return fmt.Sprintf("%s/%s", base, did)
}
